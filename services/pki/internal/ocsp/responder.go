// Package ocsp implements an RFC 6960 OCSP responder for the Device CA on the
// mTLS listener (POST /ocsp and GET /ocsp/{base64-request}).
//
// Responses are signed by a delegated responder certificate (EKU OCSPSigning,
// id-pkix-ocsp-nocheck) that the responder mints from the Device CA at start
// and rotates when half of its lifetime has elapsed. Request nonces are echoed
// in responseExtensions; nonce-less answers are cached for 60 s and the cache
// is invalidated on revocation.
package ocsp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Wire constants.
const (
	ContentTypeRequest  = "application/ocsp-request"
	ContentTypeResponse = "application/ocsp-response"
	DefaultCacheTTL     = 60 * time.Second
	DefaultValidity     = 10 * time.Minute
	maxRequestSize      = 8 << 10
)

// Options tunes the responder.
type Options struct {
	Clock     func() time.Time
	CacheTTL  time.Duration
	Validity  time.Duration // nextUpdate - thisUpdate
	SignerTTL time.Duration // delegated signer lifetime
	Metrics   *metrics.Metrics
}

// Responder answers OCSP requests for certificates issued by the Device CA.
type Responder struct {
	deviceCA *ca.CA
	store    store.Store
	opts     Options

	mu         sync.Mutex
	signerCert *x509.Certificate
	signerKey  crypto.Signer
	cache      *cache
}

// NewResponder creates a responder and mints the initial delegated signer.
func NewResponder(deviceCA *ca.CA, st store.Store, opts Options) (*Responder, error) {
	if deviceCA == nil || deviceCA.Kind() != ca.KindDevice {
		return nil, errors.New("ocsp: a Device CA is required")
	}
	if st == nil {
		return nil, errors.New("ocsp: a store is required")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.Validity <= 0 {
		opts.Validity = DefaultValidity
	}
	if opts.SignerTTL <= 0 {
		opts.SignerTTL = ca.DefaultOCSPSignerTTL
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	r := &Responder{deviceCA: deviceCA, store: st, opts: opts, cache: newCache(opts.CacheTTL)}
	if err := r.rotateSigner(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Responder) now() time.Time { return r.opts.Clock().UTC() }

// rotateSigner mints a fresh delegated responder key and certificate.
func (r *Responder) rotateSigner() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ocsp: generate signer key: %w", err)
	}
	cert, err := r.deviceCA.IssueOCSPSigner(key.Public(), r.opts.SignerTTL)
	if err != nil {
		return err
	}
	r.signerCert, r.signerKey = cert, key
	return nil
}

// signer returns the current delegated signer, rotating it when more than
// half of its lifetime has elapsed.
func (r *Responder) signer() (*x509.Certificate, crypto.Signer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	half := r.signerCert.NotBefore.Add(r.signerCert.NotAfter.Sub(r.signerCert.NotBefore) / 2)
	if now.After(half) {
		if err := r.rotateSigner(); err != nil {
			return nil, nil, err
		}
	}
	return r.signerCert, r.signerKey, nil
}

// SignerCertificate returns the current delegated responder certificate.
func (r *Responder) SignerCertificate() *x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.signerCert
}

// Register mounts the endpoints on mux.
func (r *Responder) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /ocsp", r.handlePOST)
	mux.HandleFunc("GET /ocsp/{request...}", r.handleGET)
}

// Invalidate drops cached answers for a serial (called on revocation).
func (r *Responder) Invalidate(serial string) {
	n, _, err := ca.ParseSerial(serial)
	if err != nil {
		return
	}
	r.cache.invalidate(n.String())
}

func (r *Responder) handlePOST(w http.ResponseWriter, req *http.Request) {
	if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), ContentTypeRequest) {
		http.Error(w, "Content-Type must be "+ContentTypeRequest, http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxRequestSize))
	if err != nil {
		http.Error(w, "cannot read request", http.StatusBadRequest)
		return
	}
	r.serve(w, req, body)
}

func (r *Responder) handleGET(w http.ResponseWriter, req *http.Request) {
	enc := req.PathValue("request")
	if enc == "" {
		http.Error(w, "missing request", http.StatusBadRequest)
		return
	}
	der, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(enc, "="))
	}
	if err != nil {
		r.write(w, malformedRequestResponse, "malformed")
		return
	}
	r.serve(w, req, der)
}

func (r *Responder) serve(w http.ResponseWriter, req *http.Request, der []byte) {
	resp, status, cacheable := r.respond(req.Context(), der)
	if cacheable && (status == "good" || status == "revoked" || status == "unknown") {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", int(r.opts.CacheTTL.Seconds())))
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	r.write(w, resp, status)
}

func (r *Responder) write(w http.ResponseWriter, resp []byte, status string) {
	r.opts.Metrics.OCSPRequests.WithLabelValues(status).Inc()
	w.Header().Set("Content-Type", ContentTypeResponse)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// Respond produces the DER OCSPResponse for a DER request. The second return
// value is the outcome label used for metrics: good, revoked, unknown,
// malformed, unauthorized or error.
func (r *Responder) Respond(ctx context.Context, der []byte) ([]byte, string) {
	resp, status, _ := r.respond(ctx, der)
	return resp, status
}

// respond additionally reports whether the answer may be cached by clients
// (false for nonce-bearing requests and error responses).
func (r *Responder) respond(ctx context.Context, der []byte) ([]byte, string, bool) {
	l := logging.FromContext(ctx)
	pr, err := ParseRequest(der)
	if err != nil {
		l.Warn("ocsp request rejected", "reason", err.Error())
		return malformedRequestResponse, "malformed", false
	}
	if !r.issuerMatches(pr) {
		l.Warn("ocsp request for unknown issuer", "serial", pr.SerialNumber.Text(16))
		return unauthorizedResponse, "unauthorized", false
	}
	cacheable := len(pr.Nonce) == 0
	cacheKey := pr.HashOID.String() + "|" + pr.SerialNumber.String()
	if cacheable {
		if resp, ok := r.cache.get(cacheKey, pr.SerialNumber.String(), r.now()); ok {
			return resp.der, resp.status, true
		}
	}
	serial := ca.FormatSerial(pr.SerialNumber)
	now := r.now()
	single := singleResponse{
		CertID: certID{
			HashAlgorithm: pkixAlg(pr.HashOID),
			NameHash:      pr.IssuerNameHash,
			IssuerKeyHash: pr.IssuerKeyHash,
			SerialNumber:  pr.SerialNumber,
		},
		ThisUpdate: now.Truncate(time.Second),
		NextUpdate: now.Add(r.opts.Validity).Truncate(time.Second),
	}
	var status string
	rev, err := r.store.GetRevocation(ctx, serial)
	switch {
	case err == nil:
		single.Revoked = revokedInfo{RevocationTime: rev.RevokedAt.UTC().Truncate(time.Second), Reason: asn1.Enumerated(rev.Reason)}
		status = "revoked"
	case errors.Is(err, store.ErrNotFound):
		if _, err := r.store.GetCertificate(ctx, serial); err == nil {
			single.Good = true
			status = "good"
		} else if errors.Is(err, store.ErrNotFound) {
			single.Unknown = true
			status = "unknown"
		} else {
			l.Error("ocsp certificate lookup failed", "serial", serial, "error", err.Error())
			return internalErrorResponse, "error", false
		}
	default:
		l.Error("ocsp revocation lookup failed", "serial", serial, "error", err.Error())
		return internalErrorResponse, "error", false
	}
	signerCert, signerKey, err := r.signer()
	if err != nil {
		l.Error("ocsp signer rotation failed", "error", err.Error())
		return internalErrorResponse, "error", false
	}
	resp, err := signedResponse(single, pr.Nonce, now, signerCert, signerKey)
	if err != nil {
		l.Error("ocsp response signing failed", "error", err.Error())
		return internalErrorResponse, "error", false
	}
	if cacheable {
		r.cache.put(cacheKey, pr.SerialNumber.String(), cachedResponse{der: resp, status: status}, now)
	}
	return resp, status, cacheable
}

func pkixAlg(oid asn1.ObjectIdentifier) pkixAlgorithmIdentifier {
	return pkixAlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}
}

// issuerMatches checks the request's issuer hashes against the Device CA.
func (r *Responder) issuerMatches(pr *ParsedRequest) bool {
	issuer := r.deviceCA.Certificate()
	pk, err := publicKeyBytes(issuer)
	if err != nil {
		return false
	}
	nh := newHash(pr.Hash)
	nh.Write(issuer.RawSubject)
	kh := newHash(pr.Hash)
	kh.Write(pk)
	return string(nh.Sum(nil)) == string(pr.IssuerNameHash) && string(kh.Sum(nil)) == string(pr.IssuerKeyHash)
}

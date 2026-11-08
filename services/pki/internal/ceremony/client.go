package ceremony

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	xocsp "golang.org/x/crypto/ocsp"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ocsp"
)

// ClientOptions configures the HTTP client used by the online pkictl commands.
type ClientOptions struct {
	// CAFile is a PEM bundle used to verify the PKI server (chain.pem).
	CAFile string
	// CertFile/KeyFile hold a Services CA client certificate for mTLS.
	CertFile string
	KeyFile  string
	// Token is a bearer JWT used instead of a client certificate.
	Token   string
	Timeout time.Duration
	// Insecure skips server verification (development only).
	Insecure bool
}

// NewHTTPClient builds the TLS client.
func NewHTTPClient(opts ClientOptions) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.Insecure} //nolint:gosec // explicit dev-only flag
	if opts.CAFile != "" {
		certs, err := ca.LoadCertsPEM(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("load CA file: %w", err)
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		tlsCfg.RootCAs = pool
	}
	if opts.CertFile != "" || opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

// Revoke calls POST /v1/certificates/{serial}/revoke on the management API.
func Revoke(ctx context.Context, client *http.Client, baseURL, token, serial, reason string) (map[string]any, error) {
	_, canonical, err := ca.ParseSerial(serial)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"reason": reason})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/certificates/"+canonical+"/revoke", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("revoke failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return out, nil
}

// FetchCRL downloads and parses a CRL.
func FetchCRL(ctx context.Context, client *http.Client, crlURL string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch CRL: HTTP %d", resp.StatusCode)
	}
	return x509.ParseRevocationList(data)
}

// OCSPResult is the outcome of an OCSP check.
type OCSPResult struct {
	Status       string
	RevokedAt    time.Time
	Reason       string
	ProducedAt   time.Time
	NextUpdate   time.Time
	Responder    string
	NonceEchoed  bool
	SignerIsOCSP bool
}

// OCSPCheck queries the responder for cert (issued by issuer) with a fresh
// nonce via POST, verifies the signature and delegated signer and checks the
// nonce echo.
func OCSPCheck(ctx context.Context, client *http.Client, ocspURL string, cert, issuer *x509.Certificate) (*OCSPResult, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	reqDER, err := ocsp.CreateRequest(cert, issuer, crypto.SHA256, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ocsp.ContentTypeRequest)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ocsp: HTTP %d", resp.StatusCode)
	}
	parsed, err := xocsp.ParseResponseForCert(data, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("ocsp: invalid response: %w", err)
	}
	res := &OCSPResult{ProducedAt: parsed.ProducedAt, NextUpdate: parsed.NextUpdate}
	switch parsed.Status {
	case xocsp.Good:
		res.Status = "good"
	case xocsp.Revoked:
		res.Status = "revoked"
		res.RevokedAt = parsed.RevokedAt
		res.Reason = ca.ReasonString(parsed.RevocationReason)
	default:
		res.Status = "unknown"
	}
	if parsed.Certificate != nil {
		res.Responder = parsed.Certificate.Subject.CommonName
		for _, eku := range parsed.Certificate.ExtKeyUsage {
			if eku == x509.ExtKeyUsageOCSPSigning {
				res.SignerIsOCSP = true
			}
		}
		if !res.SignerIsOCSP {
			return nil, errors.New("ocsp: responder certificate lacks EKU OCSPSigning")
		}
	}
	echoed, err := ocsp.ParseResponseNonce(data)
	if err != nil {
		return nil, err
	}
	res.NonceEchoed = bytes.Equal(echoed, nonce)
	if !res.NonceEchoed {
		return res, errors.New("ocsp: nonce was not echoed")
	}
	return res, nil
}

// JoinURL joins a base URL and a path.
func JoinURL(base, p string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(p, "/")
	return u.String(), nil
}

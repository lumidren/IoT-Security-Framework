package testutil

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/crl"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ocsp"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/server"
)

// ServerOptions tunes StartServer.
type ServerOptions struct {
	// AllowedCNs for the management API (default svc-console).
	AllowedCNs []string
	// JWTKeys trusted for management bearer tokens.
	JWTKeys []crypto.PublicKey
	// Publisher overrides the fake policy server publisher.
	Publisher revocation.Publisher
	// PolicyFailures makes the fake policy server fail that many requests
	// with HTTP 500 before succeeding.
	PolicyFailures int
	// NonceTTL overrides the attestation nonce TTL.
	NonceTTL time.Duration
	// DefaultAllowSoftwareKeys applies to tenants without a policy.
	DefaultAllowSoftwareKeys bool
	// DefaultPCRDigests are merged into every tenant policy.
	DefaultPCRDigests []string
	// OCSPCacheTTL overrides the OCSP cache TTL.
	OCSPCacheTTL time.Duration
	// RateLimit overrides the EST rate limits (default: effectively unlimited
	// so parallel tests from one IP never collide).
	RateLimit *est.RateLimitConfig
	// SupersedeGrace overrides the revocation delay of superseded certificates.
	SupersedeGrace time.Duration
	// RegistryRetries / RegistryBackoff tune the enrolled callback retries
	// (default backoff 1 ms so failure tests stay fast).
	RegistryRetries int
	RegistryBackoff time.Duration
}

// Server is a running test PKI service.
type Server struct {
	PKI    *PKI
	MTLS   *httptest.Server
	Plain  *httptest.Server
	EST    *est.Handler
	OCSP   *ocsp.Responder
	Mgmt   *mgmt.Handler
	CRL    *crl.Manager
	Revoke *revocation.Service
	Policy *FakePolicy
	// ServerCert is the mTLS listener certificate (issued by the Services CA).
	ServerCert *x509.Certificate
}

// StartServer wires the real components behind httptest servers.
func (p *PKI) StartServer(t testing.TB, opts ServerOptions) *Server {
	t.Helper()
	ctx := t.Context()
	s := &Server{PKI: p}

	var err error
	if s.CRL, err = crl.NewManager(p.Device, p.Store, crl.Options{Metrics: p.Metrics, Logger: p.Logger, Clock: p.Clock}); err != nil {
		t.Fatal(err)
	}
	if err := s.CRL.Regenerate(ctx); err != nil {
		t.Fatal(err)
	}
	if s.OCSP, err = ocsp.NewResponder(p.Device, p.Store, ocsp.Options{Metrics: p.Metrics, Clock: p.Clock, CacheTTL: opts.OCSPCacheTTL}); err != nil {
		t.Fatal(err)
	}
	s.Policy = NewFakePolicy(t, opts.PolicyFailures)
	publisher := opts.Publisher
	if publisher == nil {
		pub, err := revocation.NewHTTPPublisher(s.Policy.URL, s.Policy.Token, s.Policy.HMACKey, s.Policy.Client())
		if err != nil {
			t.Fatal(err)
		}
		pub.Sleep = func(time.Duration) {} // no real backoff in tests
		pub.Logger = p.Logger
		publisher = pub
	}
	if s.Revoke, err = revocation.NewService(p.Store, revocation.Options{CRL: s.CRL, OCSP: s.OCSP, Publisher: publisher, Metrics: p.Metrics, Clock: p.Clock, Logger: p.Logger}); err != nil {
		t.Fatal(err)
	}
	rateLimit := est.RateLimitConfig{DeviceBurst: 100000, DevicePerMinute: 6000000, IPBurst: 100000, IPPerMinute: 6000000}
	if opts.RateLimit != nil {
		rateLimit = *opts.RateLimit
	}
	registryBackoff := opts.RegistryBackoff
	if registryBackoff == 0 {
		registryBackoff = time.Millisecond
	}
	if s.EST, err = est.NewHandler(est.Config{
		DeviceCA: p.Device, FactoryCA: p.Factory.Certificate(), CACerts: p.CAChain(),
		Store: p.Store, Registry: p.Registry, Bundler: p.Bundler, Metrics: p.Metrics, Clock: p.Clock, Logger: p.Logger,
		NonceTTL: opts.NonceTTL, DefaultAllowSoftwareKeys: opts.DefaultAllowSoftwareKeys, DefaultPCRDigests: opts.DefaultPCRDigests,
		Revoker: s.Revoke, SupersedeGrace: opts.SupersedeGrace, RateLimit: rateLimit, Rollback: s.Revoke,
		RegistryRetries: opts.RegistryRetries, RegistryBackoff: registryBackoff,
	}); err != nil {
		t.Fatal(err)
	}
	allowed := opts.AllowedCNs
	if allowed == nil {
		allowed = []string{"svc-console"}
	}
	var jwtKeys []*ecdsaPublicKey
	for _, k := range opts.JWTKeys {
		if ek, ok := k.(*ecdsaPublicKey); ok {
			jwtKeys = append(jwtKeys, ek)
		}
	}
	auth := mgmt.NewAuthenticator(p.Services.Certificate(), allowed, jwtKeys, p.Clock)
	if s.Mgmt, err = mgmt.NewHandler(mgmt.Config{Auth: auth, Revoker: s.Revoke, Store: p.Store, Chain: p.CAChain(), Metrics: p.Metrics, Clock: p.Clock, DefaultAllowSoftwareKeys: opts.DefaultAllowSoftwareKeys}); err != nil {
		t.Fatal(err)
	}

	deps := server.Deps{Logger: p.Logger, Metrics: p.Metrics, Store: p.Store, EST: s.EST, OCSP: s.OCSP, Mgmt: s.Mgmt, CRL: s.CRL}
	serverKey := P256Key(t)
	s.ServerCert, err = p.Services.IssueServer("pki", []string{"localhost", "127.0.0.1", "::1"}, serverKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{s.ServerCert.Raw, p.Services.Certificate().Raw}, PrivateKey: serverKey, Leaf: s.ServerCert}
	s.MTLS = httptest.NewUnstartedServer(server.NewMTLSHandler(deps))
	s.MTLS.TLS = server.TLSConfig(tlsCert, server.ClientCAPool(p.Root.Certificate(), p.Factory.Certificate(), p.Device.Certificate(), p.Services.Certificate()))
	s.MTLS.StartTLS()
	s.Plain = httptest.NewServer(server.NewPlainHandler(deps))
	t.Cleanup(func() {
		s.MTLS.Close()
		s.Plain.Close()
	})
	return s
}

// Client returns an HTTPS client presenting the given client certificate
// (nil for an anonymous client) and trusting the test root.
func (s *Server) Client(cert *x509.Certificate, key crypto.Signer) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: server.ClientCAPool(s.PKI.Root.Certificate())}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// DeviceClient returns a client authenticated as the device.
func (s *Server) DeviceClient(d *Device) *http.Client { return s.Client(d.Cert, d.Key) }

// ESTURL returns the full URL of an EST operation.
func (s *Server) ESTURL(op string) string { return s.MTLS.URL + est.BasePath + "/" + op }

// FakePolicy records revocation events like the Policy service would.
type FakePolicy struct {
	*httptest.Server
	Token   string
	HMACKey []byte

	mu       sync.Mutex
	failures int
	events   []ReceivedEvent
	requests int
}

// ReceivedEvent is one delivered revocation event.
type ReceivedEvent struct {
	Event          revocation.Event
	ReceivedAt     time.Time
	SignatureValid bool
	AuthValid      bool
}

// NewFakePolicy starts a policy stub that fails the first `failures`
// requests with HTTP 500.
func NewFakePolicy(t testing.TB, failures int) *FakePolicy {
	t.Helper()
	fp := &FakePolicy{Token: "policy-token", HMACKey: []byte("policy-hmac-key"), failures: failures}
	fp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		defer fp.mu.Unlock()
		fp.requests++
		if r.Method != http.MethodPost || r.URL.Path != revocation.PublishPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if fp.failures > 0 {
			fp.failures--
			http.Error(w, "flaky", http.StatusInternalServerError)
			return
		}
		var ev revocation.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		fp.events = append(fp.events, ReceivedEvent{
			Event:          ev,
			ReceivedAt:     time.Now(),
			SignatureValid: revocation.VerifySignature(fp.HMACKey, body, r.Header.Get(revocation.HeaderSignature)),
			AuthValid:      r.Header.Get("Authorization") == "Bearer "+fp.Token,
		})
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(fp.Server.Close)
	return fp
}

// Events returns the delivered events.
func (fp *FakePolicy) Events() []ReceivedEvent {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return append([]ReceivedEvent(nil), fp.events...)
}

// Requests returns the number of HTTP requests received (including failures).
func (fp *FakePolicy) Requests() int {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.requests
}

// WaitContext returns a context with a short timeout for test calls.
func WaitContext(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

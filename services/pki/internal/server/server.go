// Package server assembles the two HTTP listeners of the PKI service:
//
//	mTLS  (:8443)  EST, OCSP and the management API; client certificates are
//	               verified against the Factory, Device and Services CAs when
//	               presented (cacerts/csrattrs/OCSP need none).
//	plain (:8444)  CRL, Prometheus metrics, /healthz and /readyz.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/crl"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ocsp"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Deps are the components mounted on the listeners.
type Deps struct {
	Logger  *slog.Logger
	Metrics *metrics.Metrics
	Store   store.Store
	EST     *est.Handler
	OCSP    *ocsp.Responder
	Mgmt    *mgmt.Handler
	CRL     *crl.Manager
}

// NewMTLSHandler builds the handler for the mTLS listener.
func NewMTLSHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	if d.EST != nil {
		d.EST.Register(mux)
	}
	if d.OCSP != nil {
		d.OCSP.Register(mux)
	}
	if d.Mgmt != nil {
		d.Mgmt.Register(mux)
	}
	return logging.Middleware(d.Logger, securityHeaders(mux))
}

// NewPlainHandler builds the handler for the plain listener.
func NewPlainHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	if d.CRL != nil {
		d.CRL.Register(mux)
	}
	if d.Metrics != nil {
		mux.Handle("GET /metrics", d.Metrics.Handler())
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if d.Store != nil {
			if err := d.Store.Ping(ctx); err != nil {
				http.Error(w, "store unavailable: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		if d.CRL != nil {
			if _, _, _, _, ok := d.CRL.Current(); !ok {
				http.Error(w, "crl not generated yet", http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	return logging.Middleware(d.Logger, securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// TLSConfig returns the mTLS listener configuration: TLS 1.3 only (every
// device stack and service supports it; THREAT_MODEL T-30), the server
// certificate chain and optional client certificates verified against
// clientCAs. Endpoints that need a client certificate enforce it themselves.
// TLS 1.3 cipher suites are not configurable in Go and are all AEAD.
func TLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{serverCert},
		ClientCAs:        clientCAs,
		ClientAuth:       tls.VerifyClientCertIfGiven,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:       []string{"http/1.1"},
	}
}

// ClientCAPool builds the pool of CAs whose client certificates are accepted.
func ClientCAPool(cas ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range cas {
		if c != nil {
			pool.AddCert(c)
		}
	}
	return pool
}

// Options configures Run.
type Options struct {
	MTLSAddr        string
	PlainAddr       string
	TLS             *tls.Config
	MTLSHandler     http.Handler
	PlainHandler    http.Handler
	Logger          *slog.Logger
	ShutdownTimeout time.Duration
	// Ready, when non-nil, receives the bound addresses once both listeners
	// accept connections (tests bind port 0).
	Ready chan<- Addrs
}

// Addrs are the bound listener addresses.
type Addrs struct {
	MTLS  string
	Plain string
}

// Run serves both listeners until ctx is cancelled or a listener fails, then
// shuts down gracefully.
func Run(ctx context.Context, opts Options) error {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = 15 * time.Second
	}
	if opts.TLS == nil {
		return errors.New("server: TLS configuration is required")
	}
	mtlsLn, err := net.Listen("tcp", opts.MTLSAddr)
	if err != nil {
		return err
	}
	plainLn, err := net.Listen("tcp", opts.PlainAddr)
	if err != nil {
		mtlsLn.Close()
		return err
	}
	mtlsSrv := &http.Server{Handler: opts.MTLSHandler, TLSConfig: opts.TLS, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	plainSrv := &http.Server{Handler: opts.PlainHandler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}

	errCh := make(chan error, 2)
	go func() {
		opts.Logger.Info("mTLS listener started", "addr", mtlsLn.Addr().String())
		errCh <- mtlsSrv.ServeTLS(mtlsLn, "", "")
	}()
	go func() {
		opts.Logger.Info("plain listener started", "addr", plainLn.Addr().String())
		errCh <- plainSrv.Serve(plainLn)
	}()
	if opts.Ready != nil {
		opts.Ready <- Addrs{MTLS: mtlsLn.Addr().String(), Plain: plainLn.Addr().String()}
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.ShutdownTimeout)
	defer cancel()
	opts.Logger.Info("shutting down listeners")
	err1 := mtlsSrv.Shutdown(shutdownCtx)
	err2 := plainSrv.Shutdown(shutdownCtx)
	return errors.Join(serveErr, err1, err2)
}

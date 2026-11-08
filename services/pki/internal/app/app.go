// Package app wires the PKI service from its configuration: key material and
// CA certificates, store, registry and policy clients, EST / OCSP / CRL /
// management components and the two listeners.
package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/crl"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/awskms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/file"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/pkcs11"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ocsp"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/server"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store/postgres"
)

// App is a fully wired PKI service.
type App struct {
	Config  *config.Config
	Logger  *slog.Logger
	Metrics *metrics.Metrics
	Store   store.Store

	Root, Factory, Services *x509.Certificate
	DeviceCA                *ca.CA
	ServicesCA              *ca.CA

	EST     *est.Handler
	OCSP    *ocsp.Responder
	Mgmt    *mgmt.Handler
	CRL     *crl.Manager
	Revoker *revocation.Service

	ServerCert tls.Certificate
	TLS        *tls.Config

	// Ready, when set before Run, receives the bound listener addresses.
	Ready chan<- server.Addrs

	closers []func()
}

// Build constructs the application. Nothing listens yet; call Run.
func Build(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*App, error) {
	if cfg == nil {
		return nil, errors.New("app: configuration is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &App{Config: cfg, Logger: logger, Metrics: metrics.New()}
	ok := false
	defer func() {
		if !ok {
			a.Close()
		}
	}()

	// Key material.
	provider, err := a.kmsProvider(ctx)
	if err != nil {
		return nil, err
	}
	layout := ca.Layout{Dir: cfg.CADir}
	if a.Root, err = layout.LoadCert(ca.KindRoot); err != nil {
		return nil, err
	}
	if a.Factory, err = layout.LoadCert(ca.KindFactory); err != nil {
		return nil, err
	}
	deviceCert, err := layout.LoadCert(ca.KindDevice)
	if err != nil {
		return nil, err
	}
	if a.Services, err = layout.LoadCert(ca.KindServices); err != nil {
		return nil, err
	}
	deviceSigner, err := provider.Open(ctx, cfg.DeviceCAKeyRef)
	if err != nil {
		return nil, fmt.Errorf("app: open Device CA key %q: %w", cfg.DeviceCAKeyRef, err)
	}
	servicesSigner, err := provider.Open(ctx, cfg.ServicesCAKeyRef)
	if err != nil {
		return nil, fmt.Errorf("app: open Services CA key %q: %w", cfg.ServicesCAKeyRef, err)
	}
	caOpts := ca.Options{CRLDistributionPoint: cfg.CRLDistributionPoint(), OCSPServer: cfg.OCSPURL(), OperationalTTL: cfg.OperationalCertTTL}
	if a.DeviceCA, err = ca.New(ca.KindDevice, deviceCert, deviceSigner, []*x509.Certificate{a.Root}, caOpts); err != nil {
		return nil, err
	}
	if a.ServicesCA, err = ca.New(ca.KindServices, a.Services, servicesSigner, []*x509.Certificate{a.Root}, caOpts); err != nil {
		return nil, err
	}
	bundleKey, err := a.loadBundleKey(ctx)
	if err != nil {
		return nil, err
	}
	if a.ServerCert, err = a.serverCertificate(); err != nil {
		return nil, err
	}

	// Store.
	if cfg.DatabaseURL != "" {
		pg, err := postgres.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		a.Store = pg
	} else {
		logger.Warn("PKI_DATABASE_URL is not set: using the in-memory store; all state is lost on restart")
		a.Store = store.NewMemory()
	}
	a.closers = append(a.closers, func() { _ = a.Store.Close() })

	// Outbound clients (mTLS with our own Services CA certificate).
	outbound := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      server.ClientCAPool(a.Root),
		Certificates: []tls.Certificate{a.ServerCert},
	}}}
	var reg registry.Client
	if cfg.RegistryURL != "" {
		reg = registry.NewHTTPClient(cfg.RegistryURL, cfg.RegistryToken, outbound)
	} else {
		logger.Warn("PKI_REGISTRY_URL is not set: device lifecycle checks are disabled (every device is treated as active)")
		reg = registry.AllowAll{}
	}
	var publisher revocation.Publisher
	if cfg.PolicyURL != "" {
		pub, err := revocation.NewHTTPPublisher(cfg.PolicyURL, cfg.PolicyToken, cfg.PolicyHMACKeyBytes(), outbound)
		if err != nil {
			return nil, err
		}
		pub.Logger = logger
		publisher = pub
	} else {
		logger.Warn("PKI_POLICY_URL is not set: revocation events are logged but not pushed")
		publisher = revocation.NoopPublisher{Logger: logger}
	}

	// Components.
	if a.CRL, err = crl.NewManager(a.DeviceCA, a.Store, crl.Options{Metrics: a.Metrics, Logger: logger}); err != nil {
		return nil, err
	}
	if err := a.CRL.Regenerate(ctx); err != nil {
		return nil, err
	}
	if a.OCSP, err = ocsp.NewResponder(a.DeviceCA, a.Store, ocsp.Options{Metrics: a.Metrics}); err != nil {
		return nil, err
	}
	if a.Revoker, err = revocation.NewService(a.Store, revocation.Options{CRL: a.CRL, OCSP: a.OCSP, Publisher: publisher, Metrics: a.Metrics, Logger: logger}); err != nil {
		return nil, err
	}
	pins, err := a.pins()
	if err != nil {
		return nil, err
	}
	bundler, err := est.NewBundler(bundleKey, cfg.BrokerHost, cfg.BrokerPort, pins)
	if err != nil {
		return nil, err
	}
	akRoots, err := loadOptionalCerts(cfg.TPMAKCAFile)
	if err != nil {
		return nil, fmt.Errorf("app: PKI_TPM_AK_CA_FILE: %w", err)
	}
	if a.EST, err = est.NewHandler(est.Config{
		DeviceCA: a.DeviceCA, FactoryCA: a.Factory,
		CACerts: []*x509.Certificate{a.Root, a.Factory, deviceCert, a.Services},
		Store:   a.Store, Registry: reg, Bundler: bundler, Metrics: a.Metrics,
		NonceTTL: cfg.NonceTTL, DefaultAllowSoftwareKeys: cfg.DefaultAllowSoftwareKeys,
		DefaultAKRoots: akRoots, DefaultPCRDigests: cfg.TPMAllowedPCRDigests,
	}); err != nil {
		return nil, err
	}
	jwtKeys, err := loadJWTKeys(cfg.MgmtJWTPublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("app: PKI_MGMT_JWT_PUBLIC_KEY_FILE: %w", err)
	}
	auth := mgmt.NewAuthenticator(a.Services, cfg.MgmtAllowedCNs, jwtKeys, nil)
	if a.Mgmt, err = mgmt.NewHandler(mgmt.Config{
		Auth: auth, Revoker: a.Revoker, Store: a.Store, Metrics: a.Metrics,
		Chain: []*x509.Certificate{a.Root, a.Factory, deviceCert, a.Services},
	}); err != nil {
		return nil, err
	}
	a.TLS = server.TLSConfig(a.ServerCert, server.ClientCAPool(a.Root, a.Factory, deviceCert, a.Services))
	ok = true
	return a, nil
}

func (a *App) kmsProvider(ctx context.Context) (kms.Provider, error) {
	cfg := a.Config
	switch cfg.KMS {
	case config.KMSFile:
		return &file.Provider{Passphrase: []byte(cfg.FileKMSPassphrase), Logger: a.Logger}, nil
	case config.KMSAWS:
		return awskms.NewProvider(ctx)
	case config.KMSSoftHSM:
		return pkcs11.New(pkcs11.Config{ModulePath: cfg.PKCS11Module, TokenLabel: cfg.PKCS11Token, PIN: cfg.PKCS11PIN})
	}
	return nil, fmt.Errorf("app: unknown KMS backend %q", cfg.KMS)
}

// loadBundleKey opens the Ed25519 bundle key; it always lives in the file
// backend because AWS KMS does not offer Ed25519.
func (a *App) loadBundleKey(ctx context.Context) (ed25519.PrivateKey, error) {
	prov := &file.Provider{Passphrase: []byte(a.Config.FileKMSPassphrase), Logger: a.Logger}
	signer, err := prov.Open(ctx, a.Config.BundleKeyFile)
	if err != nil {
		return nil, fmt.Errorf("app: open bundle key %q: %w", a.Config.BundleKeyFile, err)
	}
	key, ok := signer.(*file.Signer).Signer.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("app: bundle key must be Ed25519")
	}
	return key, nil
}

// serverCertificate loads PKI_SERVER_CERT_FILE/KEY_FILE or issues a fresh
// 90-day certificate from the Services CA.
func (a *App) serverCertificate() (tls.Certificate, error) {
	cfg := a.Config
	if cfg.ServerCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("app: load server certificate: %w", err)
		}
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := a.ServicesCA.IssueServer("pki", cfg.ServerSANs, key.Public())
	if err != nil {
		return tls.Certificate{}, err
	}
	a.Logger.Info("issued server certificate from the Services CA", "sans", cfg.ServerSANs, "not_after", leaf.NotAfter)
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, a.Services.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// pins returns the SPKI pins devices must trust: the Services CA (contract
// §4) and the root.
func (a *App) pins() ([][]byte, error) {
	var pins [][]byte
	for _, c := range []*x509.Certificate{a.Services, a.Root} {
		p, err := ca.SPKIPin(c.PublicKey)
		if err != nil {
			return nil, err
		}
		pins = append(pins, p)
	}
	return pins, nil
}

func loadOptionalCerts(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	return ca.LoadCertsPEM(path)
}

// loadJWTKeys parses every PUBLIC KEY block (ECDSA P-256) in a PEM file.
func loadJWTKeys(path string) ([]*ecdsa.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []*ecdsa.PublicKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ek, ok := pub.(*ecdsa.PublicKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, errors.New("JWT verification keys must be ECDSA P-256")
		}
		keys = append(keys, ek)
	}
	if len(keys) == 0 {
		return nil, errors.New("no PUBLIC KEY blocks found")
	}
	return keys, nil
}

// Run starts background maintenance and both listeners until ctx ends.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.CRL.Run(ctx)
	go a.maintenance(ctx)
	return server.Run(ctx, server.Options{
		MTLSAddr:        a.Config.ListenMTLS,
		PlainAddr:       a.Config.ListenPlain,
		TLS:             a.TLS,
		MTLSHandler:     a.MTLSHandler(),
		PlainHandler:    a.PlainHandler(),
		Logger:          a.Logger,
		ShutdownTimeout: a.Config.ShutdownTimeout,
		Ready:           a.Ready,
	})
}

// MTLSHandler returns the handler for the mTLS listener.
func (a *App) MTLSHandler() http.Handler {
	return server.NewMTLSHandler(a.deps())
}

// PlainHandler returns the handler for the plain listener.
func (a *App) PlainHandler() http.Handler {
	return server.NewPlainHandler(a.deps())
}

func (a *App) deps() server.Deps {
	return server.Deps{Logger: a.Logger, Metrics: a.Metrics, Store: a.Store, EST: a.EST, OCSP: a.OCSP, Mgmt: a.Mgmt, CRL: a.CRL}
}

// maintenance purges expired nonces and refreshes the expiring-certificate
// gauges every minute.
func (a *App) maintenance(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	a.maintainOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.maintainOnce(ctx)
		}
	}
}

func (a *App) maintainOnce(ctx context.Context) {
	now := time.Now()
	if n, err := a.Store.DeleteExpiredNonces(ctx, now); err != nil {
		a.Logger.Error("nonce purge failed", "error", err.Error())
	} else if n > 0 {
		a.Logger.Debug("purged expired nonces", "count", n)
	}
	if _, err := mgmt.ComputeStats(ctx, a.Store, a.Metrics, now); err != nil {
		a.Logger.Error("stats refresh failed", "error", err.Error())
	}
}

// Close releases resources.
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}

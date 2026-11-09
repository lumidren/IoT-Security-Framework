// Command policy is the IronMesh policy service: EMQX authn/authz backend, revocation cache with
// live-session kick, CRL fallback poller and the policy management API.
//
// "policy healthcheck [--url URL] [--timeout D]" GETs /healthz (default derived from
// POLICY_LISTEN) and exits 0 or 1, for container health checks in the distroless image.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/auth"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/clock"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/emqx"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/healthcheck"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/hooks"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheckMain(os.Args[2:], os.Getenv, os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "policy:", err)
		os.Exit(1)
	}
}

// healthcheckMain implements "policy healthcheck".
func healthcheckMain(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	listen := strings.TrimSpace(getenv("POLICY_LISTEN"))
	if listen == "" {
		listen = ":8081"
	}
	url := healthcheck.DefaultURL(listen, "/healthz")
	if strings.TrimSpace(getenv("POLICY_TLS_CERT_FILE")) != "" {
		url = "https://" + strings.TrimPrefix(url, "http://")
	}
	return healthcheck.Run(context.Background(), "policy", args, url, stdout, stderr)
}

// buildGuard returns the management API guard: ES256 service JWTs (POLICY_JWT_PUBLIC_KEY_PEM,
// aud=policy; single-use per instance with POLICY_JWT_SINGLE_USE) and/or console OIDC access
// tokens (POLICY_OIDC_ISSUER). On the TLS listener a caller presenting a Services CA certificate
// must present a token for the same service. With no verifier configured the API fails closed
// with 503.
func buildGuard(cfg config.Config, servicePEM, serviceIssuer string, servicesCA *x509.CertPool, log *slog.Logger) (auth.Guard, error) {
	var verifiers []auth.TokenVerifier
	if servicePEM != "" {
		opts := []auth.VerifierOption{auth.WithIssuer(serviceIssuer)}
		if cfg.JWTSingleUse {
			opts = append(opts, auth.WithReplayCache(auth.NewReplayCache(cfg.JWTReplayCacheSize)))
		} else {
			log.Warn("POLICY_JWT_SINGLE_USE=false: service JWTs can be replayed until they expire")
		}
		v, err := auth.NewVerifier(servicePEM, "policy", opts...)
		if err != nil {
			return nil, fmt.Errorf("POLICY_JWT_PUBLIC_KEY_PEM: %w", err)
		}
		verifiers = append(verifiers, v)
	}
	if cfg.OIDCIssuer != "" {
		v, err := auth.NewOIDCVerifier(auth.OIDCConfig{Issuer: cfg.OIDCIssuer, JWKSURL: cfg.OIDCJWKSURL, Audience: cfg.OIDCAudience, RoleClaim: cfg.OIDCRoleClaim})
		if err != nil {
			return nil, fmt.Errorf("POLICY_OIDC_ISSUER: %w", err)
		}
		verifiers = append(verifiers, v)
		log.Info("management API accepts console OIDC tokens", "issuer", cfg.OIDCIssuer, "audience", cfg.OIDCAudience, "role_claim", cfg.OIDCRoleClaim)
	}
	if len(verifiers) == 0 {
		log.Warn("neither POLICY_JWT_PUBLIC_KEY_PEM nor POLICY_OIDC_ISSUER is set: the management API (/v1/*) answers 503")
		return auth.DisabledGuard("management API disabled: configure POLICY_JWT_PUBLIC_KEY_PEM and/or POLICY_OIDC_ISSUER"), nil
	}
	return auth.NewBoundGuard(servicesCA, verifiers...), nil
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log := logging.New(os.Stdout, "policy", cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := metrics.New(reg)
	realClock := clock.Real{}

	// Revocation cache + PKI event handler + kicker.
	snapshotPath := ""
	if cfg.StateDir != "" {
		snapshotPath = filepath.Join(cfg.StateDir, revocation.SnapshotName)
	} else {
		log.Warn("POLICY_STATE_DIR is empty: revocation cache and policy versions will not survive restarts")
	}
	cache := revocation.NewCache(snapshotPath, realClock.Now)
	restored, err := cache.Load()
	if err != nil {
		return fmt.Errorf("load revocation snapshot: %w", err)
	}
	log.Info("revocation cache loaded", "entries", restored, "path", snapshotPath)

	kicker, err := emqx.NewClient(cfg.EMQXAPIURL, cfg.EMQXAPIKey, cfg.EMQXAPISecret, emqx.WithLogger(log))
	if err != nil {
		return err
	}
	// Session attributes and certificate serials recorded at authn; the revocation service uses
	// the serials to skip kicks of sessions that already run on a renewed certificate.
	identities := hooks.NewIdentityCache(0, 0, nil)
	revocations, err := revocation.NewService(revocation.ServiceConfig{
		Cache:      cache,
		Kicker:     kicker,
		Token:      cfg.PKIToken,
		HMACSecret: cfg.PKIHMACSecret,
		Clock:      realClock,
		Metrics:    m,
		Logger:     log,
		Sessions:   identities,
	})
	if err != nil {
		return err
	}
	revocations.Start(ctx)

	// CRL fallback poller.
	pollerCfg := revocation.PollerConfig{
		URL:      cfg.PKICRLURL,
		Apply:    revocations,
		Interval: cfg.CRLPollInterval,
		Metrics:  m,
		Logger:   log,
		Clock:    realClock,
	}
	if cfg.CRLIssuerCertFile != "" {
		cert, err := revocation.LoadIssuer(cfg.CRLIssuerCertFile)
		if err != nil {
			return err
		}
		pollerCfg.Issuer = cert
	}
	poller, err := revocation.NewPoller(pollerCfg)
	if err != nil {
		return err
	}
	go poller.Run(ctx)

	// Policy engine (embedded Rego + persisted versions).
	eng, err := engine.New(ctx, engine.Options{StateDir: cfg.StateDir, Logger: log})
	if err != nil {
		return err
	}

	// Registry lifecycle lookups.
	reg2, err := registry.New(cfg.RegistryURL, cfg.RegistryToken,
		registry.WithTimeout(cfg.RegistryTimeout),
		registry.WithCacheTTL(cfg.RegistryCacheTTL),
		registry.WithLookupHook(func(result string) { m.RegistryLookups.WithLabelValues(result).Inc() }),
	)
	if err != nil {
		return err
	}

	serviceCIDRs, err := hooks.ParseCIDRs(cfg.ServiceCIDRs)
	if err != nil {
		return fmt.Errorf("POLICY_SERVICE_CIDRS: %w", err)
	}
	deviceCAs, err := hooks.LoadCertificates(cfg.DeviceCAFile)
	if err != nil {
		return fmt.Errorf("POLICY_DEVICE_CA_FILE: %w", err)
	}
	servicesCAs, err := hooks.LoadCertificates(cfg.ServicesCAFile)
	if err != nil {
		return fmt.Errorf("POLICY_SERVICES_CA_FILE: %w", err)
	}
	if len(deviceCAs) == 0 || len(servicesCAs) == 0 {
		log.Warn("POLICY_DEVICE_CA_FILE and/or POLICY_SERVICES_CA_FILE not set: the issuer of cert_pem is not checked at CONNECT for that identity kind")
	}
	authn, err := hooks.NewAuthn(hooks.AuthnConfig{
		Registry:           reg2,
		Revoked:            cache,
		Identities:         identities,
		Metrics:            m,
		Logger:             log,
		FailOpen:           cfg.RegistryFailOpen,
		AllowMissingSerial: !cfg.RequireCertSerial,
		DeviceCAs:          deviceCAs,
		ServicesCAs:        servicesCAs,
		ServiceCIDRs:       serviceCIDRs,
	})
	if err != nil {
		return err
	}
	authz, err := hooks.NewAuthz(hooks.AuthzConfig{
		Engine:     eng,
		Identities: identities,
		Metrics:    m,
		Logger:     log,
		CacheTTL:   cfg.AuthzCacheTTL,
	})
	if err != nil {
		return err
	}
	eng.OnSwap(authz.FlushCache)

	// Management API guard.
	servicesPool := hooks.CertPool(servicesCAs)
	guard, err := buildGuard(cfg, os.Getenv("POLICY_JWT_PUBLIC_KEY_PEM"), os.Getenv("POLICY_JWT_ISSUER"), servicesPool, log)
	if err != nil {
		return err
	}
	api, err := mgmt.New(mgmt.Config{Engine: eng, Revocations: cache, Guard: guard, Logger: log})
	if err != nil {
		return err
	}

	handler := server.NewHandler(server.Config{
		Authn:       authn,
		Authz:       authz,
		Revocations: revocations.Handler(),
		Metrics:     promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		Register:    api.Register,
		HookToken:   cfg.HookToken,
		Ready: func() error {
			if ctx.Err() != nil {
				return errors.New("shutting down")
			}
			return nil
		},
		Logger: log,
	})

	var tlsCfg *tls.Config
	if cfg.TLSCertFile != "" {
		if tlsCfg, err = server.TLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, servicesPool); err != nil {
			return err
		}
	}
	ln, err := server.Listen(cfg.Listen, tlsCfg)
	if err != nil {
		return err
	}
	log.Info("policy service starting", "listen", cfg.Listen, "tls", tlsCfg != nil, "emqx_api", cfg.EMQXAPIURL, "registry", cfg.RegistryURL,
		"crl_url", cfg.PKICRLURL, "crl_interval", cfg.CRLPollInterval.String(), "policy_version", eng.Current().Version,
		"registry_fail_open", cfg.RegistryFailOpen, "require_cert_serial", cfg.RequireCertSerial, "jwt_single_use", cfg.JWTSingleUse)
	err = server.Serve(ctx, ln, handler, cfg.ShutdownTimeout, log)
	stop()
	waitCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() { revocations.Wait(); close(done) }()
	select {
	case <-done:
	case <-waitCtx.Done():
		log.Warn("revocation worker did not stop in time")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("policy service stopped")
	return nil
}

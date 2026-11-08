// Command policy is the IronMesh policy service: EMQX authn/authz backend, revocation cache with
// live-session kick, CRL fallback poller and the policy management API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/auth"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/clock"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/emqx"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/hooks"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "policy:", err)
		os.Exit(1)
	}
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
	revocations, err := revocation.NewService(revocation.ServiceConfig{
		Cache:      cache,
		Kicker:     kicker,
		Token:      cfg.PKIToken,
		HMACSecret: cfg.PKIHMACSecret,
		Clock:      realClock,
		Metrics:    m,
		Logger:     log,
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
	identities := hooks.NewIdentityCache(0, 0, nil)
	authn, err := hooks.NewAuthn(hooks.AuthnConfig{
		Registry:     reg2,
		Revoked:      cache,
		Identities:   identities,
		Metrics:      m,
		Logger:       log,
		FailOpen:     cfg.RegistryFailOpen,
		ServiceCIDRs: serviceCIDRs,
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
	var guard auth.Guard
	if pemKey := os.Getenv("POLICY_JWT_PUBLIC_KEY_PEM"); pemKey != "" {
		verifier, err := auth.NewVerifier(pemKey, "policy", auth.WithIssuer(os.Getenv("POLICY_JWT_ISSUER")))
		if err != nil {
			return fmt.Errorf("POLICY_JWT_PUBLIC_KEY_PEM: %w", err)
		}
		guard = verifier.Guard()
	} else {
		log.Warn("POLICY_JWT_PUBLIC_KEY_PEM is not set: the management API (/v1/*) answers 503")
		guard = auth.DisabledGuard("management API disabled: POLICY_JWT_PUBLIC_KEY_PEM is not configured")
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

	log.Info("policy service starting", "listen", cfg.Listen, "emqx_api", cfg.EMQXAPIURL, "registry", cfg.RegistryURL,
		"crl_url", cfg.PKICRLURL, "crl_interval", cfg.CRLPollInterval.String(), "policy_version", eng.Current().Version,
		"registry_fail_open", cfg.RegistryFailOpen)
	err = server.Run(ctx, cfg.Listen, handler, cfg.ShutdownTimeout, log)
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

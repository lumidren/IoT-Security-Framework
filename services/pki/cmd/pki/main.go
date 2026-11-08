// Command pki runs the IronMesh Device PKI service: EST with attestation,
// OCSP and the management API on the mTLS listener (PKI_LISTEN_MTLS, :8443)
// and the CRL, metrics and health endpoints on the plain listener
// (PKI_LISTEN_PLAIN, :8444). All configuration comes from PKI_* environment
// variables; see README.md.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/app"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
)

func main() {
	os.Exit(run(context.Background(), os.Stdout, os.Stderr))
}

// requireProductionKMS refuses to start with the development file KMS when
// PKI_ENV=production: CA private keys must live in an HSM or cloud KMS.
func requireProductionKMS(cfg *config.Config) error {
	if cfg.Env == config.EnvProduction && cfg.KMS == config.KMSFile {
		return fmt.Errorf("refusing to start: PKI_KMS=%s is not allowed when PKI_ENV=%s (use softhsm or awskms)", cfg.KMS, cfg.Env)
	}
	return nil
}

func run(ctx context.Context, stdout, stderr io.Writer) int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := requireProductionKMS(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	logger := logging.New(stdout, cfg.LogLevel)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.Build(ctx, cfg, logger)
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		return 1
	}
	defer a.Close()
	logger.Info("pki service starting", "mtls", cfg.ListenMTLS, "plain", cfg.ListenPlain, "kms", cfg.KMS, "operational_ttl", cfg.OperationalCertTTL.String())
	if err := a.Run(ctx); err != nil {
		logger.Error("server exited with error", "error", err.Error())
		return 1
	}
	logger.Info("pki service stopped")
	return 0
}

package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func lookup(m map[string]string) Lookup {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Load(lookup(map[string]string{"PKI_FILE_KMS_PASSPHRASE": "pw"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenMTLS != ":8443" || cfg.ListenPlain != ":8444" || cfg.KMS != KMSFile || cfg.OperationalCertTTL != 336*time.Hour ||
		cfg.NonceTTL != 120*time.Second || cfg.BrokerPort != 8883 || cfg.LogLevel != slog.LevelInfo || cfg.ShutdownTimeout != 15*time.Second {
		t.Fatalf("defaults %+v", cfg)
	}
	if cfg.DeviceCAKeyRef != "./pki-data/device-ca.key.json" || cfg.ServicesCAKeyRef != "./pki-data/services-ca.key.json" || cfg.BundleKeyFile != "./pki-data/bundle.key.json" {
		t.Fatalf("key refs %+v", cfg)
	}
	if len(cfg.MgmtAllowedCNs) != 3 || len(cfg.ServerSANs) != 4 {
		t.Fatalf("lists %+v", cfg)
	}
	if cfg.CRLDistributionPoint() != "https://pki.ironmesh.local/crl/device-ca.crl" || cfg.OCSPURL() != "https://pki.ironmesh.local/ocsp" {
		t.Fatalf("urls %s %s", cfg.CRLDistributionPoint(), cfg.OCSPURL())
	}
	if string(cfg.PolicyHMACKeyBytes()) != "" {
		t.Fatal("hmac default")
	}
}

func TestExplicitValues(t *testing.T) {
	t.Parallel()
	cfg, err := Load(lookup(map[string]string{
		"PKI_LISTEN_MTLS": "127.0.0.1:9443", "PKI_LISTEN_PLAIN": "127.0.0.1:9444", "PKI_DATABASE_URL": "postgres://x",
		"PKI_KMS": "AWSKMS", "PKI_CA_DIR": "/etc/pki/", "PKI_OPERATIONAL_CERT_TTL": "168h", "PKI_NONCE_TTL": "30s",
		"PKI_POLICY_URL": "https://policy:8081/", "PKI_POLICY_TOKEN": "tok", "PKI_POLICY_HMAC_KEY": "hmac",
		"PKI_REGISTRY_URL": "https://registry:8000", "PKI_REGISTRY_TOKEN": "rt", "PKI_PUBLIC_BASE_URL": "https://pki.example/",
		"PKI_SERVER_CERT_FILE": "s.crt", "PKI_SERVER_KEY_FILE": "s.key", "PKI_SERVER_SANS": " pki , pki.example ",
		"PKI_MGMT_ALLOWED_CNS": "svc-a,,svc-b", "PKI_MGMT_JWT_PUBLIC_KEY_FILE": "jwt.pem", "PKI_DEFAULT_ALLOW_SOFTWARE_KEYS": "true",
		"PKI_TPM_AK_CA_FILE": "ak.pem", "PKI_TPM_ALLOWED_PCR_DIGESTS": strings.Repeat("ab", 32) + "," + strings.Repeat("CD", 32),
		"PKI_BROKER_HOST": "mqtt.example", "PKI_BROKER_PORT": "18883", "PKI_LOG_LEVEL": "debug", "PKI_SHUTDOWN_TIMEOUT": "3s",
		"PKI_KEY_DEVICE_CA": "alias/dev", "PKI_KEY_SERVICES_CA": "alias/svc", "PKI_BUNDLE_KEY_FILE": "/keys/bundle.json",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.KMS != KMSAWS || cfg.OperationalCertTTL != 168*time.Hour || cfg.NonceTTL != 30*time.Second || cfg.PolicyURL != "https://policy:8081/" ||
		cfg.PublicBaseURL != "https://pki.example" || len(cfg.ServerSANs) != 2 || cfg.ServerSANs[1] != "pki.example" || len(cfg.MgmtAllowedCNs) != 2 ||
		!cfg.DefaultAllowSoftwareKeys || len(cfg.TPMAllowedPCRDigests) != 2 || cfg.BrokerPort != 18883 || cfg.LogLevel != slog.LevelDebug ||
		cfg.ShutdownTimeout != 3*time.Second || cfg.DeviceCAKeyRef != "alias/dev" || cfg.BundleKeyFile != "/keys/bundle.json" {
		t.Fatalf("config %+v", cfg)
	}
	if string(cfg.PolicyHMACKeyBytes()) != "hmac" {
		t.Fatal("hmac key")
	}
	cfg.PolicyHMACKey = ""
	if string(cfg.PolicyHMACKeyBytes()) != "tok" {
		t.Fatal("hmac fallback to token")
	}
	// Default key refs per backend.
	soft, err := Load(lookup(map[string]string{"PKI_KMS": "softhsm"}))
	if err != nil || soft.DeviceCAKeyRef != "ironmesh-device-ca" {
		t.Fatalf("softhsm refs %+v %v", soft, err)
	}
	aws, err := Load(lookup(map[string]string{"PKI_KMS": "awskms"}))
	if err != nil || aws.ServicesCAKeyRef != "alias/ironmesh-services-ca" {
		t.Fatalf("aws refs %+v %v", aws, err)
	}
}

func TestValidationErrors(t *testing.T) {
	t.Parallel()
	base := map[string]string{"PKI_FILE_KMS_PASSPHRASE": "pw"}
	cases := map[string]map[string]string{
		"missing passphrase": {},
		"bad kms":            {"PKI_KMS": "vault"},
		"bad duration":       {"PKI_OPERATIONAL_CERT_TTL": "two weeks"},
		"ttl too low":        {"PKI_OPERATIONAL_CERT_TTL": "1h"},
		"ttl too high":       {"PKI_OPERATIONAL_CERT_TTL": "721h"},
		"nonce ttl too low":  {"PKI_NONCE_TTL": "1s"},
		"nonce ttl too high": {"PKI_NONCE_TTL": "1h"},
		"bad bool":           {"PKI_DEFAULT_ALLOW_SOFTWARE_KEYS": "maybe"},
		"bad int":            {"PKI_BROKER_PORT": "x"},
		"bad port":           {"PKI_BROKER_PORT": "70000"},
		"bad policy url":     {"PKI_POLICY_URL": "policy:8081", "PKI_POLICY_TOKEN": "t"},
		"policy no secret":   {"PKI_POLICY_URL": "http://policy"},
		"server cert only":   {"PKI_SERVER_CERT_FILE": "a.crt"},
		"bad pcr digest":     {"PKI_TPM_ALLOWED_PCR_DIGESTS": "abcd"},
		"bad log level":      {"PKI_LOG_LEVEL": "loud"},
		"migration url only": {"PKI_MIGRATION_DATABASE_URL": "postgres://owner@db/pki"},
		"iam without db":     {"PKI_DB_IAM_AUTH": "true"},
		"bad iam bool":       {"PKI_DATABASE_URL": "postgres://db/pki", "PKI_DB_IAM_AUTH": "yes please"},
		"bundle secret name": {"PKI_BUNDLE_KEY_SECRET_ARN": "ironmesh/bundle"},
	}
	for name, extra := range cases {
		m := map[string]string{}
		if name != "missing passphrase" {
			for k, v := range base {
				m[k] = v
			}
		}
		for k, v := range extra {
			m[k] = v
		}
		if _, err := Load(lookup(m)); err == nil {
			t.Errorf("%s: expected error", name)
		} else if !strings.Contains(err.Error(), "invalid configuration") {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("PKI_FILE_KMS_PASSPHRASE", "env-pw")
	t.Setenv("PKI_BROKER_PORT", "1883")
	t.Setenv("PKI_ENV", "Production")
	cfg, err := FromEnv()
	if err != nil || cfg.BrokerPort != 1883 || cfg.Env != EnvProduction {
		t.Fatalf("FromEnv: %+v %v", cfg, err)
	}
	t.Setenv("PKI_ENV", "mars")
	if _, err := FromEnv(); err == nil {
		t.Fatal("unknown environment accepted")
	}
}

func TestDatabaseAndSecretsSettings(t *testing.T) {
	t.Parallel()
	cfg, err := Load(lookup(map[string]string{"PKI_FILE_KMS_PASSPHRASE": "pw"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MigrationDatabaseURL != "" || cfg.DBIAMAuth || cfg.DBIAMRegion != "" || cfg.BundleKeySecretARN != "" {
		t.Fatalf("defaults %+v", cfg)
	}
	arn := "arn:aws:secretsmanager:eu-west-1:123456789012:secret:ironmesh/pki/bundle-key-AbCdEf"
	cfg, err = Load(lookup(map[string]string{
		"PKI_KMS":                    "awskms",
		"PKI_DATABASE_URL":           "postgres://pki_app@db.example:5432/pki?sslmode=verify-full",
		"PKI_MIGRATION_DATABASE_URL": "postgres://pki_owner:pw@db.example:5432/pki?sslmode=verify-full",
		"PKI_DB_IAM_AUTH":            "true",
		"PKI_DB_IAM_REGION":          "eu-west-1",
		"PKI_BUNDLE_KEY_SECRET_ARN":  arn,
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MigrationDatabaseURL != "postgres://pki_owner:pw@db.example:5432/pki?sslmode=verify-full" || !cfg.DBIAMAuth ||
		cfg.DBIAMRegion != "eu-west-1" || cfg.BundleKeySecretARN != arn {
		t.Fatalf("values %+v", cfg)
	}
}

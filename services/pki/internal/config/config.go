// Package config parses the PKI service configuration from environment
// variables (all prefixed PKI_).
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
)

// KMS backends.
const (
	KMSFile    = "file"
	KMSSoftHSM = "softhsm"
	KMSAWS     = "awskms"
)

// Environments.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Config is the service configuration.
type Config struct {
	// Env is PKI_ENV: development (default) or production. Production refuses
	// the file KMS backend.
	Env         string
	ListenMTLS  string
	ListenPlain string
	DatabaseURL string

	KMS               string
	FileKMSPassphrase string
	PKCS11Module      string
	PKCS11Token       string
	PKCS11PIN         string

	// CADir holds the CA certificates (root.crt, factory-ca.crt, device-ca.crt,
	// services-ca.crt) and, for the file KMS, the key files.
	CADir            string
	DeviceCAKeyRef   string
	ServicesCAKeyRef string
	BundleKeyFile    string

	OperationalCertTTL time.Duration
	NonceTTL           time.Duration

	PolicyURL     string
	PolicyToken   string
	PolicyHMACKey string

	RegistryURL   string
	RegistryToken string

	PublicBaseURL  string
	ServerCertFile string
	ServerKeyFile  string
	ServerSANs     []string

	MgmtAllowedCNs       []string
	MgmtJWTPublicKeyFile string

	DefaultAllowSoftwareKeys bool
	TPMAKCAFile              string
	TPMAllowedPCRDigests     []string

	BrokerHost string
	BrokerPort int

	LogLevel        slog.Level
	ShutdownTimeout time.Duration
}

// Lookup resolves environment variables; os.LookupEnv in production.
type Lookup func(key string) (string, bool)

// FromEnv builds the configuration from the process environment.
func FromEnv() (*Config, error) { return Load(os.LookupEnv) }

// Load builds and validates the configuration using lookup.
func Load(lookup Lookup) (*Config, error) {
	get := func(key, def string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}
	list := func(key, def string) []string {
		var out []string
		for _, s := range strings.Split(get(key, def), ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var errs []string
	duration := func(key, def string) time.Duration {
		v := get(key, def)
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid duration %q", key, v))
		}
		return d
	}
	boolean := func(key string, def bool) bool {
		v := get(key, "")
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid boolean %q", key, v))
		}
		return b
	}
	integer := func(key string, def int) int {
		v := get(key, "")
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid integer %q", key, v))
		}
		return n
	}

	caDir := get("PKI_CA_DIR", "./pki-data")
	cfg := &Config{
		Env:               strings.ToLower(get("PKI_ENV", EnvDevelopment)),
		ListenMTLS:        get("PKI_LISTEN_MTLS", ":8443"),
		ListenPlain:       get("PKI_LISTEN_PLAIN", ":8444"),
		DatabaseURL:       get("PKI_DATABASE_URL", ""),
		KMS:               strings.ToLower(get("PKI_KMS", KMSFile)),
		FileKMSPassphrase: get("PKI_FILE_KMS_PASSPHRASE", ""),
		PKCS11Module:      get("PKI_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"),
		PKCS11Token:       get("PKI_PKCS11_TOKEN", "ironmesh"),
		PKCS11PIN:         get("PKI_PKCS11_PIN", ""),
		CADir:             caDir,
		DeviceCAKeyRef:    get("PKI_KEY_DEVICE_CA", ""),
		ServicesCAKeyRef:  get("PKI_KEY_SERVICES_CA", ""),
		BundleKeyFile:     get("PKI_BUNDLE_KEY_FILE", caDir+"/bundle.key.json"),

		OperationalCertTTL: duration("PKI_OPERATIONAL_CERT_TTL", "336h"),
		NonceTTL:           duration("PKI_NONCE_TTL", "120s"),

		PolicyURL:     get("PKI_POLICY_URL", ""),
		PolicyToken:   get("PKI_POLICY_TOKEN", ""),
		PolicyHMACKey: get("PKI_POLICY_HMAC_KEY", ""),

		RegistryURL:   get("PKI_REGISTRY_URL", ""),
		RegistryToken: get("PKI_REGISTRY_TOKEN", ""),

		PublicBaseURL:  strings.TrimRight(get("PKI_PUBLIC_BASE_URL", "https://pki.ironmesh.local"), "/"),
		ServerCertFile: get("PKI_SERVER_CERT_FILE", ""),
		ServerKeyFile:  get("PKI_SERVER_KEY_FILE", ""),
		ServerSANs:     list("PKI_SERVER_SANS", "pki,pki.ironmesh.local,localhost,127.0.0.1"),

		MgmtAllowedCNs:       list("PKI_MGMT_ALLOWED_CNS", "svc-registry,svc-policy,svc-console"),
		MgmtJWTPublicKeyFile: get("PKI_MGMT_JWT_PUBLIC_KEY_FILE", ""),

		DefaultAllowSoftwareKeys: boolean("PKI_DEFAULT_ALLOW_SOFTWARE_KEYS", false),
		TPMAKCAFile:              get("PKI_TPM_AK_CA_FILE", ""),
		TPMAllowedPCRDigests:     list("PKI_TPM_ALLOWED_PCR_DIGESTS", ""),

		BrokerHost: get("PKI_BROKER_HOST", "mqtt.ironmesh.local"),
		BrokerPort: integer("PKI_BROKER_PORT", 8883),

		ShutdownTimeout: duration("PKI_SHUTDOWN_TIMEOUT", "15s"),
	}
	if cfg.DeviceCAKeyRef == "" {
		cfg.DeviceCAKeyRef = defaultKeyRef(cfg.KMS, caDir, "device-ca")
	}
	if cfg.ServicesCAKeyRef == "" {
		cfg.ServicesCAKeyRef = defaultKeyRef(cfg.KMS, caDir, "services-ca")
	}
	level, ok := logging.ParseLevel(get("PKI_LOG_LEVEL", "info"))
	if !ok {
		errs = append(errs, "PKI_LOG_LEVEL: must be debug, info, warn or error")
	}
	cfg.LogLevel = level

	switch cfg.Env {
	case EnvDevelopment, EnvProduction, "staging", "test":
	default:
		errs = append(errs, fmt.Sprintf("PKI_ENV: unknown environment %q", cfg.Env))
	}
	switch cfg.KMS {
	case KMSFile, KMSSoftHSM, KMSAWS:
	default:
		errs = append(errs, fmt.Sprintf("PKI_KMS: unknown backend %q (file, softhsm or awskms)", cfg.KMS))
	}
	if cfg.KMS == KMSFile && cfg.FileKMSPassphrase == "" {
		errs = append(errs, "PKI_FILE_KMS_PASSPHRASE: required with PKI_KMS=file")
	}
	if cfg.OperationalCertTTL != 0 {
		if err := ca.ValidateOperationalTTL(cfg.OperationalCertTTL); err != nil {
			errs = append(errs, "PKI_OPERATIONAL_CERT_TTL: "+err.Error())
		}
	}
	if cfg.NonceTTL < 10*time.Second || cfg.NonceTTL > 10*time.Minute {
		errs = append(errs, "PKI_NONCE_TTL: must be between 10s and 10m")
	}
	if cfg.PolicyURL != "" && !strings.HasPrefix(cfg.PolicyURL, "http://") && !strings.HasPrefix(cfg.PolicyURL, "https://") {
		errs = append(errs, "PKI_POLICY_URL: must be an http(s) URL")
	}
	if cfg.PolicyURL != "" && cfg.PolicyHMACKey == "" && cfg.PolicyToken == "" {
		errs = append(errs, "PKI_POLICY_HMAC_KEY or PKI_POLICY_TOKEN: required with PKI_POLICY_URL")
	}
	if cfg.BrokerPort <= 0 || cfg.BrokerPort > 65535 {
		errs = append(errs, "PKI_BROKER_PORT: must be 1-65535")
	}
	if (cfg.ServerCertFile == "") != (cfg.ServerKeyFile == "") {
		errs = append(errs, "PKI_SERVER_CERT_FILE and PKI_SERVER_KEY_FILE must be set together")
	}
	for _, d := range cfg.TPMAllowedPCRDigests {
		if len(d) != 64 || !isHex(d) {
			errs = append(errs, fmt.Sprintf("PKI_TPM_ALLOWED_PCR_DIGESTS: %q is not a hex SHA-256", d))
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return cfg, nil
}

func defaultKeyRef(kms, caDir, name string) string {
	switch kms {
	case KMSFile:
		return caDir + "/" + name + ".key.json"
	case KMSSoftHSM:
		return "ironmesh-" + name
	default:
		return "alias/ironmesh-" + name
	}
}

// PolicyHMACKeyBytes returns the HMAC key, falling back to the bearer token.
func (c *Config) PolicyHMACKeyBytes() []byte {
	if c.PolicyHMACKey != "" {
		return []byte(c.PolicyHMACKey)
	}
	return []byte(c.PolicyToken)
}

// CRLDistributionPoint is the URL embedded in device certificates.
func (c *Config) CRLDistributionPoint() string { return c.PublicBaseURL + "/crl/device-ca.crl" }

// OCSPURL is the AIA OCSP URL embedded in device certificates.
func (c *Config) OCSPURL() string { return c.PublicBaseURL + "/ocsp" }

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

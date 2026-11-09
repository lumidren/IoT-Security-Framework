// Package config loads the policy service configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved service configuration.
type Config struct {
	// Listen is the HTTP listen address (POLICY_LISTEN, default :8081).
	Listen string

	// EMQXAPIURL is the EMQX management API base URL (POLICY_EMQX_API_URL).
	EMQXAPIURL string
	// EMQXAPIKey / EMQXAPISecret authenticate against the management API.
	EMQXAPIKey    string
	EMQXAPISecret string

	// PKICRLURL is the Device CA CRL distribution point polled as the fallback revocation path.
	PKICRLURL string
	// PKIHMACSecret verifies X-IronMesh-Signature on revocation events.
	PKIHMACSecret string
	// PKIToken is the bearer token the PKI presents on revocation events.
	PKIToken string
	// CRLPollInterval is how often the CRL is fetched (POLICY_CRL_POLL_INTERVAL, default 5s).
	CRLPollInterval time.Duration
	// CRLIssuerCertFile optionally points at the Device CA certificate used to verify CRL signatures.
	CRLIssuerCertFile string

	// RegistryURL is the Registry base URL used for lifecycle lookups.
	RegistryURL string
	// RegistryToken is the bearer token presented to the Registry.
	RegistryToken string
	// RegistryFailOpen allows devices when the Registry is unreachable (POLICY_REGISTRY_FAIL_OPEN).
	RegistryFailOpen bool
	// RegistryTimeout bounds a lifecycle lookup (default 2s).
	RegistryTimeout time.Duration
	// RegistryCacheTTL is how long lifecycle answers are cached (default 30s).
	RegistryCacheTTL time.Duration

	// ServiceCIDRs are the networks service principals (svc-*) may connect from
	// (POLICY_SERVICE_CIDRS, comma-separated; default RFC 1918 ranges + loopback).
	ServiceCIDRs []string

	// StateDir holds the revocation cache snapshot (POLICY_STATE_DIR); empty disables persistence.
	StateDir string
	// HookToken, when set, must be presented by EMQX in X-IronMesh-Hook-Token on /emqx/* calls.
	HookToken string
	// AuthzCacheTTL is the authorization decision cache lifetime (default 10s).
	AuthzCacheTTL time.Duration
	// OIDCIssuer enables console OIDC access tokens on the management API (POLICY_OIDC_ISSUER);
	// the JWKS is discovered from <issuer>/.well-known/openid-configuration.
	OIDCIssuer string
	// OIDCJWKSURL overrides JWKS discovery (POLICY_OIDC_JWKS_URL), for an issuer URL that is not
	// reachable from the service.
	OIDCJWKSURL string
	// OIDCAudience must be contained in aud (POLICY_OIDC_AUDIENCE, default ironmesh-api).
	OIDCAudience string
	// OIDCRoleClaim names the role claim (POLICY_OIDC_ROLE_CLAIM, default role; dotted paths allowed).
	OIDCRoleClaim string
	// LogLevel is debug|info|warn|error.
	LogLevel string
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
}

// Load reads the configuration using getenv (os.Getenv in production). It returns every
// validation problem at once so operators can fix them in one go.
func Load(getenv func(string) string) (Config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	dur := func(key, def string) time.Duration {
		raw := get(key, def)
		d, err := time.ParseDuration(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid duration %q", key, raw))
			return 0
		}
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s: must be positive, got %q", key, raw))
		}
		return d
	}
	boolean := func(key string, def bool) bool {
		raw := get(key, "")
		if raw == "" {
			return def
		}
		b, err := strconv.ParseBool(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid boolean %q", key, raw))
			return def
		}
		return b
	}

	cfg := Config{
		Listen:            get("POLICY_LISTEN", ":8081"),
		EMQXAPIURL:        get("POLICY_EMQX_API_URL", "http://emqx:18083"),
		EMQXAPIKey:        get("POLICY_EMQX_API_KEY", ""),
		EMQXAPISecret:     get("POLICY_EMQX_API_SECRET", ""),
		PKICRLURL:         get("POLICY_PKI_CRL_URL", "http://pki:8444/crl/device-ca.crl"),
		PKIHMACSecret:     get("POLICY_PKI_HMAC_SECRET", ""),
		PKIToken:          get("POLICY_PKI_TOKEN", ""),
		CRLPollInterval:   dur("POLICY_CRL_POLL_INTERVAL", "5s"),
		CRLIssuerCertFile: get("POLICY_CRL_ISSUER_CERT_FILE", ""),
		RegistryURL:       get("POLICY_REGISTRY_URL", ""),
		RegistryToken:     get("POLICY_REGISTRY_TOKEN", ""),
		RegistryFailOpen:  boolean("POLICY_REGISTRY_FAIL_OPEN", false),
		RegistryTimeout:   dur("POLICY_REGISTRY_TIMEOUT", "2s"),
		RegistryCacheTTL:  dur("POLICY_REGISTRY_CACHE_TTL", "30s"),
		ServiceCIDRs:      splitList(get("POLICY_SERVICE_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8")),
		StateDir:          get("POLICY_STATE_DIR", ""),
		HookToken:         get("POLICY_HOOK_TOKEN", ""),
		AuthzCacheTTL:     dur("POLICY_AUTHZ_CACHE_TTL", "10s"),
		OIDCIssuer:        get("POLICY_OIDC_ISSUER", ""),
		OIDCJWKSURL:       get("POLICY_OIDC_JWKS_URL", ""),
		OIDCAudience:      get("POLICY_OIDC_AUDIENCE", "ironmesh-api"),
		OIDCRoleClaim:     get("POLICY_OIDC_ROLE_CLAIM", "role"),
		LogLevel:          get("POLICY_LOG_LEVEL", "info"),
		ShutdownTimeout:   dur("POLICY_SHUTDOWN_TIMEOUT", "10s"),
	}

	if cfg.EMQXAPIKey == "" || cfg.EMQXAPISecret == "" {
		errs = append(errs, errors.New("POLICY_EMQX_API_KEY and POLICY_EMQX_API_SECRET are required to kick revoked sessions"))
	}
	if cfg.PKIHMACSecret == "" {
		errs = append(errs, errors.New("POLICY_PKI_HMAC_SECRET is required to verify revocation events"))
	}
	if cfg.PKIToken == "" {
		errs = append(errs, errors.New("POLICY_PKI_TOKEN is required to authenticate revocation events"))
	}
	if cfg.RegistryURL == "" {
		errs = append(errs, errors.New("POLICY_REGISTRY_URL is required for lifecycle checks"))
	}
	for key, raw := range map[string]string{
		"POLICY_EMQX_API_URL": cfg.EMQXAPIURL,
		"POLICY_PKI_CRL_URL":  cfg.PKICRLURL,
		"POLICY_REGISTRY_URL": cfg.RegistryURL,
		"POLICY_OIDC_ISSUER":  cfg.OIDCIssuer,
	} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, fmt.Errorf("%s: invalid URL %q", key, raw))
		}
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("POLICY_LOG_LEVEL: unknown level %q", cfg.LogLevel))
	}
	if len(cfg.ServiceCIDRs) == 0 {
		errs = append(errs, errors.New("POLICY_SERVICE_CIDRS: at least one CIDR is required"))
	}
	for _, c := range cfg.ServiceCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			errs = append(errs, fmt.Errorf("POLICY_SERVICE_CIDRS: invalid CIDR %q", c))
		}
	}
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

func splitList(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// MapGetenv adapts a map to the getenv signature (used by tests and tooling).
func MapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

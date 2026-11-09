package config

import (
	"strings"
	"testing"
	"time"
)

func minimalEnv() map[string]string {
	return map[string]string{
		"POLICY_EMQX_API_KEY":    "key",
		"POLICY_EMQX_API_SECRET": "secret",
		"POLICY_PKI_HMAC_SECRET": "hmac",
		"POLICY_PKI_TOKEN":       "token",
		"POLICY_REGISTRY_URL":    "http://registry:8000",
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(MapGetenv(minimalEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8081" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.EMQXAPIURL != "http://emqx:18083" {
		t.Errorf("EMQXAPIURL = %q", cfg.EMQXAPIURL)
	}
	if cfg.PKICRLURL != "http://pki:8444/crl/device-ca.crl" {
		t.Errorf("PKICRLURL = %q", cfg.PKICRLURL)
	}
	if cfg.CRLPollInterval != 5*time.Second {
		t.Errorf("CRLPollInterval = %v", cfg.CRLPollInterval)
	}
	if cfg.RegistryTimeout != 2*time.Second || cfg.RegistryCacheTTL != 30*time.Second {
		t.Errorf("registry timeouts = %v / %v", cfg.RegistryTimeout, cfg.RegistryCacheTTL)
	}
	if cfg.AuthzCacheTTL != 10*time.Second {
		t.Errorf("AuthzCacheTTL = %v", cfg.AuthzCacheTTL)
	}
	if cfg.RegistryFailOpen {
		t.Error("RegistryFailOpen should default to false")
	}
	if cfg.LogLevel != "info" || cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("LogLevel/ShutdownTimeout = %q/%v", cfg.LogLevel, cfg.ShutdownTimeout)
	}
	if len(cfg.ServiceCIDRs) != 4 || cfg.ServiceCIDRs[0] != "10.0.0.0/8" || cfg.ServiceCIDRs[3] != "127.0.0.0/8" {
		t.Errorf("ServiceCIDRs = %v", cfg.ServiceCIDRs)
	}
	if cfg.OIDCIssuer != "" || cfg.OIDCAudience != "ironmesh-api" || cfg.OIDCRoleClaim != "role" {
		t.Errorf("OIDC defaults = %q %q %q", cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCRoleClaim)
	}
	if !cfg.RequireCertSerial || !cfg.JWTSingleUse || cfg.JWTReplayCacheSize != 100000 || cfg.DeviceCAFile != "" || cfg.ServicesCAFile != "" || cfg.TLSCertFile != "" {
		t.Errorf("hardening defaults = %+v", cfg)
	}
}

func TestLoadHardeningSettings(t *testing.T) {
	env := minimalEnv()
	env["POLICY_CRL_ISSUER_CERT_FILE"] = "/etc/ironmesh/device-ca.pem"
	cfg, err := Load(MapGetenv(env))
	if err != nil || cfg.DeviceCAFile != "/etc/ironmesh/device-ca.pem" {
		t.Fatalf("device CA defaults to the CRL issuer: %q %v", cfg.DeviceCAFile, err)
	}
	env["POLICY_DEVICE_CA_FILE"] = "/etc/ironmesh/device-ca-bundle.pem"
	env["POLICY_SERVICES_CA_FILE"] = "/etc/ironmesh/services-ca.pem"
	env["POLICY_REQUIRE_CERT_SERIAL"] = "false"
	env["POLICY_JWT_SINGLE_USE"] = "false"
	env["POLICY_JWT_REPLAY_CACHE_SIZE"] = "5000"
	env["POLICY_TLS_CERT_FILE"] = "/tls/tls.crt"
	env["POLICY_TLS_KEY_FILE"] = "/tls/tls.key"
	cfg, err = Load(MapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceCAFile != "/etc/ironmesh/device-ca-bundle.pem" || cfg.ServicesCAFile != "/etc/ironmesh/services-ca.pem" || cfg.RequireCertSerial ||
		cfg.JWTSingleUse || cfg.JWTReplayCacheSize != 5000 || cfg.TLSCertFile != "/tls/tls.crt" || cfg.TLSKeyFile != "/tls/tls.key" {
		t.Fatalf("settings = %+v", cfg)
	}
}

func TestLoadOIDC(t *testing.T) {
	env := minimalEnv()
	env["POLICY_OIDC_ISSUER"] = "https://idp.ironmesh.local/realms/ironmesh"
	env["POLICY_OIDC_AUDIENCE"] = "console"
	env["POLICY_OIDC_ROLE_CLAIM"] = "realm_access.roles"
	cfg, err := Load(MapGetenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDCIssuer != "https://idp.ironmesh.local/realms/ironmesh" || cfg.OIDCAudience != "console" || cfg.OIDCRoleClaim != "realm_access.roles" {
		t.Errorf("OIDC = %q %q %q", cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCRoleClaim)
	}
}

func TestLoadServiceCIDRs(t *testing.T) {
	env := minimalEnv()
	env["POLICY_SERVICE_CIDRS"] = " 10.1.0.0/16, fd00::/8 ,"
	cfg, err := Load(MapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ServiceCIDRs) != 2 || cfg.ServiceCIDRs[1] != "fd00::/8" {
		t.Errorf("ServiceCIDRs = %v", cfg.ServiceCIDRs)
	}
	env["POLICY_SERVICE_CIDRS"] = "10.1.0.0/16,not-a-cidr"
	if _, err := Load(MapGetenv(env)); err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("invalid CIDR err = %v", err)
	}
	env["POLICY_SERVICE_CIDRS"] = " , "
	if _, err := Load(MapGetenv(env)); err == nil || !strings.Contains(err.Error(), "at least one CIDR") {
		t.Errorf("empty CIDR list err = %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := minimalEnv()
	env["POLICY_LISTEN"] = "127.0.0.1:9000"
	env["POLICY_CRL_POLL_INTERVAL"] = "250ms"
	env["POLICY_REGISTRY_FAIL_OPEN"] = "true"
	env["POLICY_STATE_DIR"] = "/var/lib/policy"
	env["POLICY_HOOK_TOKEN"] = "hook"
	env["POLICY_LOG_LEVEL"] = "DEBUG"
	env["POLICY_CRL_ISSUER_CERT_FILE"] = "/etc/ironmesh/device-ca.pem"
	cfg, err := Load(MapGetenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" || cfg.CRLPollInterval != 250*time.Millisecond || !cfg.RegistryFailOpen {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.StateDir != "/var/lib/policy" || cfg.HookToken != "hook" || cfg.LogLevel != "DEBUG" || cfg.CRLIssuerCertFile == "" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]string)
		wantMsg string
	}{
		{"missing emqx key", func(m map[string]string) { delete(m, "POLICY_EMQX_API_KEY") }, "POLICY_EMQX_API_KEY"},
		{"missing hmac", func(m map[string]string) { delete(m, "POLICY_PKI_HMAC_SECRET") }, "POLICY_PKI_HMAC_SECRET"},
		{"missing pki token", func(m map[string]string) { delete(m, "POLICY_PKI_TOKEN") }, "POLICY_PKI_TOKEN"},
		{"missing registry", func(m map[string]string) { delete(m, "POLICY_REGISTRY_URL") }, "POLICY_REGISTRY_URL"},
		{"bad duration", func(m map[string]string) { m["POLICY_CRL_POLL_INTERVAL"] = "soon" }, "invalid duration"},
		{"negative duration", func(m map[string]string) { m["POLICY_REGISTRY_TIMEOUT"] = "-1s" }, "must be positive"},
		{"bad bool", func(m map[string]string) { m["POLICY_REGISTRY_FAIL_OPEN"] = "maybe" }, "invalid boolean"},
		{"bad url", func(m map[string]string) { m["POLICY_EMQX_API_URL"] = "emqx:18083" }, "invalid URL"},
		{"bad scheme", func(m map[string]string) { m["POLICY_REGISTRY_URL"] = "ftp://registry" }, "invalid URL"},
		{"bad level", func(m map[string]string) { m["POLICY_LOG_LEVEL"] = "loud" }, "unknown level"},
		{"bad oidc issuer", func(m map[string]string) { m["POLICY_OIDC_ISSUER"] = "idp.example/realms/x" }, "POLICY_OIDC_ISSUER"},
		{"bad replay cache size", func(m map[string]string) { m["POLICY_JWT_REPLAY_CACHE_SIZE"] = "lots" }, "invalid integer"},
		{"tiny replay cache", func(m map[string]string) { m["POLICY_JWT_REPLAY_CACHE_SIZE"] = "10" }, "at least 1000"},
		{"tls cert without key", func(m map[string]string) { m["POLICY_TLS_CERT_FILE"] = "/tls/tls.crt" }, "POLICY_TLS_KEY_FILE"},
		{"bad require serial", func(m map[string]string) { m["POLICY_REQUIRE_CERT_SERIAL"] = "sometimes" }, "invalid boolean"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := minimalEnv()
			tc.mutate(env)
			_, err := Load(MapGetenv(env))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error %q does not mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestLoadReportsAllErrorsAtOnce(t *testing.T) {
	_, err := Load(MapGetenv(map[string]string{}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"POLICY_EMQX_API_KEY", "POLICY_PKI_HMAC_SECRET", "POLICY_PKI_TOKEN", "POLICY_REGISTRY_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

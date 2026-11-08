// Package config loads the bridge configuration from the environment.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved bridge configuration.
type Config struct {
	// Listen is the HTTP address for /metrics, /healthz, /readyz and /emqx/events (default :8082).
	Listen string

	MQTTURL      *url.URL
	MQTTClientID string
	MQTTTopic    string

	TLSCertFile   string
	TLSKeyFile    string
	TLSCAFile     string
	TLSServerName string

	KafkaBrokers     []string
	KafkaIngestTopic string
	KafkaAuthTopic   string
	KafkaTLS         bool
	KafkaTLSCAFile   string

	MaxInflight   int
	EventsToken   string
	KeepAlive     time.Duration
	SessionExpiry time.Duration
	ConnectRetry  time.Duration

	LogLevel        string
	ShutdownTimeout time.Duration
	OTLPEndpoint    string
	ServiceName     string
}

// Load reads the configuration using getenv (os.Getenv in production).
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
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: invalid duration %q", key, raw))
			return 0
		}
		return d
	}
	integer := func(key string, def int) int {
		raw := get(key, "")
		if raw == "" {
			return def
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid integer %q", key, raw))
			return def
		}
		return n
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
		Listen:           get("BRIDGE_LISTEN", ":8082"),
		MQTTClientID:     get("BRIDGE_MQTT_CLIENT_ID", "svc-bridge"),
		MQTTTopic:        get("BRIDGE_MQTT_TOPIC", "$share/bridge/im/v1/#"),
		TLSCertFile:      get("BRIDGE_TLS_CERT_FILE", ""),
		TLSKeyFile:       get("BRIDGE_TLS_KEY_FILE", ""),
		TLSCAFile:        get("BRIDGE_TLS_CA_FILE", ""),
		TLSServerName:    get("BRIDGE_TLS_SERVER_NAME", ""),
		KafkaBrokers:     splitList(get("BRIDGE_KAFKA_BROKERS", "redpanda:9092")),
		KafkaIngestTopic: get("BRIDGE_KAFKA_INGEST_TOPIC", "im.ingest"),
		KafkaAuthTopic:   get("BRIDGE_KAFKA_AUTH_TOPIC", "im.auth"),
		KafkaTLS:         boolean("BRIDGE_KAFKA_TLS", false),
		KafkaTLSCAFile:   get("BRIDGE_KAFKA_TLS_CA_FILE", ""),
		MaxInflight:      integer("BRIDGE_MAX_INFLIGHT", 1024),
		EventsToken:      get("BRIDGE_EVENTS_TOKEN", ""),
		KeepAlive:        dur("BRIDGE_MQTT_KEEPALIVE", "60s"),
		SessionExpiry:    dur("BRIDGE_MQTT_SESSION_EXPIRY", "168h"),
		ConnectRetry:     dur("BRIDGE_MQTT_CONNECT_RETRY", "2s"),
		LogLevel:         get("BRIDGE_LOG_LEVEL", "info"),
		ShutdownTimeout:  dur("BRIDGE_SHUTDOWN_TIMEOUT", "15s"),
		OTLPEndpoint:     get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		ServiceName:      get("OTEL_SERVICE_NAME", "ironmesh-bridge"),
	}

	rawURL := get("BRIDGE_MQTT_URL", "ssl://emqx:8883")
	u, err := url.Parse(rawURL)
	switch {
	case err != nil || u.Host == "":
		errs = append(errs, fmt.Errorf("BRIDGE_MQTT_URL: invalid URL %q", rawURL))
	default:
		switch strings.ToLower(u.Scheme) {
		case "ssl", "tls", "mqtts", "mqtt", "tcp":
			cfg.MQTTURL = u
		default:
			errs = append(errs, fmt.Errorf("BRIDGE_MQTT_URL: unsupported scheme %q", u.Scheme))
		}
	}
	if cfg.MQTTURL != nil && cfg.MQTTUsesTLS() {
		for key, v := range map[string]string{"BRIDGE_TLS_CERT_FILE": cfg.TLSCertFile, "BRIDGE_TLS_KEY_FILE": cfg.TLSKeyFile, "BRIDGE_TLS_CA_FILE": cfg.TLSCAFile} {
			if v == "" {
				errs = append(errs, fmt.Errorf("%s is required for an mTLS broker URL", key))
			}
		}
	}
	if len(cfg.KafkaBrokers) == 0 {
		errs = append(errs, errors.New("BRIDGE_KAFKA_BROKERS must list at least one broker"))
	}
	if cfg.KafkaIngestTopic == "" || cfg.KafkaAuthTopic == "" {
		errs = append(errs, errors.New("Kafka topics must not be empty"))
	}
	if cfg.MaxInflight < 1 || cfg.MaxInflight > 65535 {
		errs = append(errs, fmt.Errorf("BRIDGE_MAX_INFLIGHT must be between 1 and 65535, got %d", cfg.MaxInflight))
	}
	if cfg.KeepAlive > 65535*time.Second {
		errs = append(errs, errors.New("BRIDGE_MQTT_KEEPALIVE must be at most 65535s"))
	}
	if cfg.KafkaTLS && cfg.KafkaTLSCAFile == "" {
		errs = append(errs, errors.New("BRIDGE_KAFKA_TLS_CA_FILE is required when BRIDGE_KAFKA_TLS=true"))
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("BRIDGE_LOG_LEVEL: unknown level %q", cfg.LogLevel))
	}
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

// MQTTUsesTLS reports whether the broker URL scheme requires TLS.
func (c Config) MQTTUsesTLS() bool {
	if c.MQTTURL == nil {
		return false
	}
	switch strings.ToLower(c.MQTTURL.Scheme) {
	case "ssl", "tls", "mqtts":
		return true
	}
	return false
}

// MQTTTLSConfig builds the mTLS configuration for the broker connection (TLS 1.3, ALPN mqtt,
// Services CA pinning through RootCAs). It returns nil for plaintext URLs.
func (c Config) MQTTTLSConfig() (*tls.Config, error) {
	if !c.MQTTUsesTLS() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	pool, err := loadPool(c.TLSCAFile)
	if err != nil {
		return nil, err
	}
	serverName := c.TLSServerName
	if serverName == "" {
		serverName = c.MQTTURL.Hostname()
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"mqtt"},
	}, nil
}

// KafkaTLSConfig builds the TLS configuration for the Kafka connection, or nil when disabled.
func (c Config) KafkaTLSConfig() (*tls.Config, error) {
	if !c.KafkaTLS {
		return nil, nil
	}
	pool, err := loadPool(c.KafkaTLSCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("CA bundle %s contains no certificates", path)
	}
	return pool, nil
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

// MapGetenv adapts a map to the getenv signature (tests and tooling).
func MapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

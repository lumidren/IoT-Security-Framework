package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestPKI(t *testing.T) (cert, key, ca string) {
	t.Helper()
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc-bridge", Organization: []string{"IronMesh"}, OrganizationalUnit: []string{"services"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	cert = filepath.Join(dir, "cert.pem")
	key = filepath.Join(dir, "key.pem")
	ca = filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return cert, key, ca
}

func tlsEnv(t *testing.T) map[string]string {
	cert, key, ca := writeTestPKI(t)
	return map[string]string{"BRIDGE_TLS_CERT_FILE": cert, "BRIDGE_TLS_KEY_FILE": key, "BRIDGE_TLS_CA_FILE": ca}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(MapGetenv(tlsEnv(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8082" || cfg.MQTTURL.String() != "ssl://emqx:8883" || cfg.MQTTClientID != "svc-bridge" || cfg.MQTTTopic != "$share/bridge/im/v1/#" {
		t.Errorf("defaults = %+v", cfg)
	}
	if len(cfg.KafkaBrokers) != 1 || cfg.KafkaBrokers[0] != "redpanda:9092" || cfg.KafkaIngestTopic != "im.ingest" || cfg.KafkaAuthTopic != "im.auth" {
		t.Errorf("kafka defaults = %+v", cfg)
	}
	if cfg.MaxInflight != 1024 || cfg.KeepAlive != 60*time.Second || cfg.SessionExpiry != 168*time.Hour || cfg.ConnectRetry != 2*time.Second || cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("timing defaults = %+v", cfg)
	}
	if cfg.LogLevel != "info" || cfg.ServiceName != "ironmesh-bridge" || cfg.KafkaTLS {
		t.Errorf("misc defaults = %+v", cfg)
	}
	if !cfg.MQTTUsesTLS() {
		t.Error("ssl scheme must use TLS")
	}
	tc, err := cfg.MQTTTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tc.MinVersion != tls.VersionTLS13 || len(tc.NextProtos) != 1 || tc.NextProtos[0] != "mqtt" || tc.ServerName != "emqx" || len(tc.Certificates) != 1 || tc.RootCAs == nil {
		t.Errorf("tls config = %+v", tc)
	}
	if kt, err := cfg.KafkaTLSConfig(); err != nil || kt != nil {
		t.Errorf("kafka tls disabled should yield nil: %v %v", kt, err)
	}
}

func TestLoadPlaintextAndOverrides(t *testing.T) {
	env := map[string]string{
		"BRIDGE_MQTT_URL":             "mqtt://localhost:1883",
		"BRIDGE_LISTEN":               "127.0.0.1:9090",
		"BRIDGE_KAFKA_BROKERS":        " a:9092, b:9092 ,",
		"BRIDGE_MAX_INFLIGHT":         "16",
		"BRIDGE_EVENTS_TOKEN":         "tok",
		"BRIDGE_TLS_SERVER_NAME":      "broker.example",
		"BRIDGE_LOG_LEVEL":            "DEBUG",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel:4317",
	}
	cfg, err := Load(MapGetenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MQTTUsesTLS() {
		t.Error("mqtt scheme is plaintext")
	}
	if tc, err := cfg.MQTTTLSConfig(); err != nil || tc != nil {
		t.Errorf("plaintext should yield nil tls config: %v %v", tc, err)
	}
	if len(cfg.KafkaBrokers) != 2 || cfg.KafkaBrokers[1] != "b:9092" || cfg.MaxInflight != 16 || cfg.EventsToken != "tok" || cfg.OTLPEndpoint != "http://otel:4317" {
		t.Errorf("overrides = %+v", cfg)
	}
}

func TestLoadValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"bad url", func(m map[string]string) { m["BRIDGE_MQTT_URL"] = "emqx:8883" }, "invalid URL"},
		{"bad scheme", func(m map[string]string) { m["BRIDGE_MQTT_URL"] = "ws://emqx" }, "unsupported scheme"},
		{"missing cert", func(m map[string]string) { delete(m, "BRIDGE_TLS_CERT_FILE") }, "BRIDGE_TLS_CERT_FILE"},
		{"no brokers", func(m map[string]string) { m["BRIDGE_KAFKA_BROKERS"] = " , " }, "at least one broker"},
		{"bad inflight", func(m map[string]string) { m["BRIDGE_MAX_INFLIGHT"] = "0" }, "BRIDGE_MAX_INFLIGHT"},
		{"huge inflight", func(m map[string]string) { m["BRIDGE_MAX_INFLIGHT"] = "70000" }, "BRIDGE_MAX_INFLIGHT"},
		{"non-numeric inflight", func(m map[string]string) { m["BRIDGE_MAX_INFLIGHT"] = "many" }, "invalid integer"},
		{"bad duration", func(m map[string]string) { m["BRIDGE_MQTT_KEEPALIVE"] = "soon" }, "invalid duration"},
		{"keepalive too long", func(m map[string]string) { m["BRIDGE_MQTT_KEEPALIVE"] = "20h" }, "at most 65535s"},
		{"bad bool", func(m map[string]string) { m["BRIDGE_KAFKA_TLS"] = "maybe" }, "invalid boolean"},
		{"bad tls enabled bool", func(m map[string]string) { m["BRIDGE_KAFKA_TLS_ENABLED"] = "si" }, "invalid boolean"},
		{"unknown sasl", func(m map[string]string) { m["BRIDGE_KAFKA_SASL_MECHANISM"] = "gssapi" }, "BRIDGE_KAFKA_SASL_MECHANISM"},
		{"scram without password", func(m map[string]string) {
			m["BRIDGE_KAFKA_SASL_MECHANISM"] = "scram-sha-512"
			m["BRIDGE_KAFKA_SASL_USERNAME"] = "bridge"
		}, "BRIDGE_KAFKA_SASL_PASSWORD"},
		{"plain without tls", func(m map[string]string) {
			m["BRIDGE_KAFKA_SASL_MECHANISM"] = "plain"
			m["BRIDGE_KAFKA_SASL_USERNAME"], m["BRIDGE_KAFKA_SASL_PASSWORD"] = "u", "p"
		}, "BRIDGE_KAFKA_TLS_ENABLED"},
		{"msk iam without tls", func(m map[string]string) { m["BRIDGE_KAFKA_SASL_MECHANISM"] = "aws-msk-iam" }, "BRIDGE_KAFKA_TLS_ENABLED"},
		{"zero partitions", func(m map[string]string) { m["BRIDGE_KAFKA_TOPIC_PARTITIONS"] = "0" }, "BRIDGE_KAFKA_TOPIC_PARTITIONS"},
		{"bad replication", func(m map[string]string) { m["BRIDGE_KAFKA_TOPIC_REPLICATION"] = "0" }, "BRIDGE_KAFKA_TOPIC_REPLICATION"},
		{"bad topics create", func(m map[string]string) { m["BRIDGE_KAFKA_TOPICS_CREATE"] = "sure" }, "invalid boolean"},
		{"bad level", func(m map[string]string) { m["BRIDGE_LOG_LEVEL"] = "loud" }, "unknown level"},
		{"session expiry beyond uint32", func(m map[string]string) { m["BRIDGE_MQTT_SESSION_EXPIRY"] = "1193047h" }, "BRIDGE_MQTT_SESSION_EXPIRY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tlsEnv(t)
			tc.mutate(env)
			_, err := Load(MapGetenv(env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestTLSConfigErrors(t *testing.T) {
	env := tlsEnv(t)
	cfg, err := Load(MapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSKeyFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := cfg.MQTTTLSConfig(); err == nil {
		t.Error("missing key should fail")
	}
	cfg, _ = Load(MapGetenv(env))
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	cfg.TLSCAFile = bad
	if _, err := cfg.MQTTTLSConfig(); err == nil {
		t.Error("CA bundle without certificates should fail")
	}
	cfg.TLSCAFile = filepath.Join(t.TempDir(), "none.pem")
	if _, err := cfg.MQTTTLSConfig(); err == nil {
		t.Error("missing CA should fail")
	}

	env["BRIDGE_KAFKA_TLS"] = "true"
	env["BRIDGE_KAFKA_TLS_CA_FILE"] = env["BRIDGE_TLS_CA_FILE"]
	cfg, err = Load(MapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	kt, err := cfg.KafkaTLSConfig()
	if err != nil || kt == nil || kt.RootCAs == nil {
		t.Errorf("kafka tls = %+v %v", kt, err)
	}
	cfg.KafkaTLSCAFile = bad
	if _, err := cfg.KafkaTLSConfig(); err == nil {
		t.Error("bad kafka CA should fail")
	}
}

func TestLoadKafkaSecurityAndTopics(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{"BRIDGE_MQTT_URL": "mqtt://localhost:1883"}
	}
	cfg, err := Load(MapGetenv(base()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KafkaSASLMechanism != "none" || cfg.KafkaTopicsCreate || cfg.KafkaTopicPartitions != 12 || cfg.KafkaTopicReplication != 3 || cfg.KafkaTLS {
		t.Errorf("defaults = %+v", cfg)
	}
	if got := cfg.KafkaTopics(); strings.Join(got, ",") != "im.ingest,im.auth,im.alerts,im.audit,im.commands,im.campaigns" {
		t.Errorf("topics = %v", got)
	}

	env := base()
	env["BRIDGE_KAFKA_TLS_ENABLED"] = "true"
	env["BRIDGE_KAFKA_SASL_MECHANISM"] = "AWS-MSK-IAM"
	env["BRIDGE_KAFKA_TOPICS_CREATE"] = "true"
	env["BRIDGE_KAFKA_TOPIC_PARTITIONS"] = "24"
	env["BRIDGE_KAFKA_TOPIC_REPLICATION"] = "-1"
	env["BRIDGE_KAFKA_INGEST_TOPIC"] = "im.ingest.v2"
	env["BRIDGE_KAFKA_AUTH_TOPIC"] = "im.alerts"
	cfg, err = Load(MapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.KafkaTLS || cfg.KafkaSASLMechanism != "aws-msk-iam" || !cfg.KafkaTopicsCreate || cfg.KafkaTopicPartitions != 24 || cfg.KafkaTopicReplication != -1 {
		t.Errorf("overrides = %+v", cfg)
	}
	if got := cfg.KafkaTopics(); strings.Join(got, ",") != "im.ingest.v2,im.alerts,im.audit,im.commands,im.campaigns" {
		t.Errorf("topics = %v", got)
	}
	// TLS without a CA bundle uses the system roots.
	kt, err := cfg.KafkaTLSConfig()
	if err != nil || kt == nil || kt.RootCAs != nil || kt.MinVersion != tls.VersionTLS12 {
		t.Errorf("system-roots TLS = %+v %v", kt, err)
	}

	env = base()
	env["BRIDGE_KAFKA_SASL_MECHANISM"] = "scram-sha-512"
	env["BRIDGE_KAFKA_SASL_USERNAME"], env["BRIDGE_KAFKA_SASL_PASSWORD"] = "bridge", "s3cret"
	if cfg, err = Load(MapGetenv(env)); err != nil || cfg.KafkaSASLUsername != "bridge" || cfg.KafkaSASLPassword != "s3cret" {
		t.Errorf("scram = %+v %v", cfg, err)
	}
	env["BRIDGE_KAFKA_SASL_MECHANISM"] = "plain"
	env["BRIDGE_KAFKA_TLS"] = "true"
	if _, err = Load(MapGetenv(env)); err != nil {
		t.Errorf("plain over TLS: %v", err)
	}
}

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/bridge"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/config"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestHealthcheckMain(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	env := map[string]string{"BRIDGE_LISTEN": strings.TrimPrefix(srv.URL, "http://")}
	var out, errOut bytes.Buffer
	if code := healthcheckMain(nil, config.MapGetenv(env), &out, &errOut); code != 0 {
		t.Fatalf("healthy: %d %s", code, errOut.String())
	}
	status = http.StatusInternalServerError
	if code := healthcheckMain(nil, config.MapGetenv(env), &out, &errOut); code != 1 {
		t.Fatalf("unhealthy: %d", code)
	}
	status = http.StatusOK
	if code := healthcheckMain([]string{"--url", srv.URL + "/healthz"}, config.MapGetenv(nil), &out, &errOut); code != 0 {
		t.Fatalf("--url: %d", code)
	}
}

func TestKafkaConfigAndTopics(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(3), kfake.EnableSASL(), kfake.Superuser("SCRAM-SHA-512", "bridge", "pw"))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	cfg, err := config.Load(config.MapGetenv(map[string]string{
		"BRIDGE_MQTT_URL":                "mqtt://localhost:1883",
		"BRIDGE_KAFKA_BROKERS":           strings.Join(cluster.ListenAddrs(), ","),
		"BRIDGE_KAFKA_SASL_MECHANISM":    "scram-sha-512",
		"BRIDGE_KAFKA_SASL_USERNAME":     "bridge",
		"BRIDGE_KAFKA_SASL_PASSWORD":     "pw",
		"BRIDGE_KAFKA_TOPICS_CREATE":     "true",
		"BRIDGE_KAFKA_TOPIC_PARTITIONS":  "6",
		"BRIDGE_KAFKA_TOPIC_REPLICATION": "3",
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	kcfg, err := kafkaConfig(ctx, cfg, discard())
	if err != nil || kcfg.SASL == nil || kcfg.TLS != nil {
		t.Fatalf("kafkaConfig: %+v %v", kcfg, err)
	}
	p, err := bridge.NewKafkaProducer(kcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := ensureTopics(ctx, cfg, p, discard()); err != nil {
		t.Fatalf("ensureTopics: %v", err)
	}
	if err := ensureTopics(ctx, cfg, p, discard()); err != nil {
		t.Fatalf("ensureTopics is not idempotent: %v", err)
	}
	// Existing topics are success even when the requested settings differ.
	cfg.KafkaTopicReplication = 9
	if err := ensureTopics(ctx, cfg, p, discard()); err != nil {
		t.Fatalf("existing topics must not fail: %v", err)
	}
	cfg.KafkaIngestTopic = "im.ingest.new"
	if err := ensureTopics(ctx, cfg, p, discard()); err == nil {
		t.Fatal("impossible replication factor accepted")
	}
	cfg.KafkaTopicsCreate = false
	if err := ensureTopics(ctx, cfg, nil, discard()); err != nil {
		t.Fatal(err)
	}

	cfg.KafkaSASLMechanism = "gssapi"
	if _, err := kafkaConfig(ctx, cfg, discard()); err == nil {
		t.Fatal("unknown mechanism accepted")
	}
	cfg.KafkaSASLMechanism = "none"
	cfg.KafkaTLS, cfg.KafkaTLSCAFile = true, "/nonexistent/ca.pem"
	if _, err := kafkaConfig(ctx, cfg, discard()); err == nil {
		t.Fatal("missing CA file accepted")
	}
}

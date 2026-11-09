// Command bridge subscribes to EMQX as svc-bridge ($share/bridge/im/v1/#) and forwards device
// messages to Redpanda (im.ingest) and EMQX auth events (webhook) to im.auth.
//
// "bridge healthcheck [--url URL] [--timeout D]" GETs /healthz (default derived from
// BRIDGE_LISTEN) and exits 0 or 1, for container health checks in the distroless image.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/bridge"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/healthcheck"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/server"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/telemetry"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheckMain(os.Args[2:], os.Getenv, os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge:", err)
		os.Exit(1)
	}
}

// healthcheckMain implements "bridge healthcheck".
func healthcheckMain(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	listen := strings.TrimSpace(getenv("BRIDGE_LISTEN"))
	if listen == "" {
		listen = ":8082"
	}
	return healthcheck.Run(context.Background(), "bridge", args, healthcheck.DefaultURL(listen, "/healthz"), stdout, stderr)
}

// kafkaConfig builds the producer configuration: TLS (BRIDGE_KAFKA_TLS[_ENABLED]) and SASL
// (BRIDGE_KAFKA_SASL_MECHANISM).
func kafkaConfig(ctx context.Context, cfg config.Config, log *slog.Logger) (bridge.KafkaConfig, error) {
	kafkaTLS, err := cfg.KafkaTLSConfig()
	if err != nil {
		return bridge.KafkaConfig{}, err
	}
	mech, err := bridge.NewSASLMechanism(ctx, cfg.KafkaSASLMechanism, cfg.KafkaSASLUsername, cfg.KafkaSASLPassword, nil)
	if err != nil {
		return bridge.KafkaConfig{}, err
	}
	return bridge.KafkaConfig{Brokers: cfg.KafkaBrokers, ClientID: cfg.MQTTClientID, TLS: kafkaTLS, SASL: mech, Logger: log}, nil
}

// ensureTopics creates the platform topics when BRIDGE_KAFKA_TOPICS_CREATE=true.
func ensureTopics(ctx context.Context, cfg config.Config, producer *bridge.KafkaProducer, log *slog.Logger) error {
	if !cfg.KafkaTopicsCreate {
		return nil
	}
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	topics := cfg.KafkaTopics()
	created, err := producer.EnsureTopics(tctx, int32(cfg.KafkaTopicPartitions), int16(cfg.KafkaTopicReplication), topics...)
	if err != nil {
		return err
	}
	log.Info("kafka topics ensured", "topics", topics, "created", created, "partitions", cfg.KafkaTopicPartitions, "replication", cfg.KafkaTopicReplication)
	return nil
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log := logging.New(os.Stdout, "bridge", cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := telemetry.Setup(ctx, cfg.ServiceName, cfg.OTLPEndpoint, log)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := bridge.NewMetrics(reg)

	kcfg, err := kafkaConfig(ctx, cfg, log)
	if err != nil {
		return err
	}
	producer, err := bridge.NewKafkaProducer(kcfg)
	if err != nil {
		return err
	}
	defer producer.Close()
	if err := ensureTopics(ctx, cfg, producer, log); err != nil {
		return err
	}

	forwarder, err := bridge.NewForwarder(bridge.ForwarderConfig{Producer: producer, IngestTopic: cfg.KafkaIngestTopic, Metrics: m, Logger: log})
	if err != nil {
		return err
	}
	mqttTLS, err := cfg.MQTTTLSConfig()
	if err != nil {
		return err
	}
	if mqttTLS == nil {
		log.Warn("broker URL is plaintext; mTLS is mandatory outside local development", "url", cfg.MQTTURL.String())
	}
	source, err := bridge.NewMQTTSource(bridge.MQTTConfig{
		ServerURL:         cfg.MQTTURL,
		ClientID:          cfg.MQTTClientID,
		TopicFilter:       cfg.MQTTTopic,
		TLS:               mqttTLS,
		KeepAlive:         uint16(cfg.KeepAlive / time.Second),
		SessionExpiry:     uint32(cfg.SessionExpiry / time.Second),
		ReceiveMaximum:    uint16(cfg.MaxInflight),
		ConnectRetryDelay: cfg.ConnectRetry,
		Logger:            log,
		Metrics:           m,
	})
	if err != nil {
		return err
	}
	consumer, err := bridge.NewConsumer(bridge.ConsumerConfig{Source: source, Forwarder: forwarder, MaxInflight: cfg.MaxInflight, Metrics: m, Logger: log})
	if err != nil {
		return err
	}
	events, err := bridge.NewEventsHandler(bridge.EventsConfig{Producer: producer, Topic: cfg.KafkaAuthTopic, Token: cfg.EventsToken, Metrics: m, Logger: log})
	if err != nil {
		return err
	}
	if cfg.EventsToken == "" {
		log.Warn("BRIDGE_EVENTS_TOKEN is empty: /emqx/events accepts unauthenticated posts")
	}
	if cfg.KafkaSASLMechanism == bridge.SASLNone && !cfg.KafkaTLS {
		log.Warn("Kafka connection is plaintext and unauthenticated; set BRIDGE_KAFKA_TLS_ENABLED and BRIDGE_KAFKA_SASL_MECHANISM outside local development")
	}

	handler := server.NewHandler(server.Config{
		Metrics: promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		Events:  events,
		Ready: func() error {
			if !source.Connected() {
				return errors.New("mqtt session not established")
			}
			pctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := producer.Ping(pctx); err != nil {
				return fmt.Errorf("kafka unreachable: %w", err)
			}
			return nil
		},
		Logger: log,
	})

	log.Info("bridge starting", "listen", cfg.Listen, "mqtt", cfg.MQTTURL.String(), "filter", cfg.MQTTTopic,
		"kafka", cfg.KafkaBrokers, "ingest_topic", cfg.KafkaIngestTopic, "auth_topic", cfg.KafkaAuthTopic, "max_inflight", cfg.MaxInflight)

	consumerDone := make(chan error, 1)
	go func() { consumerDone <- consumer.Run(ctx) }()
	serverErr := server.Run(ctx, cfg.Listen, handler, cfg.ShutdownTimeout, log)
	stop()

	select {
	case err := <-consumerDone:
		if err != nil {
			log.Error("consumer stopped with error", "err", err.Error())
		}
	case <-time.After(cfg.ShutdownTimeout):
		log.Warn("consumer did not drain in time; unacknowledged messages will be redelivered")
	}
	tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdownTracing(tctx); err != nil {
		log.Warn("tracing shutdown", "err", err.Error())
	}
	if serverErr != nil {
		return serverErr
	}
	log.Info("bridge stopped")
	return nil
}

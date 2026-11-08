// Command bridge subscribes to EMQX as svc-bridge ($share/bridge/im/v1/#) and forwards device
// messages to Redpanda (im.ingest) and EMQX auth events (webhook) to im.auth.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/bridge"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/server"
	"github.com/lumidren/IoT-Security-Framework/services/bridge/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge:", err)
		os.Exit(1)
	}
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

	kafkaTLS, err := cfg.KafkaTLSConfig()
	if err != nil {
		return err
	}
	producer, err := bridge.NewKafkaProducer(bridge.KafkaConfig{Brokers: cfg.KafkaBrokers, ClientID: cfg.MQTTClientID, TLS: kafkaTLS, Logger: log})
	if err != nil {
		return err
	}
	defer producer.Close()

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

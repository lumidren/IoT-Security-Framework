package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
)

// Header is a Kafka record header.
type Header struct {
	Key   string
	Value string
}

// Record is a message destined for Kafka.
type Record struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers []Header
	// Timestamp is informational (fakes, logs); the Kafka record carries the produce time.
	Timestamp time.Time
}

// Producer publishes records. Produce returns only after the broker acknowledged the record (or
// the attempt failed), which is what at-least-once delivery relies on.
type Producer interface {
	Produce(ctx context.Context, rec Record) error
}

// KafkaConfig configures the franz-go producer.
type KafkaConfig struct {
	Brokers  []string
	ClientID string
	TLS      *tls.Config
	// SASL authenticates every broker connection (NewSASLMechanism); nil disables SASL.
	SASL   sasl.Mechanism
	Logger *slog.Logger
	// DeliveryTimeout bounds retries of one record (default 30s).
	DeliveryTimeout time.Duration
	// Linger batches records for up to this long (default 5ms).
	Linger time.Duration
}

// KafkaProducer is the Redpanda/Kafka Producer (idempotent, acks=all).
type KafkaProducer struct {
	cl *kgo.Client
}

// NewKafkaProducer creates the client. Connections are established lazily.
func NewKafkaProducer(cfg KafkaConfig) (*KafkaProducer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka: at least one broker is required")
	}
	if cfg.DeliveryTimeout <= 0 {
		cfg.DeliveryTimeout = 30 * time.Second
	}
	if cfg.Linger < 0 {
		cfg.Linger = 0
	} else if cfg.Linger == 0 {
		cfg.Linger = 5 * time.Millisecond
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "ironmesh-bridge"
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerLinger(cfg.Linger),
		kgo.RecordDeliveryTimeout(cfg.DeliveryTimeout),
		kgo.ProduceRequestTimeout(10 * time.Second),
	}
	if cfg.TLS != nil {
		opts = append(opts, kgo.DialTLSConfig(cfg.TLS))
	}
	if cfg.SASL != nil {
		opts = append(opts, kgo.SASL(cfg.SASL))
	}
	if cfg.Logger != nil {
		opts = append(opts, kgo.WithLogger(&slogKgoLogger{log: cfg.Logger}))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("kafka: create client: %w", err)
	}
	return &KafkaProducer{cl: cl}, nil
}

// Produce implements Producer.
func (p *KafkaProducer) Produce(ctx context.Context, rec Record) error {
	// The record timestamp is left to the client (produce time): franz-go measures the delivery
	// timeout from it, so an old receipt time (e.g. a redelivery after an outage) would fail the
	// record immediately. The MQTT receipt time travels in the received_at header instead.
	kr := &kgo.Record{Topic: rec.Topic, Key: rec.Key, Value: rec.Value}
	for _, h := range rec.Headers {
		kr.Headers = append(kr.Headers, kgo.RecordHeader{Key: h.Key, Value: []byte(h.Value)})
	}
	if err := p.cl.ProduceSync(ctx, kr).FirstErr(); err != nil {
		return fmt.Errorf("kafka: produce to %s: %w", rec.Topic, err)
	}
	return nil
}

// Ping checks broker connectivity.
func (p *KafkaProducer) Ping(ctx context.Context) error { return p.cl.Ping(ctx) }

// Close flushes buffered records and closes the client.
func (p *KafkaProducer) Close() { p.cl.Close() }

type slogKgoLogger struct {
	log *slog.Logger
}

func (l *slogKgoLogger) Level() kgo.LogLevel { return kgo.LogLevelInfo }

func (l *slogKgoLogger) Log(level kgo.LogLevel, msg string, keyvals ...any) {
	attrs := append([]any{"component", "kafka"}, keyvals...)
	switch level {
	case kgo.LogLevelError:
		l.log.Error(msg, attrs...)
	case kgo.LogLevelWarn:
		l.log.Warn(msg, attrs...)
	case kgo.LogLevelInfo:
		l.log.Info(msg, attrs...)
	default:
		l.log.Debug(msg, attrs...)
	}
}

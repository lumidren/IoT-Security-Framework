package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ErrDrop marks a message that must be acknowledged without forwarding (it can never succeed).
var ErrDrop = errors.New("bridge: message dropped")

// Kafka header names (API_CONTRACT.md section 6).
const (
	HeaderMQTTTopic  = "mqtt_topic"
	HeaderTenantID   = "tenant_id"
	HeaderDeviceID   = "device_id"
	HeaderMsgClass   = "msg_class"
	HeaderReceivedAt = "received_at"
	// HeaderTraceParent is set from the MQTT 5 user property of the same name via W3C propagation.
	HeaderTraceParent = "traceparent"
)

// ForwarderConfig configures a Forwarder.
type ForwarderConfig struct {
	Producer    Producer
	IngestTopic string
	Metrics     *Metrics
	Logger      *slog.Logger
	// TracerProvider defaults to the global provider; Propagator to W3C TraceContext + Baggage.
	TracerProvider trace.TracerProvider
	Propagator     propagation.TextMapPropagator
	Clock          func() time.Time
}

// Forwarder turns one MQTT message into one Kafka record on im.ingest.
type Forwarder struct {
	producer   Producer
	topic      string
	metrics    *Metrics
	log        *slog.Logger
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
	now        func() time.Time
}

// NewForwarder validates cfg and returns a Forwarder.
func NewForwarder(cfg ForwarderConfig) (*Forwarder, error) {
	if cfg.Producer == nil || cfg.Metrics == nil {
		return nil, errors.New("forwarder: producer and metrics are required")
	}
	if cfg.IngestTopic == "" {
		cfg.IngestTopic = "im.ingest"
	}
	f := &Forwarder{producer: cfg.Producer, topic: cfg.IngestTopic, metrics: cfg.Metrics, log: cfg.Logger, propagator: cfg.Propagator, now: cfg.Clock}
	if f.log == nil {
		f.log = slog.Default()
	}
	tp := cfg.TracerProvider
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	f.tracer = tp.Tracer("github.com/lumidren/IoT-Security-Framework/services/bridge")
	if f.propagator == nil {
		f.propagator = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	}
	if f.now == nil {
		f.now = time.Now
	}
	return f, nil
}

// Forward produces msg to the ingest topic. It returns ErrDrop (wrapped) for messages that can
// never be forwarded, nil on success, and any other error when the produce attempt failed.
func (f *Forwarder) Forward(ctx context.Context, msg *Message) error {
	topic, err := ParseTopic(msg.Topic)
	if err != nil {
		f.metrics.Dropped.WithLabelValues("invalid_topic").Inc()
		return fmt.Errorf("%w: %w", ErrDrop, err)
	}
	if !topic.Ingest() {
		f.metrics.Dropped.WithLabelValues("downlink").Inc()
		return fmt.Errorf("%w: %s is cloud-originated", ErrDrop, topic.Class)
	}

	ctx = f.propagator.Extract(ctx, propagation.MapCarrier(msg.UserProperties))
	ctx, span := f.tracer.Start(ctx, "bridge.forward",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "mqtt"),
			attribute.String("messaging.destination.name", msg.Topic),
			attribute.String("messaging.kafka.destination", f.topic),
			attribute.String("ironmesh.tenant_id", topic.Tenant),
			attribute.String("ironmesh.device_id", topic.Device),
			attribute.String("ironmesh.msg_class", string(topic.Class)),
		))
	defer span.End()

	receivedAt := msg.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = f.now()
	}
	rec := Record{
		Topic:     f.topic,
		Key:       []byte(topic.Key()),
		Value:     msg.Payload,
		Timestamp: receivedAt,
		Headers: []Header{
			{Key: HeaderMQTTTopic, Value: msg.Topic},
			{Key: HeaderTenantID, Value: topic.Tenant},
			{Key: HeaderDeviceID, Value: topic.Device},
			{Key: HeaderMsgClass, Value: string(topic.Class)},
			{Key: HeaderReceivedAt, Value: receivedAt.UTC().Format(time.RFC3339Nano)},
		},
	}
	carrier := propagation.MapCarrier{}
	f.propagator.Inject(ctx, carrier)
	keys := carrier.Keys()
	sort.Strings(keys)
	for _, k := range keys {
		rec.Headers = append(rec.Headers, Header{Key: k, Value: carrier.Get(k)})
	}

	if err := f.producer.Produce(ctx, rec); err != nil {
		f.metrics.ForwardErrors.Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, "produce failed")
		return fmt.Errorf("bridge: forward %s: %w", msg.Topic, err)
	}
	f.metrics.Messages.WithLabelValues(string(topic.Class)).Inc()
	f.metrics.ForwardLatency.Observe(f.now().Sub(receivedAt).Seconds())
	span.SetStatus(codes.Ok, "")
	return nil
}

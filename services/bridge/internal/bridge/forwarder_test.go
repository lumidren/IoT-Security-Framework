package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func TestNewForwarderValidation(t *testing.T) {
	m := newMetrics()
	if _, err := NewForwarder(ForwarderConfig{Metrics: m}); err == nil {
		t.Error("missing producer should fail")
	}
	if _, err := NewForwarder(ForwarderConfig{Producer: &fakeProducer{}}); err == nil {
		t.Error("missing metrics should fail")
	}
	f, err := NewForwarder(ForwarderConfig{Producer: &fakeProducer{}, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	if f.topic != "im.ingest" || f.log == nil || f.propagator == nil || f.tracer == nil || f.now == nil {
		t.Errorf("defaults not applied: %+v", f)
	}
}

func TestForwardBuildsContractRecord(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{}
	f := newForwarder(t, p, m)
	topic := "im/v1/" + tenant + "/" + dev + "/shadow/reported"
	msg := NewMessage(topic, []byte{0xd2, 0x84}, 1, false, map[string]string{"traceparent": traceparent, "x-other": "ignored"}, fixedNow, nil)
	if err := f.Forward(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	recs := p.Records()
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	rec := recs[0]
	if rec.Topic != "im.ingest" || string(rec.Key) != tenant+"/"+dev || string(rec.Value) != "\xd2\x84" || !rec.Timestamp.Equal(fixedNow) {
		t.Errorf("record = %+v", rec)
	}
	want := map[string]string{
		HeaderMQTTTopic:   topic,
		HeaderTenantID:    tenant,
		HeaderDeviceID:    dev,
		HeaderMsgClass:    "shadow_reported",
		HeaderReceivedAt:  fixedNow.UTC().Format(time.RFC3339Nano),
		HeaderTraceParent: traceparent,
	}
	for k, v := range want {
		if got, ok := headerValue(rec, k); !ok || got != v {
			t.Errorf("header %s = %q (%v), want %q", k, got, ok, v)
		}
	}
	if _, ok := headerValue(rec, "x-other"); ok {
		t.Error("unrelated user properties must not leak into Kafka headers")
	}
	if got := testutil.ToFloat64(m.Messages.WithLabelValues("shadow_reported")); got != 1 {
		t.Errorf("messages = %v", got)
	}
}

func TestForwardWithoutTraceparentHasNoTraceHeader(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{}
	f := newForwarder(t, p, m)
	msg := NewMessage("im/v1/"+tenant+"/"+dev+"/telemetry", []byte("x"), 1, false, nil, time.Time{}, nil)
	if err := f.Forward(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	rec := p.Records()[0]
	if _, ok := headerValue(rec, HeaderTraceParent); ok {
		t.Error("no traceparent should be emitted when none arrived and no SDK is installed")
	}
	if got, _ := headerValue(rec, HeaderReceivedAt); got != fixedNow.UTC().Format(time.RFC3339Nano) {
		t.Errorf("received_at should fall back to the clock, got %q", got)
	}
}

func TestForwardPropagatesTraceContextThroughSDK(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	m := newMetrics()
	p := &fakeProducer{}
	f, err := NewForwarder(ForwarderConfig{Producer: p, Metrics: m, Logger: discardLogger(), TracerProvider: tp, Propagator: propagation.TraceContext{}})
	if err != nil {
		t.Fatal(err)
	}
	msg := NewMessage("im/v1/"+tenant+"/"+dev+"/telemetry", []byte("x"), 1, false, map[string]string{"traceparent": traceparent}, fixedNow, nil)
	if err := f.Forward(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "bridge.forward" || spans[0].SpanKind != trace.SpanKindConsumer {
		t.Fatalf("spans = %+v", spans)
	}
	span := spans[0]
	if span.SpanContext.TraceID().String() != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("span trace id = %s, want the device's trace", span.SpanContext.TraceID())
	}
	if span.Parent.SpanID().String() != "b7ad6b7169203331" {
		t.Errorf("parent span = %s", span.Parent.SpanID())
	}
	got, _ := headerValue(p.Records()[0], HeaderTraceParent)
	if !strings.HasPrefix(got, "00-0af7651916cd43dd8448eb211c80319c-"+span.SpanContext.SpanID().String()) {
		t.Errorf("kafka traceparent = %q should carry the bridge span under the device trace", got)
	}

	// Without an inbound traceparent the SDK starts a new root trace and still propagates it.
	exporter.Reset()
	if err := f.Forward(context.Background(), NewMessage("im/v1/"+tenant+"/"+dev+"/telemetry", []byte("x"), 1, false, nil, fixedNow, nil)); err != nil {
		t.Fatal(err)
	}
	if v, ok := headerValue(p.Records()[1], HeaderTraceParent); !ok || !strings.HasPrefix(v, "00-") {
		t.Errorf("root trace should be injected: %q %v", v, ok)
	}
}

func TestForwardErrorsAndDrops(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{err: errors.New("broker unavailable")}
	f := newForwarder(t, p, m)
	err := f.Forward(context.Background(), testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", nil, nil))
	if err == nil || errors.Is(err, ErrDrop) {
		t.Fatalf("produce failure should be a retryable error, got %v", err)
	}
	if got := testutil.ToFloat64(m.ForwardErrors); got != 1 {
		t.Errorf("forward errors = %v", got)
	}
	err = f.Forward(context.Background(), testMessage("not/a/topic", nil, nil))
	if !errors.Is(err, ErrDrop) || !errors.Is(err, ErrInvalidTopic) {
		t.Errorf("invalid topic err = %v", err)
	}
	err = f.Forward(context.Background(), testMessage("im/v1/"+tenant+"/"+dev+"/config", nil, nil))
	if !errors.Is(err, ErrDrop) {
		t.Errorf("downlink err = %v", err)
	}
	if p.Calls() != 1 {
		t.Errorf("dropped messages must not be produced; calls = %d", p.Calls())
	}
}

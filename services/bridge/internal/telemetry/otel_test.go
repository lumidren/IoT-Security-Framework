package telemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

func TestSetupWithoutEndpoint(t *testing.T) {
	shutdown, err := Setup(context.Background(), "ironmesh-bridge", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown returned %v", err)
	}
	fields := otel.GetTextMapPropagator().Fields()
	found := false
	for _, f := range fields {
		if f == "traceparent" {
			found = true
		}
	}
	if !found {
		t.Errorf("propagator fields = %v, want traceparent", fields)
	}
}

func TestSetupWithEndpointInstallsProvider(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	shutdown, err := Setup(context.Background(), "ironmesh-bridge", "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, span := otel.Tracer("test").Start(context.Background(), "probe")
	if !span.SpanContext().IsValid() {
		t.Error("SDK tracer provider should produce valid span contexts")
	}
	span.End()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = shutdown(ctx) // the collector is unreachable; the flush error (if any) is acceptable here
}

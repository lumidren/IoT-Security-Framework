// Package telemetry configures OpenTelemetry tracing for the bridge: W3C trace-context
// propagation (MQTT 5 user property traceparent -> Kafka header traceparent) and an OTLP/gRPC
// exporter when OTEL_EXPORTER_OTLP_ENDPOINT is set.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Setup installs the global propagator and, when endpoint is non-empty, a tracer provider that
// exports to the OTLP/gRPC collector configured through the standard OTEL_EXPORTER_OTLP_*
// environment variables. The returned function flushes and shuts the provider down.
func Setup(ctx context.Context, serviceName, endpoint string, log *slog.Logger) (func(context.Context) error, error) {
	if log == nil {
		log = slog.Default()
	}
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if endpoint == "" {
		log.Info("tracing export disabled (OTEL_EXPORTER_OTLP_ENDPOINT not set); trace context is still propagated")
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", serviceName),
		attribute.String("service.namespace", "ironmesh"),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	log.Info("tracing export enabled", "endpoint", endpoint, "service", serviceName)
	return tp.Shutdown, nil
}

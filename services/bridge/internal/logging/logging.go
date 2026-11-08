// Package logging builds the JSON slog logger mandated by DESIGN_CONTRACT.md section 9
// (fields ts, level, service, trace_id, span_id, tenant_id, device_id, msg).
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// New returns a JSON logger writing to w with the contract field names. Records logged with a
// context carrying an OpenTelemetry span gain trace_id and span_id.
func New(w io.Writer, service, level string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: ParseLevel(level),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Key = "ts"
			}
			if len(groups) == 0 && a.Key == slog.LevelKey {
				if lvl, ok := a.Value.Any().(slog.Level); ok {
					a.Value = slog.StringValue(strings.ToLower(lvl.String()))
				}
			}
			return a
		},
	})
	return slog.New(&traceHandler{Handler: h}).With("service", service)
}

// ParseLevel converts a textual level into a slog.Level, defaulting to info.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type traceHandler struct {
	slog.Handler
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{Handler: h.Handler.WithGroup(name)}
}

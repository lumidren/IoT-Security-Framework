// Package logging configures structured JSON logging with the field names
// required by DESIGN_CONTRACT §9 (ts, level, service, trace_id, span_id,
// tenant_id, device_id, msg) and propagates W3C traceparent ids from HTTP
// requests into request-scoped loggers.
package logging

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ServiceName is the value of the "service" field.
const ServiceName = "pki"

type ctxKey struct{}

// New returns a JSON logger writing to w at the given level.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				a.Key = "ts"
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.UTC().Format(time.RFC3339Nano))
				}
			case slog.LevelKey:
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			}
			return a
		},
	})
	return slog.New(h).With("service", ServiceName)
}

// ParseLevel parses debug/info/warn/error (case-insensitive).
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, true
	case "debug":
		return slog.LevelDebug, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return slog.LevelInfo, false
}

// WithLogger stores a logger in the context.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the request-scoped logger or slog.Default().
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// ParseTraceparent extracts trace and span ids from a W3C traceparent header
// (version-traceid-spanid-flags). It returns false for malformed values.
func ParseTraceparent(h string) (traceID, spanID string, ok bool) {
	parts := strings.Split(strings.TrimSpace(h), "-")
	if len(parts) < 4 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[0]) != 2 {
		return "", "", false
	}
	for _, p := range parts[:3] {
		if !isHex(p) {
			return "", "", false
		}
	}
	if strings.Trim(parts[1], "0") == "" || strings.Trim(parts[2], "0") == "" {
		return "", "", false
	}
	return strings.ToLower(parts[1]), strings.ToLower(parts[2]), true
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Middleware attaches a request-scoped logger (with trace_id/span_id when a
// traceparent header is present) to the context and logs each request.
func Middleware(base *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := base
		if tid, sid, ok := ParseTraceparent(r.Header.Get("traceparent")); ok {
			l = l.With("trace_id", tid, "span_id", sid)
		}
		rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rw, r.WithContext(WithLogger(r.Context(), l)))
		l.Debug("http request", "method", r.Method, "path", r.URL.Path, "status", rw.status, "duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap allows http.ResponseController to reach the underlying writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

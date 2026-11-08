// Package logging builds the JSON slog logger mandated by DESIGN_CONTRACT.md section 9
// (fields ts, level, service, trace_id, span_id, tenant_id, device_id, msg).
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// New returns a JSON logger writing to w with the contract field names. level is one of
// debug, info, warn, error (case-insensitive); anything else falls back to info.
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
	return slog.New(h).With("service", service)
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

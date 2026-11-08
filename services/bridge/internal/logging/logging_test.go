package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestNewWritesContractFields(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "bridge", "debug")
	log.With("component", "x").WithGroup("g").Info("hello", "tenant_id", "t1", "device_id", "dev-0123456789abcdef")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v: %q", err, buf.String())
	}
	for _, k := range []string{"ts", "level", "service", "msg", "component", "g"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("missing field %q in %v", k, rec)
		}
	}
	if rec["level"] != "info" || rec["service"] != "bridge" {
		t.Errorf("record = %v", rec)
	}
	if _, ok := rec["time"]; ok {
		t.Error("time key should have been renamed to ts")
	}
}

func TestTraceFieldsFromContext(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "bridge", "info")
	tid, _ := trace.TraceIDFromHex("0af7651916cd43dd8448eb211c80319c")
	sid, _ := trace.SpanIDFromHex("b7ad6b7169203331")
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	log.InfoContext(ctx, "traced")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["trace_id"] != "0af7651916cd43dd8448eb211c80319c" || rec["span_id"] != "b7ad6b7169203331" {
		t.Errorf("trace fields = %v", rec)
	}
	buf.Reset()
	log.Info("untraced")
	rec = map[string]any{}
	_ = json.Unmarshal(buf.Bytes(), &rec)
	if _, ok := rec["trace_id"]; ok {
		t.Error("trace_id must be absent without a span")
	}
}

func TestLevelFilteringAndParse(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "bridge", "warn")
	log.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info should be filtered: %q", buf.String())
	}
	log.Warn("kept")
	if buf.Len() == 0 {
		t.Fatal("warn should be logged")
	}
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "warning": slog.LevelWarn, "ERROR": slog.LevelError, "": slog.LevelInfo, "x": slog.LevelInfo} {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

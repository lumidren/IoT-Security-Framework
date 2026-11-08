package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNewWritesContractFields(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "policy", "debug")
	log.Info("hello", "tenant_id", "t1", "device_id", "dev-0123456789abcdef")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v: %q", err, buf.String())
	}
	for _, k := range []string{"ts", "level", "service", "msg", "tenant_id", "device_id"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("missing field %q in %v", k, rec)
		}
	}
	if rec["level"] != "info" {
		t.Errorf("level = %v, want info", rec["level"])
	}
	if rec["service"] != "policy" {
		t.Errorf("service = %v, want policy", rec["service"])
	}
	if _, ok := rec["time"]; ok {
		t.Errorf("time key should have been renamed to ts")
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "policy", "warn")
	log.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info should be filtered at warn level, got %q", buf.String())
	}
	log.Warn("kept")
	if buf.Len() == 0 {
		t.Fatalf("warn should be logged at warn level")
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn,
		"warning": slog.LevelWarn, "error": slog.LevelError, "": slog.LevelInfo, "bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewJSONFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := New(&buf, slog.LevelDebug)
	l.Warn("hello", "tenant_id", "t1", "device_id", "dev-1")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not json: %v: %s", err, buf.String())
	}
	if rec["ts"] == nil || rec["level"] != "warn" || rec["service"] != ServiceName || rec["msg"] != "hello" || rec["tenant_id"] != "t1" || rec["device_id"] != "dev-1" {
		t.Fatalf("record %v", rec)
	}
	if _, ok := rec["time"]; ok {
		t.Fatal("time key should be renamed to ts")
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()
	cases := map[string]slog.Level{"": slog.LevelInfo, "info": slog.LevelInfo, "DEBUG": slog.LevelDebug, "warn": slog.LevelWarn, "warning": slog.LevelWarn, "Error": slog.LevelError}
	for in, want := range cases {
		got, ok := ParseLevel(in)
		if !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v %v", in, got, ok)
		}
	}
	if _, ok := ParseLevel("loud"); ok {
		t.Error("unknown level accepted")
	}
}

func TestParseTraceparent(t *testing.T) {
	t.Parallel()
	tid, sid, ok := ParseTraceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01")
	if !ok || tid != "4bf92f3577b34da6a3ce929d0e0e4736" || sid != "00f067aa0ba902b7" {
		t.Fatalf("parse: %q %q %v", tid, sid, ok)
	}
	bad := []string{"", "00-abc-def-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", "zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", "00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01"}
	for _, in := range bad {
		if _, _, ok := ParseTraceparent(in); ok {
			t.Errorf("ParseTraceparent(%q) should fail", in)
		}
	}
}

func TestMiddlewareAndContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	base := New(&buf, slog.LevelDebug)
	h := Middleware(base, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		FromContext(r.Context()).Info("inside")
		if _, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok {
			t.Error("status writer should expose Unwrap")
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status %d", rec.Code)
	}
	out := buf.String()
	if !strings.Contains(out, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`) || !strings.Contains(out, `"span_id":"00f067aa0ba902b7"`) || !strings.Contains(out, `"status":418`) || !strings.Contains(out, "inside") {
		t.Fatalf("log output %s", out)
	}
	// Without traceparent the request still logs, and FromContext falls back.
	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/y", nil))
	if strings.Contains(buf.String(), "trace_id") || !strings.Contains(buf.String(), `"path":"/y"`) {
		t.Fatalf("log output %s", buf.String())
	}
	if FromContext(context.Background()) != slog.Default() {
		t.Fatal("FromContext default")
	}
	if FromContext(WithLogger(context.Background(), nil)) != slog.Default() {
		t.Fatal("nil logger in context should fall back")
	}
}

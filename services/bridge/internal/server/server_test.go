package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
}

func TestNewHandlerRoutes(t *testing.T) {
	var readyErr error
	h := NewHandler(Config{
		Metrics: okHandler("metrics"),
		Events:  okHandler("events"),
		Ready:   func() error { return readyErr },
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	call := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	if rec := call("GET", "/metrics"); rec.Body.String() != "metrics" {
		t.Errorf("metrics = %q", rec.Body.String())
	}
	if rec := call("POST", "/emqx/events"); rec.Body.String() != "events" {
		t.Errorf("events = %q", rec.Body.String())
	}
	if rec := call("GET", "/healthz"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
	if rec := call("GET", "/readyz"); rec.Code != 200 {
		t.Errorf("readyz = %d", rec.Code)
	}
	readyErr = errors.New("mqtt disconnected")
	if rec := call("GET", "/readyz"); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "mqtt disconnected") {
		t.Errorf("readyz not ready = %d %q", rec.Code, rec.Body.String())
	}
	if rec := call("GET", "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown = %d", rec.Code)
	}
	if rec := call("GET", "/healthz"); rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers missing")
	}

	panicking := NewHandler(Config{Events: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })})
	rec := httptest.NewRecorder()
	panicking.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/emqx/events", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("panic = %d", rec.Code)
	}
	minimal := NewHandler(Config{})
	rec = httptest.NewRecorder()
	minimal.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 200 {
		t.Errorf("readyz without Ready = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	minimal.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("metrics without handler = %d", rec.Code)
	}
}

func TestServeAndShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, NewHandler(Config{}), 0, nil) }()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + ln.Addr().String() + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server never answered: %v", err)
	}
	resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestRunErrorsAndStop(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if err := Run(context.Background(), busy.Addr().String(), NewHandler(Config{}), time.Second, nil); err == nil {
		t.Error("occupied port should fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, "127.0.0.1:0", NewHandler(Config{}), time.Second, nil) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closed.Close()
	if err := Serve(context.Background(), closed, NewHandler(Config{}), time.Second, nil); err == nil {
		t.Error("closed listener should fail")
	}
}

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
	readyErr := error(nil)
	registered := false
	h := NewHandler(Config{
		Authn:       okHandler("authn"),
		Authz:       okHandler("authz"),
		Revocations: okHandler("revocations"),
		Metrics:     okHandler("metrics"),
		Register: func(mux *http.ServeMux) {
			registered = true
			mux.Handle("GET /v1/extra", okHandler("extra"))
			mux.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
		},
		HookToken: "hook",
		Ready:     func() error { return readyErr },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if !registered {
		t.Fatal("Register was not called")
	}
	call := func(method, path string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := call("POST", "/emqx/authn", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("authn without hook token = %d", rec.Code)
	}
	if rec := call("POST", "/emqx/authz", map[string]string{"X-IronMesh-Hook-Token": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("authz with wrong hook token = %d", rec.Code)
	}
	if rec := call("POST", "/emqx/authn", map[string]string{"X-IronMesh-Hook-Token": "hook"}); rec.Code != 200 || rec.Body.String() != "authn" {
		t.Errorf("authn = %d %q", rec.Code, rec.Body.String())
	}
	if rec := call("POST", "/emqx/authz", map[string]string{"X-IronMesh-Hook-Token": "hook"}); rec.Body.String() != "authz" {
		t.Errorf("authz = %q", rec.Body.String())
	}
	if rec := call("POST", "/internal/v1/revocations", nil); rec.Body.String() != "revocations" {
		t.Errorf("revocations = %q", rec.Body.String())
	}
	if rec := call("GET", "/metrics", nil); rec.Body.String() != "metrics" {
		t.Errorf("metrics = %q", rec.Body.String())
	}
	if rec := call("GET", "/v1/extra", nil); rec.Body.String() != "extra" {
		t.Errorf("extra = %q", rec.Body.String())
	}
	if rec := call("GET", "/healthz", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
	if rec := call("GET", "/readyz", nil); rec.Code != 200 {
		t.Errorf("readyz = %d", rec.Code)
	}
	readyErr = errors.New("crl never fetched")
	if rec := call("GET", "/readyz", nil); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "crl never fetched") {
		t.Errorf("readyz not ready = %d %q", rec.Code, rec.Body.String())
	}
	rec := call("GET", "/panic", nil)
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("panic = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("security headers missing: %v", rec.Header())
	}
	if rec := call("GET", "/nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown route = %d", rec.Code)
	}
}

func TestNewHandlerWithoutHookTokenOrOptionalParts(t *testing.T) {
	h := NewHandler(Config{Authn: okHandler("authn")})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/emqx/authn", nil))
	if rec.Code != 200 {
		t.Errorf("authn without configured hook token = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 200 {
		t.Errorf("readyz without Ready func = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
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
	go func() { done <- Serve(ctx, ln, NewHandler(Config{}), time.Second, nil) }()

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
	if resp.StatusCode != 200 {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop after cancel")
	}
}

func TestRunListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := Run(context.Background(), ln.Addr().String(), NewHandler(Config{}), time.Second, nil); err == nil {
		t.Fatal("binding an occupied port should fail")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, "127.0.0.1:0", NewHandler(Config{}), 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
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
}

func TestServeReturnsListenerErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // Serve fails immediately on a closed listener
	if err := Serve(context.Background(), ln, NewHandler(Config{}), time.Second, nil); err == nil {
		t.Fatal("expected error from closed listener")
	}
}

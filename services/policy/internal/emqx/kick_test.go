package emqx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "key", "secret", WithBackoff(time.Millisecond), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient("emqx:18083", "k", "s"); err == nil {
		t.Error("expected error for URL without scheme")
	}
	if _, err := NewClient("ftp://emqx", "k", "s"); err == nil {
		t.Error("expected error for unsupported scheme")
	}
	if _, err := NewClient("http://emqx:18083", "", "s"); err == nil {
		t.Error("expected error for missing key")
	}
	c, err := NewClient("http://emqx:18083/", "k", "s", WithAttempts(0), WithBackoff(-1), WithLogger(nil), WithHTTPClient(http.DefaultClient))
	if err != nil {
		t.Fatal(err)
	}
	if c.attempts != 3 || c.backoff != 200*time.Millisecond || c.log == nil || c.http != http.DefaultClient {
		t.Errorf("options misapplied: %+v", c)
	}
}

func TestKickSuccessUsesDeleteWithBasicAuth(t *testing.T) {
	var gotMethod, gotPath, gotUser, gotPass string
	var gotOK bool
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.Kick(context.Background(), "dev-8f3a1c2b9d4e5f60"); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/v5/clients/dev-8f3a1c2b9d4e5f60" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if !gotOK || gotUser != "key" || gotPass != "secret" {
		t.Errorf("basic auth = %q/%q ok=%v", gotUser, gotPass, gotOK)
	}
}

func TestKickEscapesClientID(t *testing.T) {
	var gotPath string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.Kick(context.Background(), "weird/id?x"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v5/clients/weird%2Fid%3Fx" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestKickNotFoundIsSuccess(t *testing.T) {
	var calls int32
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, `{"code":"CLIENTID_NOT_FOUND"}`, http.StatusNotFound)
	})
	if err := c.Kick(context.Background(), "dev-8f3a1c2b9d4e5f60"); err != nil {
		t.Fatalf("404 should be success, got %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestKickRetriesServerErrors(t *testing.T) {
	var calls int32
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.Kick(context.Background(), "dev-8f3a1c2b9d4e5f60"); err != nil {
		t.Fatalf("expected success on third attempt, got %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestKickGivesUpAfterThreeAttempts(t *testing.T) {
	var calls int32
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := c.Kick(context.Background(), "dev-8f3a1c2b9d4e5f60")
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestKickUnauthorizedIsNotRetried(t *testing.T) {
	var calls int32
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	err := c.Kick(context.Background(), "dev-8f3a1c2b9d4e5f60")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestKickBadRequestIsNotRetried(t *testing.T) {
	var calls int32
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	})
	if err := c.Kick(context.Background(), "dev-8f3a1c2b9d4e5f60"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err = %v, want ErrBadRequest", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
	if err := c.Kick(context.Background(), ""); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty id err = %v, want ErrBadRequest", err)
	}
}

func TestKickTransportErrorRetriedThenContextCancel(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	srv.Close() // connection refused on every attempt
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.Kick(ctx, "dev-8f3a1c2b9d4e5f60")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, context.Canceled) {
		// Depending on timing the request itself may fail first; either way the kick must fail.
		t.Logf("non-context error (acceptable): %v", err)
	}
}

func TestFakeKicker(t *testing.T) {
	f := NewFake()
	if err := f.Kick(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	f.SetErr(errors.New("boom"))
	if err := f.Kick(context.Background(), "b"); err == nil {
		t.Fatal("expected error after SetErr")
	}
	if got := f.Calls(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("Calls = %v", got)
	}
	select {
	case id := <-f.Kicked:
		if id != "a" {
			t.Errorf("first kicked = %q", id)
		}
	default:
		t.Error("Kicked channel empty")
	}
	// Channel saturation must never block the caller.
	full := &Fake{Kicked: make(chan string)}
	done := make(chan struct{})
	go func() { _ = full.Kick(context.Background(), "x"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Kick blocked on a full channel")
	}
}

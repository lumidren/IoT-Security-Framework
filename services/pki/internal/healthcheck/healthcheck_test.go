package healthcheck

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDefaultURL(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		":8444":            "http://127.0.0.1:8444/healthz",
		"0.0.0.0:8444":     "http://127.0.0.1:8444/healthz",
		"[::]:8444":        "http://127.0.0.1:8444/healthz",
		"10.0.0.5:8444":    "http://10.0.0.5:8444/healthz",
		"localhost:9":      "http://localhost:9/healthz",
		"[::1]:8081":       "http://[::1]:8081/healthz",
		"8082":             "http://127.0.0.1:8082/healthz",
		" 127.0.0.1:8081 ": "http://127.0.0.1:8081/healthz",
	}
	for in, want := range cases {
		if got := DefaultURL(in, "healthz"); got != want {
			t.Errorf("DefaultURL(%q) = %q want %q", in, got, want)
		}
	}
	if got := DefaultURL(":1", "/x"); got != "http://127.0.0.1:1/x" {
		t.Errorf("path: %s", got)
	}
}

func TestIsLoopback(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "127.8.0.1": true, "::1": true, "10.0.0.1": false, "pki": false, "": false} {
		if IsLoopback(host) != want {
			t.Errorf("%q: %v", host, !want)
		}
	}
}

func TestRun(t *testing.T) {
	t.Parallel()
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	ctx := context.Background()
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := Run(ctx, "svc", args, srv.URL+"/healthz", &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, out, _ := run(); code != 0 || !strings.Contains(out, "ok") {
		t.Fatalf("healthy default: %d %s", code, out)
	}
	if code, _, _ := run("--url", srv.URL+"/other"); code != 1 {
		t.Fatalf("404: %d", code)
	}
	status = http.StatusServiceUnavailable
	if code, _, errOut := run(); code != 1 || !strings.Contains(errOut, "503") {
		t.Fatalf("503: %d %s", code, errOut)
	}
	if code, _, _ := run("--url", "http://127.0.0.1:1/healthz", "--timeout", "500ms"); code != 1 {
		t.Fatalf("refused: %d", code)
	}
	if code, _, _ := run("--url", "ftp://x/healthz"); code != 1 {
		t.Fatalf("bad scheme: %d", code)
	}
	if code, _, _ := run("--bogus"); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
	if code, _, _ := run("extra"); code != 2 {
		t.Fatalf("extra arg: %d", code)
	}
	if code, _, _ := run("-h"); code != 0 {
		t.Fatalf("help: %d", code)
	}
}

func TestCheckTLS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	ctx := context.Background()
	// Loopback: verification skipped, so the self-signed test certificate is accepted.
	if err := Check(ctx, srv.URL+"/healthz", time.Second); err != nil {
		t.Fatalf("loopback https: %v", err)
	}
	// Non-loopback hosts are verified; plain http has no TLS configuration at all.
	for raw, skip := range map[string]bool{"https://127.0.0.1:1/": true, "https://[::1]:1/": true, "https://localhost:1/": true, "https://pki:8443/": false, "https://10.0.0.5:1/": false} {
		u, _ := url.Parse(raw)
		tr := newClient(u, 0).Transport.(*http.Transport)
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify != skip || tr.Proxy != nil {
			t.Errorf("%s: skip verify want %v", raw, skip)
		}
	}
	u, _ := url.Parse("http://127.0.0.1:1/")
	if tr := newClient(u, time.Second).Transport.(*http.Transport); tr.TLSClientConfig != nil {
		t.Error("plain http got a TLS config")
	}
	// Redirects are not followed (a 3xx is unhealthy).
	redir := httptest.NewServer(http.RedirectHandler("http://example.invalid/", http.StatusFound))
	defer redir.Close()
	if err := Check(ctx, redir.URL, 0); err == nil {
		t.Fatal("redirect treated as healthy")
	}
}

// Package healthcheck implements the "healthcheck" subcommand of the service
// binaries. Distroless images ship no curl/wget, so container and compose
// health checks run the binary itself:
//
//	bridge healthcheck [--url http://127.0.0.1:8082/healthz] [--timeout 3s]
//
// It GETs the health URL once and exits 0 on a 2xx response, 1 otherwise
// (2 on usage errors). Proxies from the environment are ignored. TLS
// certificate verification is only skipped for https URLs whose host is a
// loopback address (a local listener whose certificate does not name
// 127.0.0.1); every other https URL is verified against the system roots.
package healthcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout bounds one health check.
const DefaultTimeout = 3 * time.Second

// DefaultURL derives the local health URL from a listen address such as
// ":8444", "0.0.0.0:8444", "[::]:8444" or "10.0.0.5:8444". Unspecified hosts
// map to the IPv4 loopback address.
func DefaultURL(listen, path string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		host, port = "", strings.TrimPrefix(strings.TrimSpace(listen), ":")
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "http://" + net.JoinHostPort(host, port) + path
}

// IsLoopback reports whether host is "localhost" or a loopback IP.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Check performs one GET against rawURL.
func Check(ctx context.Context, rawURL string, timeout time.Duration) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid health URL %q", rawURL)
	}
	client := newClient(u, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s returned %d", u.Redacted(), resp.StatusCode)
	}
	return nil
}

// newClient returns a proxy-less, redirect-less client; TLS verification is
// skipped only for https on a loopback host.
func newClient(u *url.URL, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	if u.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if IsLoopback(u.Hostname()) {
			transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // loopback-only, see package doc
		}
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// Run implements the subcommand: args are the arguments after "healthcheck".
func Run(ctx context.Context, name string, args []string, defaultURL string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(name+" healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("url", defaultURL, "health endpoint to GET")
	timeout := fs.Duration("timeout", DefaultTimeout, "request timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s healthcheck: unexpected arguments %v\n", name, fs.Args())
		return 2
	}
	if err := Check(ctx, *target, *timeout); err != nil {
		fmt.Fprintf(stderr, "%s healthcheck: unhealthy: %v\n", name, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s healthcheck: ok\n", name)
	return 0
}

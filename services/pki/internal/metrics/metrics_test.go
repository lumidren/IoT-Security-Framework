package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandler(t *testing.T) {
	t.Parallel()
	m := New()
	m2 := New() // independent registries never collide
	if m.Registry() == nil || m2.Registry() == m.Registry() {
		t.Fatal("registry")
	}
	m.ESTRequests.WithLabelValues("simpleenroll", "200").Inc()
	m.RevocationLatency.Observe(0.2)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	out := string(body)
	for _, want := range []string{
		`ironmesh_cert_expiring_total{window="24h"} 0`,
		`ironmesh_cert_expiring_total{window="7d"} 0`,
		`ironmesh_est_requests_total{code="200",op="simpleenroll"} 1`,
		`ironmesh_revocation_latency_seconds_bucket`,
		`ironmesh_revocation_publish_latency_seconds`,
		`ironmesh_auth_failures_total`,
		`go_goroutines`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

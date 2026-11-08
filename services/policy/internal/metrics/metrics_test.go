package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewRegistersContractNames(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.AuthFailures.WithLabelValues("revoked").Inc()
	m.AuthzDecisions.WithLabelValues("allow", "publish").Inc()
	m.ObserveRevocationLatency(0.25)
	m.ObserveRevocationLatency(-1) // clamped to zero, never panics

	want := []string{
		"ironmesh_auth_failures_total",
		"ironmesh_authz_decisions_total",
		"ironmesh_revocation_apply_latency_seconds",
		"ironmesh_revocation_latency_seconds",
	}
	for _, name := range want {
		if n := testutil.CollectAndCount(reg, name); n == 0 {
			t.Errorf("metric %s not registered or empty", name)
		}
	}
	if got := testutil.ToFloat64(m.AuthFailures.WithLabelValues("revoked")); got != 1 {
		t.Errorf("auth failures = %v, want 1", got)
	}
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == "ironmesh_revocation_latency_seconds" {
			h := f.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() != 2 {
				t.Errorf("sample count = %d, want 2", h.GetSampleCount())
			}
			if h.GetSampleSum() != 0.25 {
				t.Errorf("sample sum = %v, want 0.25", h.GetSampleSum())
			}
		}
	}
}

func TestNewPanicsOnDoubleRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when registering twice on the same registry")
		}
	}()
	New(reg)
}

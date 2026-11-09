// Package metrics declares every Prometheus series exported by the policy service.
//
// Names follow DESIGN_CONTRACT.md section 9 (prefix ironmesh_). A Metrics value is bound to a
// registry so tests can use isolated registries instead of the process-wide default.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the collectors used across the service.
type Metrics struct {
	// AuthFailures counts denied CONNECTs by reason (contract: ironmesh_auth_failures_total).
	AuthFailures *prometheus.CounterVec
	// AuthnDecisions counts every authn decision by result and identity kind.
	AuthnDecisions *prometheus.CounterVec
	// AuthzDecisions counts every authz decision by result and action.
	AuthzDecisions *prometheus.CounterVec
	// AuthzCache counts decision-cache hits and misses.
	AuthzCache *prometheus.CounterVec
	// RevocationApplyLatency measures revoked_at -> broker kick completed.
	RevocationApplyLatency prometheus.Histogram
	// RevocationLatency is the contract-mandated alias of RevocationApplyLatency
	// (ironmesh_revocation_latency_seconds); both observe the same value.
	RevocationLatency prometheus.Histogram
	// Revocations counts revocations applied to the cache by source (event|crl|snapshot).
	Revocations *prometheus.CounterVec
	// Kicks counts EMQX session kicks by result (ok|error|skipped; skipped = the live session already
	// uses another certificate than the revoked serial).
	Kicks *prometheus.CounterVec
	// CRLPolls counts CRL poll attempts by result (updated|not_modified|error).
	CRLPolls *prometheus.CounterVec
	// CRLSerials is the number of serials in the last successfully parsed CRL.
	CRLSerials prometheus.Gauge
	// CRLLastSuccess is the unix time of the last successful CRL fetch.
	CRLLastSuccess prometheus.Gauge
	// RegistryLookups counts registry lifecycle lookups by result (hit|miss|error|cache).
	RegistryLookups *prometheus.CounterVec
	// RevokedEntries is the current size of the revocation cache.
	RevokedEntries prometheus.Gauge
}

// New creates and registers the collectors on reg.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		AuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_auth_failures_total",
			Help: "MQTT CONNECT attempts denied by the policy authn hook, by reason.",
		}, []string{"reason"}),
		AuthnDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_authn_decisions_total",
			Help: "Authentication decisions returned to EMQX, by result and identity kind.",
		}, []string{"result", "kind"}),
		AuthzDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_authz_decisions_total",
			Help: "Authorization decisions returned to EMQX, by result and action.",
		}, []string{"result", "action"}),
		AuthzCache: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_authz_cache_total",
			Help: "Authorization decision cache lookups, by outcome (hit|miss).",
		}, []string{"outcome"}),
		RevocationApplyLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ironmesh_revocation_apply_latency_seconds",
			Help:    "Seconds from the PKI revoked_at timestamp until the live MQTT session was kicked.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
		}),
		RevocationLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ironmesh_revocation_latency_seconds",
			Help:    "Seconds from the PKI revoked_at timestamp until the live MQTT session was kicked (contract name).",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
		}),
		Revocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_revocations_total",
			Help: "Revocations applied to the in-memory cache, by source.",
		}, []string{"source"}),
		Kicks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_kick_total",
			Help: "EMQX session kick attempts, by result.",
		}, []string{"result"}),
		CRLPolls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_crl_poll_total",
			Help: "CRL poll attempts, by result.",
		}, []string{"result"}),
		CRLSerials: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_crl_revoked_serials",
			Help: "Number of revoked serials in the most recently parsed CRL.",
		}),
		CRLLastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_crl_last_success_timestamp_seconds",
			Help: "Unix time of the last successful CRL fetch.",
		}),
		RegistryLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_registry_lookups_total",
			Help: "Device lifecycle lookups against the Registry, by result.",
		}, []string{"result"}),
		RevokedEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_revocation_cache_entries",
			Help: "Entries currently held in the revocation cache.",
		}),
	}
	reg.MustRegister(
		m.AuthFailures, m.AuthnDecisions, m.AuthzDecisions, m.AuthzCache,
		m.RevocationApplyLatency, m.RevocationLatency, m.Revocations, m.Kicks,
		m.CRLPolls, m.CRLSerials, m.CRLLastSuccess, m.RegistryLookups, m.RevokedEntries,
	)
	return m
}

// ObserveRevocationLatency records the same observation on both histogram names.
func (m *Metrics) ObserveRevocationLatency(seconds float64) {
	if seconds < 0 {
		seconds = 0
	}
	m.RevocationApplyLatency.Observe(seconds)
	m.RevocationLatency.Observe(seconds)
}

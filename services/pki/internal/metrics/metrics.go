// Package metrics defines the Prometheus metrics of the PKI service (names per
// DESIGN_CONTRACT آ§9, prefix ironmesh_). Metrics are registered on a private
// registry so tests can create many instances without collisions.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every collector of the service.
type Metrics struct {
	registry *prometheus.Registry

	// CertExpiring is ironmesh_cert_expiring_total{window="24h|72h|7d"}.
	CertExpiring *prometheus.GaugeVec
	// RevocationLatency is ironmesh_revocation_latency_seconds: time from the
	// revoke request to the Policy service acknowledging the event.
	RevocationLatency prometheus.Histogram
	// RevocationPublishLatency is ironmesh_revocation_publish_latency_seconds:
	// the HTTP publish call alone (including retries).
	RevocationPublishLatency prometheus.Histogram
	// RevocationPublishFailures counts failed delivery attempts of revocation
	// events (each attempt is retried from the outbox until acknowledged).
	RevocationPublishFailures prometheus.Counter
	// RevocationOutboxPending is ironmesh_revocation_outbox_pending: revocation
	// events written to the outbox but not yet acknowledged by every Policy
	// endpoint.
	RevocationOutboxPending prometheus.Gauge
	// RevocationPublishAttempts is
	// ironmesh_revocation_publish_attempts_total{result="ok|error"}: delivery
	// attempts of outbox events (one attempt covers every fan-out endpoint).
	RevocationPublishAttempts *prometheus.CounterVec
	// RevocationPublishEndpoints is
	// ironmesh_revocation_publish_endpoint_total{result="ok|error"}: deliveries
	// to individual Policy endpoints (one per resolved address with fan-out).
	RevocationPublishEndpoints *prometheus.CounterVec
	// Revocations counts revocations by reason.
	Revocations *prometheus.CounterVec
	// ESTRequests is ironmesh_est_requests_total{op,code}.
	ESTRequests *prometheus.CounterVec
	// CertsIssued is ironmesh_certs_issued_total{kind}.
	CertsIssued *prometheus.CounterVec
	// AuthFailures is ironmesh_auth_failures_total (contract-required name).
	AuthFailures prometheus.Counter
	// OCSPRequests is ironmesh_ocsp_requests_total{status}.
	OCSPRequests *prometheus.CounterVec
	// CRLGenerations counts CRL regenerations.
	CRLGenerations prometheus.Counter
	// AttestationFailures is ironmesh_attestation_failures_total{reason}.
	AttestationFailures *prometheus.CounterVec
}

// Windows are the expiry windows exported by CertExpiring.
var Windows = []string{"24h", "72h", "7d"}

// New creates and registers all metrics on a fresh registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		CertExpiring: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ironmesh_cert_expiring_total",
			Help: "Number of non-revoked certificates expiring within the window.",
		}, []string{"window"}),
		RevocationLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ironmesh_revocation_latency_seconds",
			Help:    "Seconds from revoke request to the Policy service acknowledging the event (every endpoint, retries included).",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}),
		RevocationPublishLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ironmesh_revocation_publish_latency_seconds",
			Help:    "Seconds spent publishing a revocation event to the Policy service.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}),
		RevocationPublishFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironmesh_revocation_publish_failures_total",
			Help: "Failed attempts to deliver a revocation event to the Policy service.",
		}),
		RevocationOutboxPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_revocation_outbox_pending",
			Help: "Revocation events in the outbox that are not acknowledged by every Policy endpoint yet.",
		}),
		RevocationPublishAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_revocation_publish_attempts_total",
			Help: "Delivery attempts of revocation outbox events, by result.",
		}, []string{"result"}),
		RevocationPublishEndpoints: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_revocation_publish_endpoint_total",
			Help: "Revocation event deliveries to individual Policy endpoints, by result.",
		}, []string{"result"}),
		Revocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_revocations_total",
			Help: "Certificates revoked, by reason.",
		}, []string{"reason"}),
		ESTRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_est_requests_total",
			Help: "EST requests by operation and HTTP status code.",
		}, []string{"op", "code"}),
		CertsIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_certs_issued_total",
			Help: "Certificates issued, by kind.",
		}, []string{"kind"}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironmesh_auth_failures_total",
			Help: "Authentication/authorization failures on EST and management endpoints.",
		}),
		OCSPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_ocsp_requests_total",
			Help: "OCSP requests by resulting certificate status.",
		}, []string{"status"}),
		CRLGenerations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironmesh_crl_generations_total",
			Help: "CRL regenerations.",
		}),
		AttestationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_attestation_failures_total",
			Help: "Rejected attestations by failure class.",
		}, []string{"reason"}),
	}
	reg.MustRegister(
		m.CertExpiring, m.RevocationLatency, m.RevocationPublishLatency, m.RevocationPublishFailures, m.Revocations,
		m.RevocationOutboxPending, m.RevocationPublishAttempts, m.RevocationPublishEndpoints,
		m.ESTRequests, m.CertsIssued, m.AuthFailures, m.OCSPRequests, m.CRLGenerations, m.AttestationFailures,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	for _, w := range Windows {
		m.CertExpiring.WithLabelValues(w).Set(0)
	}
	for _, r := range []string{"ok", "error"} {
		m.RevocationPublishAttempts.WithLabelValues(r)
		m.RevocationPublishEndpoints.WithLabelValues(r)
	}
	return m
}

// Registry exposes the underlying registry (tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler serves the metrics in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

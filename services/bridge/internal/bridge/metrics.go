// Package bridge forwards device messages from the EMQX shared subscription to Redpanda and
// EMQX auth events from the webhook endpoint to the im.auth topic (DESIGN_CONTRACT.md section 7,
// API_CONTRACT.md section 6).
package bridge

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the Prometheus collectors of the bridge (DESIGN_CONTRACT.md section 9 names).
type Metrics struct {
	// Messages counts records forwarded to im.ingest by message class.
	Messages *prometheus.CounterVec
	// ForwardErrors counts failed produce attempts.
	ForwardErrors prometheus.Counter
	// Dropped counts messages acknowledged without forwarding, by reason.
	Dropped *prometheus.CounterVec
	// Inflight is the number of messages between receipt and MQTT acknowledgement.
	Inflight prometheus.Gauge
	// AckErrors counts MQTT acknowledgements that failed (connection lost; broker redelivers).
	AckErrors prometheus.Counter
	// AuthEvents counts EMQX auth events forwarded to im.auth by kind.
	AuthEvents *prometheus.CounterVec
	// ConnectedDevices is derived from client.connected / client.disconnected events.
	ConnectedDevices prometheus.Gauge
	// MQTTConnected is 1 while the bridge holds a broker session.
	MQTTConnected prometheus.Gauge
	// ForwardLatency measures receipt -> Kafka acknowledgement.
	ForwardLatency prometheus.Histogram
}

// NewMetrics creates and registers the collectors on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Messages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_bridge_messages_total",
			Help: "Device messages forwarded to the ingest topic, by message class.",
		}, []string{"class"}),
		ForwardErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironmesh_bridge_forward_errors_total",
			Help: "Failed attempts to produce a device message to Kafka.",
		}),
		Dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_bridge_dropped_total",
			Help: "Messages acknowledged without forwarding, by reason.",
		}, []string{"reason"}),
		Inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_bridge_inflight",
			Help: "Messages received from MQTT and not yet acknowledged.",
		}),
		AckErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironmesh_bridge_ack_errors_total",
			Help: "MQTT acknowledgements that could not be sent.",
		}),
		AuthEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironmesh_bridge_auth_events_total",
			Help: "EMQX auth events forwarded to im.auth, by kind.",
		}, []string{"event"}),
		ConnectedDevices: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_connected_devices",
			Help: "Devices currently connected to the broker (derived from EMQX events).",
		}),
		MQTTConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ironmesh_bridge_mqtt_connected",
			Help: "1 while the bridge holds an MQTT session, else 0.",
		}),
		ForwardLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ironmesh_bridge_forward_latency_seconds",
			Help:    "Seconds from MQTT receipt to Kafka acknowledgement.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		}),
	}
	reg.MustRegister(m.Messages, m.ForwardErrors, m.Dropped, m.Inflight, m.AckErrors, m.AuthEvents, m.ConnectedDevices, m.MQTTConnected, m.ForwardLatency)
	return m
}

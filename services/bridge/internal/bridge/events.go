package bridge

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Auth event kinds published to im.auth (API_CONTRACT.md section 6).
const (
	EventConnected    = "connected"
	EventDisconnected = "disconnected"
	EventAuthnFailed  = "authn_failed"
	EventAuthzDenied  = "authz_denied"
)

// emqxEvent is the superset of fields EMQX 5 webhook/rule-engine events carry.
type emqxEvent struct {
	Event       string            `json:"event"`
	ClientID    string            `json:"clientid"`
	Username    string            `json:"username"`
	PeerName    string            `json:"peername"`
	PeerHost    string            `json:"peerhost"`
	Reason      string            `json:"reason"`
	ReasonCode  string            `json:"reason_code"`
	Topic       string            `json:"topic"`
	Action      string            `json:"action"`
	Result      string            `json:"result"`
	Timestamp   int64             `json:"timestamp"`
	Node        string            `json:"node"`
	ClientAttrs map[string]string `json:"client_attrs"`
}

// AuthEvent is the normalised record written to im.auth.
type AuthEvent struct {
	Event    string    `json:"event"`
	ClientID string    `json:"clientid"`
	PeerHost string    `json:"peerhost,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Topic    string    `json:"topic,omitempty"`
	Action   string    `json:"action,omitempty"`
	At       time.Time `json:"at"`
	DeviceID string    `json:"device_id,omitempty"`
	TenantID string    `json:"tenant_id,omitempty"`
	Node     string    `json:"node,omitempty"`
}

// EventsConfig configures the EMQX webhook endpoint.
type EventsConfig struct {
	Producer Producer
	// Topic defaults to im.auth.
	Topic string
	// Token, when set, must be presented as a bearer token by EMQX.
	Token        string
	Metrics      *Metrics
	Logger       *slog.Logger
	Clock        func() time.Time
	MaxBodyBytes int64
}

// EventsHandler serves POST /emqx/events.
type EventsHandler struct {
	producer Producer
	topic    string
	token    []byte
	metrics  *Metrics
	log      *slog.Logger
	now      func() time.Time
	maxBody  int64

	mu        sync.Mutex
	connected map[string]bool
}

// NewEventsHandler validates cfg and returns the handler.
func NewEventsHandler(cfg EventsConfig) (*EventsHandler, error) {
	if cfg.Producer == nil || cfg.Metrics == nil {
		return nil, errors.New("events: producer and metrics are required")
	}
	h := &EventsHandler{producer: cfg.Producer, topic: cfg.Topic, token: []byte(cfg.Token), metrics: cfg.Metrics, log: cfg.Logger, now: cfg.Clock, maxBody: cfg.MaxBodyBytes, connected: make(map[string]bool)}
	if h.topic == "" {
		h.topic = "im.auth"
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.maxBody <= 0 {
		h.maxBody = 1 << 20
	}
	return h, nil
}

// ServeHTTP accepts one event object or an array of them.
func (h *EventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(h.token) > 0 && !h.authorized(r.Header.Get("Authorization")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}
	events, err := decodeEvents(body)
	if err != nil {
		http.Error(w, "body is not an EMQX event or event array", http.StatusBadRequest)
		return
	}
	accepted, ignored := 0, 0
	for _, raw := range events {
		ev, ok := h.normalize(raw)
		if !ok {
			ignored++
			continue
		}
		if err := h.publish(r.Context(), ev); err != nil {
			h.log.Error("auth event not forwarded", "event", ev.Event, "client_id", ev.ClientID, "err", err.Error())
			http.Error(w, "event bus unavailable; retry", http.StatusServiceUnavailable)
			return
		}
		accepted++
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "ignored": ignored})
}

func (h *EventsHandler) authorized(header string) bool {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(header[len(prefix):])), h.token) == 1
}

func decodeEvents(body []byte) ([]emqxEvent, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if trimmed[0] == '[' {
		var list []emqxEvent
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var one emqxEvent
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, err
	}
	return []emqxEvent{one}, nil
}

// normalize maps EMQX event names onto the im.auth vocabulary. Successful authn/authz
// completions and unknown events are ignored.
func (h *EventsHandler) normalize(raw emqxEvent) (AuthEvent, bool) {
	name := strings.ToLower(strings.TrimSpace(raw.Event))
	var kind string
	switch name {
	case "client.connected":
		kind = EventConnected
	case "client.disconnected":
		kind = EventDisconnected
	case "client.authenticate failed", "client.authenticate.failed", "client.authn_failed":
		kind = EventAuthnFailed
	case "client.authorize denied", "client.authorize.denied", "client.authz_denied":
		kind = EventAuthzDenied
	case "client.check_authn_complete", "client.authenticate":
		code := strings.ToLower(raw.ReasonCode)
		if code == "" || code == "success" {
			if strings.ToLower(raw.Result) == "deny" {
				kind = EventAuthnFailed
				break
			}
			h.metrics.AuthEvents.WithLabelValues("ignored").Inc()
			return AuthEvent{}, false
		}
		kind = EventAuthnFailed
	case "client.check_authz_complete", "client.authorize":
		if strings.ToLower(raw.Result) != "deny" {
			h.metrics.AuthEvents.WithLabelValues("ignored").Inc()
			return AuthEvent{}, false
		}
		kind = EventAuthzDenied
	default:
		h.metrics.AuthEvents.WithLabelValues("ignored").Inc()
		return AuthEvent{}, false
	}
	if raw.ClientID == "" {
		h.metrics.AuthEvents.WithLabelValues("ignored").Inc()
		return AuthEvent{}, false
	}
	ev := AuthEvent{
		Event:    kind,
		ClientID: raw.ClientID,
		PeerHost: peerHost(raw),
		Reason:   firstNonEmpty(raw.Reason, raw.ReasonCode),
		Topic:    raw.Topic,
		Action:   raw.Action,
		Node:     raw.Node,
		At:       h.now().UTC(),
	}
	if raw.Timestamp > 0 {
		ev.At = time.UnixMilli(raw.Timestamp).UTC()
	}
	if IsDeviceID(raw.ClientID) {
		ev.DeviceID = raw.ClientID
	}
	if raw.ClientAttrs != nil {
		ev.TenantID = raw.ClientAttrs["tenant_id"]
	}
	h.trackConnected(ev)
	return ev, true
}

func (h *EventsHandler) trackConnected(ev AuthEvent) {
	if ev.DeviceID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch ev.Event {
	case EventConnected:
		h.connected[ev.DeviceID] = true
	case EventDisconnected:
		delete(h.connected, ev.DeviceID)
	default:
		return
	}
	h.metrics.ConnectedDevices.Set(float64(len(h.connected)))
}

// ConnectedDevices returns the number of devices currently believed to be connected.
func (h *EventsHandler) ConnectedDevices() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.connected)
}

func (h *EventsHandler) publish(ctx context.Context, ev AuthEvent) error {
	value, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	rec := Record{
		Topic:     h.topic,
		Key:       []byte(ev.ClientID),
		Value:     value,
		Timestamp: ev.At,
		Headers: []Header{
			{Key: "event", Value: ev.Event},
			{Key: "clientid", Value: ev.ClientID},
			{Key: HeaderReceivedAt, Value: h.now().UTC().Format(time.RFC3339Nano)},
		},
	}
	if ev.DeviceID != "" {
		rec.Headers = append(rec.Headers, Header{Key: HeaderDeviceID, Value: ev.DeviceID})
	}
	if ev.TenantID != "" {
		rec.Headers = append(rec.Headers, Header{Key: HeaderTenantID, Value: ev.TenantID})
	}
	if err := h.producer.Produce(ctx, rec); err != nil {
		return err
	}
	h.metrics.AuthEvents.WithLabelValues(ev.Event).Inc()
	return nil
}

func peerHost(raw emqxEvent) string {
	if raw.PeerHost != "" {
		return raw.PeerHost
	}
	if raw.PeerName == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw.PeerName); err == nil {
		return host
	}
	return raw.PeerName
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

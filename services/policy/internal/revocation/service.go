package revocation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/clock"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/emqx"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/identity"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/problem"
)

// Event is the signed revocation notification pushed by the PKI (DESIGN_CONTRACT.md section 2).
//
// DeviceDeny asks for a device-level deny (revoke-all: registry quarantine or decommission).
// Without it only Serial is denied, unless Reason is keyCompromise or cessationOfOperation (see
// DeviceDenyReason), so a superseded certificate does not lock the renewed device out.
type Event struct {
	EventID    string    `json:"event_id"`
	Serial     string    `json:"serial"`
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
	DeviceDeny bool      `json:"device_deny,omitempty"`
}

// DeviceDenyReason reports whether a revocation reason deny-lists the whole device:
// keyCompromise (the device key or identity is no longer trustworthy) and cessationOfOperation
// (quarantine / decommission). Any spelling of case and underscores is accepted.
func DeviceDenyReason(reason string) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(reason), "_", "")) {
	case "keycompromise", "cessationofoperation":
		return true
	}
	return false
}

// SessionSerials reports the certificate serial of a client's current (last admitted) session.
// *hooks.IdentityCache implements it.
type SessionSerials interface {
	LiveSerial(clientID string) (serial string, known bool)
}

// Validate checks the event shape.
func (e Event) Validate() error {
	var errs []error
	if strings.TrimSpace(e.EventID) == "" {
		errs = append(errs, errors.New("event_id is required"))
	} else if len(e.EventID) > 128 {
		errs = append(errs, errors.New("event_id is too long"))
	}
	if e.Serial != "" && NormalizeSerial(e.Serial) == "" {
		errs = append(errs, errors.New("serial is not hexadecimal"))
	}
	if e.DeviceID == "" && NormalizeSerial(e.Serial) == "" {
		errs = append(errs, errors.New("device_id or serial is required"))
	}
	if e.DeviceID != "" && !identity.IsDeviceID(e.DeviceID) && !identity.IsServiceCN(e.DeviceID) {
		errs = append(errs, errors.New("device_id is not a device id or service identity"))
	}
	if e.TenantID != "" && !identity.IsTenantID(e.TenantID) {
		errs = append(errs, errors.New("tenant_id is not a UUID"))
	}
	if e.RevokedAt.IsZero() {
		errs = append(errs, errors.New("revoked_at is required"))
	}
	if len(e.Reason) > 256 {
		errs = append(errs, errors.New("reason is too long"))
	}
	return errors.Join(errs...)
}

// ServiceConfig configures a Service.
type ServiceConfig struct {
	Cache      *Cache
	Kicker     emqx.Kicker
	Token      string
	HMACSecret string
	Clock      clock.Clock
	Metrics    *metrics.Metrics
	Logger     *slog.Logger
	// Sessions, when set, lets serial-scoped revocations skip the kick when the live session is
	// known to use another certificate. Without it (or when the serial of the live session is
	// unknown, e.g. it was admitted by another policy replica) the session is kicked; a device
	// that renewed reconnects with its current certificate.
	Sessions SessionSerials
	// QueueSize bounds pending kicks (default 1024).
	QueueSize int
	// KickTimeout bounds one kick including retries (default 5s).
	KickTimeout time.Duration
	// RetryInterval is how often unkicked entries are retried (default 30s).
	RetryInterval time.Duration
	// MaxBodyBytes bounds the event body (default 64 KiB).
	MaxBodyBytes int64
}

// Service applies revocation events: deny-list the device, persist, kick the live session.
type Service struct {
	cache         *Cache
	kicker        emqx.Kicker
	sessions      SessionSerials
	token         []byte
	secret        []byte
	clock         clock.Clock
	metrics       *metrics.Metrics
	log           *slog.Logger
	queue         chan string
	kickTimeout   time.Duration
	retryInterval time.Duration
	maxBody       int64
	wg            sync.WaitGroup
	startOnce     sync.Once
}

// Result describes what Apply did.
type Result struct {
	Added      bool `json:"added"`
	Duplicate  bool `json:"duplicate"`
	KickQueued bool `json:"kick_queued"`
}

// ErrQueueFull is returned when a kick cannot be queued before the request context ends.
var ErrQueueFull = errors.New("revocation: kick queue is full")

// NewService validates cfg and returns a Service. Start must be called to process kicks.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Cache == nil {
		return nil, errors.New("revocation: cache is required")
	}
	if cfg.Kicker == nil {
		return nil, errors.New("revocation: kicker is required")
	}
	if cfg.Token == "" || cfg.HMACSecret == "" {
		return nil, errors.New("revocation: token and HMAC secret are required")
	}
	if cfg.Metrics == nil {
		return nil, errors.New("revocation: metrics are required")
	}
	s := &Service{
		cache:         cfg.Cache,
		kicker:        cfg.Kicker,
		sessions:      cfg.Sessions,
		token:         []byte(cfg.Token),
		secret:        []byte(cfg.HMACSecret),
		clock:         cfg.Clock,
		metrics:       cfg.Metrics,
		log:           cfg.Logger,
		kickTimeout:   cfg.KickTimeout,
		retryInterval: cfg.RetryInterval,
		maxBody:       cfg.MaxBodyBytes,
	}
	if s.clock == nil {
		s.clock = clock.Real{}
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	s.queue = make(chan string, cfg.QueueSize)
	if s.kickTimeout <= 0 {
		s.kickTimeout = 5 * time.Second
	}
	if s.retryInterval <= 0 {
		s.retryInterval = 30 * time.Second
	}
	if s.maxBody <= 0 {
		s.maxBody = 64 << 10
	}
	s.metrics.RevokedEntries.Set(float64(s.cache.Len()))
	return s, nil
}

// Start launches the kick worker and re-queues entries that were never kicked (restart recovery).
// It returns immediately; the worker stops when ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		for _, e := range s.cache.Unkicked() {
			select {
			case s.queue <- e.EventID:
			default:
			}
		}
		s.wg.Add(1)
		go s.run(ctx)
	})
}

// Wait blocks until the worker has exited.
func (s *Service) Wait() { s.wg.Wait() }

// Handler serves POST /internal/v1/revocations.
func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

// ApplySerial records a serial learned from the CRL (no device id, so no kick). It returns whether
// the serial was new.
func (s *Service) ApplySerial(serial string, revokedAt time.Time, reason string) (bool, error) {
	norm := NormalizeSerial(serial)
	if norm == "" {
		return false, fmt.Errorf("revocation: invalid serial %q", serial)
	}
	res, err := s.Apply(context.Background(), Event{
		EventID:   "crl:" + norm,
		Serial:    norm,
		Reason:    reason,
		RevokedAt: revokedAt,
	}, SourceCRL)
	return res.Added, err
}

// Apply records the event in the cache and queues the broker kick when a device id is known.
// The device id is deny-listed only for device-level revocations (DeviceDeny or a
// DeviceDenyReason); otherwise only the serial is.
func (s *Service) Apply(ctx context.Context, ev Event, source string) (Result, error) {
	entry := Entry{
		EventID:    ev.EventID,
		Serial:     ev.Serial,
		DeviceID:   ev.DeviceID,
		TenantID:   ev.TenantID,
		Reason:     ev.Reason,
		DeviceDeny: ev.DeviceID != "" && (ev.DeviceDeny || DeviceDenyReason(ev.Reason)),
		RevokedAt:  ev.RevokedAt.UTC(),
		Source:     source,
	}
	added, perr := s.cache.Upsert(entry)
	if perr != nil {
		s.log.Error("revocation snapshot not persisted", "event_id", ev.EventID, "err", perr.Error())
	}
	s.metrics.RevokedEntries.Set(float64(s.cache.Len()))
	if !added {
		return Result{Duplicate: true}, nil
	}
	s.metrics.Revocations.WithLabelValues(source).Inc()
	s.log.Info("revocation applied",
		"event_id", ev.EventID, "device_id", ev.DeviceID, "tenant_id", ev.TenantID,
		"serial", NormalizeSerial(ev.Serial), "reason", ev.Reason, "device_deny", entry.DeviceDeny, "source", source)
	res := Result{Added: true}
	if entry.DeviceID == "" {
		return res, nil
	}
	select {
	case s.queue <- ev.EventID:
		res.KickQueued = true
		return res, nil
	case <-ctx.Done():
		return res, ErrQueueFull
	}
}

func (s *Service) run(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.retryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.queue:
			s.kick(ctx, id)
		case <-ticker.C:
			for _, e := range s.cache.Unkicked() {
				if ctx.Err() != nil {
					return
				}
				s.kick(ctx, e.EventID)
			}
		}
	}
}

func (s *Service) kick(ctx context.Context, eventID string) {
	e, ok := s.cache.Get(eventID)
	if !ok || e.DeviceID == "" || e.Kicked {
		return
	}
	// A serial-scoped revocation only ends the session if it runs on that certificate.
	if !e.DeviceDeny && e.Serial != "" && s.sessions != nil {
		if live, known := s.sessions.LiveSerial(e.DeviceID); known && NormalizeSerial(live) != e.Serial {
			s.metrics.Kicks.WithLabelValues("skipped").Inc()
			if err := s.cache.MarkKickSkipped(eventID); err != nil {
				s.log.Error("failed to record skipped kick", "event_id", eventID, "err", err.Error())
			}
			s.log.Info("revoked certificate is not the live session's; kick skipped", "device_id", e.DeviceID, "tenant_id", e.TenantID, "event_id", eventID, "serial", e.Serial)
			return
		}
	}
	kctx, cancel := context.WithTimeout(ctx, s.kickTimeout)
	defer cancel()
	if err := s.kicker.Kick(kctx, e.DeviceID); err != nil {
		s.metrics.Kicks.WithLabelValues("error").Inc()
		s.log.Error("failed to kick revoked session; will retry", "device_id", e.DeviceID, "tenant_id", e.TenantID, "event_id", eventID, "err", err.Error())
		return
	}
	s.metrics.Kicks.WithLabelValues("ok").Inc()
	latency := s.clock.Now().Sub(e.RevokedAt).Seconds()
	s.metrics.ObserveRevocationLatency(latency)
	if err := s.cache.MarkKicked(eventID); err != nil {
		s.log.Error("failed to record kick", "event_id", eventID, "err", err.Error())
	}
	s.log.Info("revoked session kicked", "device_id", e.DeviceID, "tenant_id", e.TenantID, "event_id", eventID, "latency_seconds", latency)
}

func (s *Service) authorized(header string) bool {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(header[len(prefix):])), s.token) == 1
}

func (s *Service) validSignature(header string, body []byte) bool {
	sig := strings.TrimSpace(header)
	sig = strings.TrimPrefix(sig, "sha256=")
	got, err := hex.DecodeString(sig)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		problem.Write(w, r, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}
	if !s.authorized(r.Header.Get("Authorization")) {
		s.metrics.AuthFailures.WithLabelValues("revocation_token").Inc()
		problem.Write(w, r, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			problem.Write(w, r, http.StatusRequestEntityTooLarge, "body exceeds limit")
			return
		}
		problem.Write(w, r, http.StatusBadRequest, "could not read body")
		return
	}
	if !s.validSignature(r.Header.Get("X-IronMesh-Signature"), body) {
		s.metrics.AuthFailures.WithLabelValues("revocation_signature").Inc()
		problem.Write(w, r, http.StatusUnauthorized, "missing or invalid X-IronMesh-Signature")
		return
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		problem.Write(w, r, http.StatusBadRequest, "body is not a valid revocation event", err.Error())
		return
	}
	if err := ev.Validate(); err != nil {
		problem.Write(w, r, http.StatusUnprocessableEntity, "revocation event failed validation", strings.Split(err.Error(), "\n")...)
		return
	}
	res, err := s.Apply(r.Context(), ev, SourceEvent)
	if err != nil {
		problem.Write(w, r, http.StatusServiceUnavailable, "revocation accepted into cache but kick could not be queued; retry")
		return
	}
	status := "accepted"
	if res.Duplicate {
		status = "duplicate"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      status,
		"event_id":    ev.EventID,
		"kick_queued": res.KickQueued,
	})
}

// Package revocation implements certificate revocation (DESIGN_CONTRACT §2):
// write the revocation together with its Policy event (durable outbox),
// regenerate the CRL, invalidate OCSP caches, make a first signed delivery
// attempt to the Policy service and leave retries (exponential backoff, until
// every Policy endpoint acknowledged) to the outbox Dispatcher. The end-to-end
// latency (revoke request -> acknowledgement) is
// ironmesh_revocation_latency_seconds.
package revocation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

var (
	// ErrNotFound means no certificate with that serial is known.
	ErrNotFound = store.ErrNotFound
	// ErrAlreadyRevoked means the serial was revoked earlier.
	ErrAlreadyRevoked = store.ErrAlreadyRevoked
	// ErrInvalidSerial means the serial could not be parsed.
	ErrInvalidSerial = errors.New("revocation: invalid serial")
	// ErrInvalidReason means the reason is not an RFC 5280 CRLReason.
	ErrInvalidReason = errors.New("revocation: invalid reason")
)

// CRLRegenerator is satisfied by *crl.Manager.
type CRLRegenerator interface {
	Regenerate(ctx context.Context) error
}

// OCSPInvalidator is satisfied by *ocsp.Responder.
type OCSPInvalidator interface {
	Invalidate(serial string)
}

// Options wires the service.
type Options struct {
	CRL       CRLRegenerator
	OCSP      OCSPInvalidator
	Publisher Publisher
	Metrics   *metrics.Metrics
	Clock     func() time.Time
	Logger    *slog.Logger
	// Dispatcher tunes the outbox dispatcher (Publisher, Metrics, Clock and
	// Logger are taken from the fields above).
	Dispatcher DispatcherOptions
}

// Service revokes certificates.
type Service struct {
	store      store.Store
	opts       Options
	dispatcher *Dispatcher
}

// NewService returns a Service. Nil CRL/OCSP/Publisher hooks are skipped.
func NewService(st store.Store, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("revocation: a store is required")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Publisher == nil {
		opts.Publisher = NoopPublisher{Logger: opts.Logger}
	}
	dopts := opts.Dispatcher
	dopts.Publisher, dopts.Metrics, dopts.Clock, dopts.Logger = opts.Publisher, opts.Metrics, opts.Clock, opts.Logger
	return &Service{store: st, opts: opts, dispatcher: NewDispatcher(st, dopts)}, nil
}

// Dispatcher returns the outbox dispatcher; run it with RunDispatcher.
func (s *Service) Dispatcher() *Dispatcher { return s.dispatcher }

// RunDispatcher delivers pending outbox events (including those left by a
// previous process) until ctx ends.
func (s *Service) RunDispatcher(ctx context.Context) { s.dispatcher.Run(ctx) }

// Result describes a completed revocation.
type Result struct {
	Serial         string        `json:"serial"`
	DeviceID       string        `json:"device_id"`
	TenantID       string        `json:"tenant_id"`
	Reason         int           `json:"reason_code"`
	ReasonName     string        `json:"reason"`
	RevokedAt      time.Time     `json:"revoked_at"`
	EventID        string        `json:"event_id"`
	DeviceDeny     bool          `json:"device_deny"`
	Published      bool          `json:"published"`
	PublishLatency time.Duration `json:"-"`
	PublishError   string        `json:"publish_error,omitempty"`
}

// Revoke revokes one certificate. It returns ErrNotFound, ErrAlreadyRevoked,
// ErrInvalidSerial or ErrInvalidReason for client errors.
//
// The revocation and its Policy event are committed together (revocation
// outbox); Revoke then makes one delivery attempt before returning. A failed
// attempt is reported in the Result (Published=false), not as an error: the
// revocation is durable, visible via CRL/OCSP, and the dispatcher keeps
// retrying the event until every Policy endpoint acknowledged it.
//
// The event denies only this serial (device_deny=false), so revoking one
// certificate (for example the one superseded by a renewal) does not lock
// the device out of its other, valid certificates.
func (s *Service) Revoke(ctx context.Context, serial, reason, revokedBy string) (*Result, error) {
	return s.revoke(ctx, serial, reason, revokedBy, true, false)
}

// RevokeUndelivered revokes a certificate that was issued but never handed
// to the device (enrollment rolled back). It writes the revocation,
// regenerates the CRL and invalidates OCSP like Revoke, but does not push an
// event to the Policy service: no session can exist on that certificate.
func (s *Service) RevokeUndelivered(ctx context.Context, serial, reason, revokedBy string) (*Result, error) {
	return s.revoke(ctx, serial, reason, revokedBy, false, false)
}

func (s *Service) revoke(ctx context.Context, serial, reason, revokedBy string, publish, deviceDeny bool) (*Result, error) {
	start := s.opts.Clock()
	_, canonical, err := ca.ParseSerial(serial)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSerial, err)
	}
	reasonCode, err := ca.ParseReason(reason)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReason, err)
	}
	rec, err := s.store.GetCertificate(ctx, canonical)
	if err != nil {
		return nil, err
	}
	eventID, err := newEventID()
	if err != nil {
		return nil, err
	}
	now := s.opts.Clock().UTC()
	rev := &store.Revocation{
		Serial: canonical, DeviceID: rec.DeviceID, TenantID: rec.TenantID, IssuerCN: rec.IssuerCN, NotAfter: rec.NotAfter,
		Reason: reasonCode, RevokedAt: now, RevokedBy: revokedBy,
	}
	ev := Event{EventID: eventID, Serial: canonical, DeviceID: rec.DeviceID, TenantID: rec.TenantID, Reason: ca.ReasonString(reasonCode), RevokedAt: now, DeviceDeny: deviceDeny}
	var outbox *store.OutboxEvent
	if publish {
		payload, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		// The writer holds the event for one lease so the background
		// dispatcher does not race the inline first attempt; after a crash
		// the event becomes due when the lease ends.
		outbox = &store.OutboxEvent{EventID: eventID, TenantID: rec.TenantID, Payload: payload, CreatedAt: start.UTC(), NextAttemptAt: now.Add(s.dispatcher.Lease())}
		err = s.store.AddRevocationWithEvent(ctx, rev, outbox)
		if err != nil {
			return nil, err
		}
	} else if err := s.store.AddRevocation(ctx, rev); err != nil {
		return nil, err
	}
	s.opts.Metrics.Revocations.WithLabelValues(ca.ReasonString(reasonCode)).Inc()
	log := s.opts.Logger.With("serial", canonical, "device_id", rec.DeviceID, "tenant_id", rec.TenantID, "reason", ca.ReasonString(reasonCode), "revoked_by", revokedBy, "event_id", eventID, "device_deny", deviceDeny)
	log.Info("certificate revoked")

	if s.opts.CRL != nil {
		if err := s.opts.CRL.Regenerate(ctx); err != nil {
			log.Error("crl regeneration after revocation failed", "error", err.Error())
		}
	}
	if s.opts.OCSP != nil {
		s.opts.OCSP.Invalidate(canonical)
	}

	res := &Result{Serial: canonical, DeviceID: rec.DeviceID, TenantID: rec.TenantID, Reason: reasonCode, ReasonName: ca.ReasonString(reasonCode), RevokedAt: now, EventID: eventID, DeviceDeny: deviceDeny && publish}
	if !publish {
		log.Info("revocation not published: certificate was never delivered")
		return res, nil
	}
	pubStart := s.opts.Clock()
	pubErr := s.dispatcher.Attempt(ctx, outbox)
	res.PublishLatency = s.opts.Clock().Sub(pubStart)
	if pubErr != nil {
		res.PublishError = pubErr.Error()
		log.Error("first revocation event delivery failed; queued in the outbox for retry", "error", pubErr.Error(), "publish_ms", res.PublishLatency.Milliseconds())
		s.dispatcher.RefreshPending(ctx)
		return res, nil
	}
	res.Published = true
	s.dispatcher.RefreshPending(ctx)
	return res, nil
}

// RevokeDevice revokes every unexpired, unrevoked certificate of a device
// (revoke-all: registry quarantine and decommission). Its events carry
// device_deny=true so the Policy service deny-lists the device id itself.
func (s *Service) RevokeDevice(ctx context.Context, deviceID, reason, revokedBy string) ([]*Result, error) {
	if _, err := ca.ParseReason(reason); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReason, err)
	}
	certs, err := s.store.ListCertificatesByDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	now := s.opts.Clock().UTC()
	results := []*Result{}
	for _, c := range certs {
		if !c.NotAfter.After(now) {
			continue
		}
		res, err := s.revoke(ctx, c.Serial, reason, revokedBy, true, true)
		if errors.Is(err, ErrAlreadyRevoked) {
			continue
		}
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// newEventID returns a random UUIDv4 string.
func newEventID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("revocation: event id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

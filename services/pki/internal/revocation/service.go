// Package revocation implements certificate revocation (DESIGN_CONTRACT §2):
// write the revocation, regenerate the CRL, invalidate OCSP caches and push a
// signed event to the Policy service synchronously, measuring the end-to-end
// latency as ironmesh_revocation_latency_seconds.
package revocation

import (
	"context"
	"crypto/rand"
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
}

// Service revokes certificates.
type Service struct {
	store store.Store
	opts  Options
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
	return &Service{store: st, opts: opts}, nil
}

// Result describes a completed revocation.
type Result struct {
	Serial         string        `json:"serial"`
	DeviceID       string        `json:"device_id"`
	TenantID       string        `json:"tenant_id"`
	Reason         int           `json:"reason_code"`
	ReasonName     string        `json:"reason"`
	RevokedAt      time.Time     `json:"revoked_at"`
	EventID        string        `json:"event_id"`
	Published      bool          `json:"published"`
	PublishLatency time.Duration `json:"-"`
	PublishError   string        `json:"publish_error,omitempty"`
}

// Revoke revokes one certificate. It returns ErrNotFound, ErrAlreadyRevoked,
// ErrInvalidSerial or ErrInvalidReason for client errors. A publish failure
// after retries is reported in the Result (Published=false), not as an error,
// because the revocation itself is durable and visible via CRL/OCSP.
func (s *Service) Revoke(ctx context.Context, serial, reason, revokedBy string) (*Result, error) {
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
	if err := s.store.AddRevocation(ctx, rev); err != nil {
		return nil, err
	}
	s.opts.Metrics.Revocations.WithLabelValues(ca.ReasonString(reasonCode)).Inc()
	log := s.opts.Logger.With("serial", canonical, "device_id", rec.DeviceID, "tenant_id", rec.TenantID, "reason", ca.ReasonString(reasonCode), "revoked_by", revokedBy, "event_id", eventID)
	log.Info("certificate revoked")

	if s.opts.CRL != nil {
		if err := s.opts.CRL.Regenerate(ctx); err != nil {
			log.Error("crl regeneration after revocation failed", "error", err.Error())
		}
	}
	if s.opts.OCSP != nil {
		s.opts.OCSP.Invalidate(canonical)
	}

	res := &Result{Serial: canonical, DeviceID: rec.DeviceID, TenantID: rec.TenantID, Reason: reasonCode, ReasonName: ca.ReasonString(reasonCode), RevokedAt: now, EventID: eventID}
	ev := Event{EventID: eventID, Serial: canonical, DeviceID: rec.DeviceID, TenantID: rec.TenantID, Reason: ca.ReasonString(reasonCode), RevokedAt: now}
	pubStart := s.opts.Clock()
	pubErr := s.opts.Publisher.Publish(ctx, ev)
	res.PublishLatency = s.opts.Clock().Sub(pubStart)
	s.opts.Metrics.RevocationPublishLatency.Observe(res.PublishLatency.Seconds())
	if pubErr != nil {
		s.opts.Metrics.RevocationPublishFailures.Inc()
		res.PublishError = pubErr.Error()
		log.Error("revocation event publish failed", "error", pubErr.Error(), "publish_ms", res.PublishLatency.Milliseconds())
		return res, nil
	}
	res.Published = true
	total := s.opts.Clock().Sub(start)
	s.opts.Metrics.RevocationLatency.Observe(total.Seconds())
	log.Info("revocation event published", "publish_ms", res.PublishLatency.Milliseconds(), "total_ms", total.Milliseconds())
	return res, nil
}

// RevokeDevice revokes every unexpired, unrevoked certificate of a device.
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
		res, err := s.Revoke(ctx, c.Serial, reason, revokedBy)
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

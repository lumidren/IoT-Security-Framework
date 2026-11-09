package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Memory is an in-memory Store for tests and single-node development. All
// records are copied on the way in and out so callers cannot alias state.
type Memory struct {
	mu          sync.RWMutex
	certs       map[string]*CertificateRecord
	revocations map[string]*Revocation
	nonces      map[string]*Nonce
	policies    map[string]*TenantPolicy
	outbox      map[string]*OutboxEvent
	crlNumber   int64
	closed      bool
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		certs:       map[string]*CertificateRecord{},
		revocations: map[string]*Revocation{},
		nonces:      map[string]*Nonce{},
		policies:    map[string]*TenantPolicy{},
		outbox:      map[string]*OutboxEvent{},
	}
}

var errClosed = errors.New("store: closed")

func (m *Memory) checkOpen() error {
	if m.closed {
		return errClosed
	}
	return nil
}

// PutCertificate implements Store.
func (m *Memory) PutCertificate(_ context.Context, rec *CertificateRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	if rec.Serial == "" {
		return errors.New("store: serial is required")
	}
	if _, ok := m.certs[rec.Serial]; ok {
		return ErrAlreadyExists
	}
	m.certs[rec.Serial] = copyCert(rec)
	return nil
}

// GetCertificate implements Store.
func (m *Memory) GetCertificate(_ context.Context, serial string) (*CertificateRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	rec, ok := m.certs[serial]
	if !ok {
		return nil, ErrNotFound
	}
	return copyCert(rec), nil
}

// ListCertificatesByDevice implements Store.
func (m *Memory) ListCertificatesByDevice(_ context.Context, deviceID string) ([]*CertificateRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	var out []*CertificateRecord
	for _, rec := range m.certs {
		if rec.DeviceID == deviceID {
			out = append(out, copyCert(rec))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].IssuedAt.After(out[j].IssuedAt)
		}
		return out[i].Serial < out[j].Serial
	})
	return out, nil
}

// CountExpiring implements Store.
func (m *Memory) CountExpiring(_ context.Context, from, until time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return 0, err
	}
	n := 0
	for serial, rec := range m.certs {
		if _, revoked := m.revocations[serial]; revoked {
			continue
		}
		if rec.NotAfter.After(from) && !rec.NotAfter.After(until) {
			n++
		}
	}
	return n, nil
}

// Stats implements Store.
func (m *Memory) Stats(_ context.Context, now time.Time) (*Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	s := &Stats{Total: len(m.certs)}
	for serial, rec := range m.certs {
		if _, revoked := m.revocations[serial]; revoked {
			s.Revoked++
		}
		if !rec.NotAfter.After(now) {
			s.Expired++
		}
	}
	return s, nil
}

// AddRevocation implements Store.
func (m *Memory) AddRevocation(_ context.Context, rev *Revocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	if rev.Serial == "" {
		return errors.New("store: serial is required")
	}
	if _, ok := m.revocations[rev.Serial]; ok {
		return ErrAlreadyRevoked
	}
	r := *rev
	m.revocations[rev.Serial] = &r
	return nil
}

// GetRevocation implements Store.
func (m *Memory) GetRevocation(_ context.Context, serial string) (*Revocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	rev, ok := m.revocations[serial]
	if !ok {
		return nil, ErrNotFound
	}
	r := *rev
	return &r, nil
}

// ListRevocations implements Store.
func (m *Memory) ListRevocations(_ context.Context) ([]*Revocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	out := make([]*Revocation, 0, len(m.revocations))
	for _, rev := range m.revocations {
		r := *rev
		out = append(out, &r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial < out[j].Serial })
	return out, nil
}

// AddRevocationWithEvent implements Store.
func (m *Memory) AddRevocationWithEvent(_ context.Context, rev *Revocation, ev *OutboxEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	if rev.Serial == "" {
		return errors.New("store: serial is required")
	}
	if ev == nil || ev.EventID == "" {
		return errors.New("store: outbox event id is required")
	}
	kind, err := OutboxKind(ev.Kind)
	if err != nil {
		return err
	}
	if _, ok := m.revocations[rev.Serial]; ok {
		return ErrAlreadyRevoked
	}
	if _, ok := m.outbox[ev.EventID]; ok {
		return ErrAlreadyExists
	}
	r := *rev
	m.revocations[rev.Serial] = &r
	c := copyOutbox(ev)
	c.Kind = kind
	m.outbox[ev.EventID] = c
	return nil
}

// AddOutboxEvent implements Store.
func (m *Memory) AddOutboxEvent(_ context.Context, ev *OutboxEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	if ev == nil || ev.EventID == "" {
		return errors.New("store: outbox event id is required")
	}
	kind, err := OutboxKind(ev.Kind)
	if err != nil {
		return err
	}
	if _, ok := m.outbox[ev.EventID]; ok {
		return ErrAlreadyExists
	}
	c := copyOutbox(ev)
	c.Kind = kind
	m.outbox[ev.EventID] = c
	return nil
}

// ClaimOutbox implements Store.
func (m *Memory) ClaimOutbox(_ context.Context, now time.Time, lease time.Duration, limit int) ([]*OutboxEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	var due []*OutboxEvent
	for _, ev := range m.outbox {
		if ev.DeliveredAt.IsZero() && !ev.NextAttemptAt.After(now) {
			due = append(due, ev)
		}
	}
	sortOutbox(due)
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	out := make([]*OutboxEvent, 0, len(due))
	for _, ev := range due {
		ev.NextAttemptAt = now.Add(lease)
		out = append(out, copyOutbox(ev))
	}
	return out, nil
}

// RecordOutboxAttempt implements Store.
func (m *Memory) RecordOutboxAttempt(_ context.Context, eventID string, attempts int, next time.Time, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	ev, ok := m.outbox[eventID]
	if !ok {
		return ErrNotFound
	}
	ev.Attempts, ev.NextAttemptAt, ev.LastError = attempts, next, lastErr
	return nil
}

// AckOutbox implements Store.
func (m *Memory) AckOutbox(_ context.Context, eventID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	ev, ok := m.outbox[eventID]
	if !ok {
		return ErrNotFound
	}
	if ev.DeliveredAt.IsZero() {
		ev.DeliveredAt = at
	}
	return nil
}

// CountPendingOutbox implements Store.
func (m *Memory) CountPendingOutbox(context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return 0, err
	}
	n := 0
	for _, ev := range m.outbox {
		if ev.DeliveredAt.IsZero() {
			n++
		}
	}
	return n, nil
}

func sortOutbox(list []*OutboxEvent) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		}
		return list[i].EventID < list[j].EventID
	})
}

func copyOutbox(ev *OutboxEvent) *OutboxEvent {
	c := *ev
	c.Payload = append([]byte(nil), ev.Payload...)
	return &c
}

// PutNonce implements Store.
func (m *Memory) PutNonce(_ context.Context, n *Nonce) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	if n.Value == "" {
		return errors.New("store: nonce value is required")
	}
	if _, ok := m.nonces[n.Value]; ok {
		return ErrAlreadyExists
	}
	c := *n
	m.nonces[n.Value] = &c
	return nil
}

// ConsumeNonce implements Store.
func (m *Memory) ConsumeNonce(_ context.Context, value string, now time.Time) (*Nonce, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	n, ok := m.nonces[value]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.nonces, value)
	c := *n
	if !c.ExpiresAt.After(now) {
		return &c, ErrNonceExpired
	}
	return &c, nil
}

// DeleteExpiredNonces implements Store.
func (m *Memory) DeleteExpiredNonces(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return 0, err
	}
	n := 0
	for k, v := range m.nonces {
		if !v.ExpiresAt.After(now) {
			delete(m.nonces, k)
			n++
		}
	}
	return n, nil
}

// NextCRLNumber implements Store.
func (m *Memory) NextCRLNumber(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return 0, err
	}
	m.crlNumber++
	return m.crlNumber, nil
}

// GetTenantPolicy implements Store.
func (m *Memory) GetTenantPolicy(_ context.Context, tenantID string) (*TenantPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkOpen(); err != nil {
		return nil, err
	}
	p, ok := m.policies[tenantID]
	if !ok {
		return nil, ErrNotFound
	}
	return copyPolicy(p), nil
}

// PutTenantPolicy implements Store.
func (m *Memory) PutTenantPolicy(_ context.Context, p *TenantPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkOpen(); err != nil {
		return err
	}
	if p.TenantID == "" {
		return errors.New("store: tenant id is required")
	}
	m.policies[p.TenantID] = copyPolicy(p)
	return nil
}

// Ping implements Store.
func (m *Memory) Ping(context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.checkOpen()
}

// Close implements Store.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func copyCert(rec *CertificateRecord) *CertificateRecord {
	c := *rec
	c.DER = append([]byte(nil), rec.DER...)
	return &c
}

func copyPolicy(p *TenantPolicy) *TenantPolicy {
	c := *p
	c.AllowedPCRDigests = append([]string(nil), p.AllowedPCRDigests...)
	c.TenantCmdPubKey = append([]byte(nil), p.TenantCmdPubKey...)
	c.FwSigningPubKeys = nil
	for _, k := range p.FwSigningPubKeys {
		c.FwSigningPubKeys = append(c.FwSigningPubKeys, append([]byte(nil), k...))
	}
	return &c
}

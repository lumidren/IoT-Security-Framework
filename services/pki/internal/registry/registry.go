// Package registry is the PKI's client to the Registry service, which owns the
// device lifecycle (DESIGN_CONTRACT §7): manufactured -> provisioned -> active
// -> quarantined -> active | decommissioned. Enrollment is only permitted in
// the first three states.
package registry

import (
	"context"
	"errors"
	"sync"
	"time"
)

// State is a device lifecycle state.
type State string

// Lifecycle states.
const (
	StateManufactured   State = "manufactured"
	StateProvisioned    State = "provisioned"
	StateActive         State = "active"
	StateQuarantined    State = "quarantined"
	StateDecommissioned State = "decommissioned"
)

// EnrollmentAllowed reports whether a device in this state may (re)enroll.
func (s State) EnrollmentAllowed() bool {
	switch s {
	case StateManufactured, StateProvisioned, StateActive:
		return true
	}
	return false
}

// Device is the registry's view of a device.
type Device struct {
	DeviceID  string `json:"device_id"`
	TenantID  string `json:"tenant_id"`
	State     State  `json:"state"`
	Assurance string `json:"assurance_level,omitempty"`
	// SeType is the secure element type recorded at manufacture
	// (atecc608, tpm2, optee, software); enrollment attestations must match it.
	SeType string `json:"se_type,omitempty"`
	// BootstrapSerial is the canonical serial of the bootstrap certificate
	// issued at the factory; first enrollment must present exactly that cert.
	BootstrapSerial string `json:"bootstrap_serial,omitempty"`
}

// Enrollment is the body of POST /internal/v1/devices/{id}/enrolled
// (API_CONTRACT §1.12): the certificate just issued and the attested
// device properties. The registry transitions the device to active and
// records the certificate.
type Enrollment struct {
	SerialHex      string    `json:"serial_hex"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	SeType         string    `json:"se_type"`
	AssuranceLevel string    `json:"assurance_level"`
	FwVersion      string    `json:"fw_version,omitempty"`
	FwHashHex      string    `json:"fw_hash_hex,omitempty"`
}

var (
	// ErrNotFound is returned when the registry does not know the device.
	ErrNotFound = errors.New("registry: device not found")
	// ErrRejected is returned when the registry refused a request with a
	// non-retryable client error (4xx other than 404/408/429); retrying the
	// same request cannot succeed.
	ErrRejected = errors.New("registry: request rejected")
)

// Client looks up devices and records enrollment results.
type Client interface {
	GetDevice(ctx context.Context, tenantID, deviceID string) (*Device, error)
	RecordAssurance(ctx context.Context, tenantID, deviceID, assurance string) error
	// RecordEnrollment reports an issued certificate so the registry can
	// record it and activate the device. The PKI treats a failure as fatal
	// for the enrollment.
	RecordEnrollment(ctx context.Context, tenantID, deviceID string, e Enrollment) error
}

// Memory is an in-memory Client for tests and single-node development.
type Memory struct {
	mu      sync.RWMutex
	devices map[string]Device
	// Err, when set, is returned by every call (simulates outages).
	Err error
	// EnrollErr, when set, is returned by RecordEnrollment for the next
	// EnrollFailures calls (every call when EnrollFailures is 0).
	EnrollErr      error
	EnrollFailures int

	enrollCalls int
	enrollments map[string][]Enrollment
}

// NewMemory returns an empty in-memory registry.
func NewMemory() *Memory {
	return &Memory{devices: map[string]Device{}, enrollments: map[string][]Enrollment{}}
}

func key(tenantID, deviceID string) string { return tenantID + "/" + deviceID }

// Put inserts or replaces a device.
func (m *Memory) Put(d Device) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[key(d.TenantID, d.DeviceID)] = d
}

// SetState changes a device's state (no-op for unknown devices).
func (m *Memory) SetState(tenantID, deviceID string, s State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.devices[key(tenantID, deviceID)]; ok {
		d.State = s
		m.devices[key(tenantID, deviceID)] = d
	}
}

// GetDevice implements Client.
func (m *Memory) GetDevice(_ context.Context, tenantID, deviceID string) (*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Err != nil {
		return nil, m.Err
	}
	d, ok := m.devices[key(tenantID, deviceID)]
	if !ok {
		return nil, ErrNotFound
	}
	return &d, nil
}

// RecordAssurance implements Client.
func (m *Memory) RecordAssurance(_ context.Context, tenantID, deviceID, assurance string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	d, ok := m.devices[key(tenantID, deviceID)]
	if !ok {
		return ErrNotFound
	}
	d.Assurance = assurance
	m.devices[key(tenantID, deviceID)] = d
	return nil
}

// SetEnrollFailure makes the next n RecordEnrollment calls fail with err
// (n == 0: every call). A nil err clears the failure.
func (m *Memory) SetEnrollFailure(err error, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EnrollErr, m.EnrollFailures = err, n
}

// RecordEnrollment implements Client: it records the enrollment and moves a
// manufactured or provisioned device to active.
func (m *Memory) RecordEnrollment(_ context.Context, tenantID, deviceID string, e Enrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrollCalls++
	if m.Err != nil {
		return m.Err
	}
	if m.EnrollErr != nil {
		err := m.EnrollErr
		if m.EnrollFailures > 0 {
			m.EnrollFailures--
			if m.EnrollFailures == 0 {
				m.EnrollErr = nil
			}
		}
		return err
	}
	k := key(tenantID, deviceID)
	d, ok := m.devices[k]
	if !ok {
		return ErrNotFound
	}
	switch d.State {
	case StateManufactured, StateProvisioned:
		d.State = StateActive
	}
	d.Assurance = e.AssuranceLevel
	m.devices[k] = d
	if m.enrollments == nil {
		m.enrollments = map[string][]Enrollment{}
	}
	m.enrollments[k] = append(m.enrollments[k], e)
	return nil
}

// Enrollments returns the recorded enrollments of a device, oldest first.
func (m *Memory) Enrollments(tenantID, deviceID string) []Enrollment {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Enrollment(nil), m.enrollments[key(tenantID, deviceID)]...)
}

// EnrollCalls returns how many RecordEnrollment calls were made (including
// failed ones).
func (m *Memory) EnrollCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enrollCalls
}

// AllowAll is a development-only client that treats every device as active.
// The server logs a warning when it is in use.
type AllowAll struct{}

// GetDevice implements Client.
func (AllowAll) GetDevice(_ context.Context, tenantID, deviceID string) (*Device, error) {
	return &Device{DeviceID: deviceID, TenantID: tenantID, State: StateActive}, nil
}

// RecordAssurance implements Client.
func (AllowAll) RecordAssurance(context.Context, string, string, string) error { return nil }

// RecordEnrollment implements Client.
func (AllowAll) RecordEnrollment(context.Context, string, string, Enrollment) error { return nil }

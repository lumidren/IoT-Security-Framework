// Package registry is the PKI's client to the Registry service, which owns the
// device lifecycle (DESIGN_CONTRACT §7): manufactured -> provisioned -> active
// -> quarantined -> active | decommissioned. Enrollment is only permitted in
// the first three states.
package registry

import (
	"context"
	"errors"
	"sync"
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

// ErrNotFound is returned when the registry does not know the device.
var ErrNotFound = errors.New("registry: device not found")

// Client looks up devices and records their assurance level.
type Client interface {
	GetDevice(ctx context.Context, tenantID, deviceID string) (*Device, error)
	RecordAssurance(ctx context.Context, tenantID, deviceID, assurance string) error
}

// Memory is an in-memory Client for tests and single-node development.
type Memory struct {
	mu      sync.RWMutex
	devices map[string]Device
	// Err, when set, is returned by every call (simulates outages).
	Err error
}

// NewMemory returns an empty in-memory registry.
func NewMemory() *Memory { return &Memory{devices: map[string]Device{}} }

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

// AllowAll is a development-only client that treats every device as active.
// The server logs a warning when it is in use.
type AllowAll struct{}

// GetDevice implements Client.
func (AllowAll) GetDevice(_ context.Context, tenantID, deviceID string) (*Device, error) {
	return &Device{DeviceID: deviceID, TenantID: tenantID, State: StateActive}, nil
}

// RecordAssurance implements Client.
func (AllowAll) RecordAssurance(context.Context, string, string, string) error { return nil }

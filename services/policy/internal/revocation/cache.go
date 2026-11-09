// Package revocation keeps the in-memory deny list the authn hook consults, fed by signed PKI
// events (fast path) and by polling the Device CA CRL (fallback path). The cache survives restarts
// through a JSON snapshot in POLICY_STATE_DIR.
//
// Two kinds of denial exist. A device-level deny (Entry.DeviceDeny: revoke-all from registry
// quarantine/decommission, reasons keyCompromise and cessationOfOperation, or an explicit
// device_deny event flag) rejects every certificate of the device id. Every other revocation
// (superseded on renewal, a single revoked serial, CRL entries) denies only its serial, which the
// authn hook checks against the certificate presented at CONNECT.
//
// A device release (Release: the registry released a quarantined device) lifts the device-level
// deny: every device-level entry of that device revoked at or before released_at stops applying,
// including such entries that arrive after the release (out-of-order delivery). Serial-level
// denies are never lifted, so the device is admitted again only with a newly enrolled
// certificate, and a later quarantine (revoked_at after the release) denies it again.
package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sources of a revocation entry.
const (
	SourceEvent    = "event"
	SourceCRL      = "crl"
	SnapshotName   = "revocations.json"
	snapshotFormat = 3
)

// Release is an applied device_release event.
type Release struct {
	EventID    string    `json:"event_id"`
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	ReleasedAt time.Time `json:"released_at"`
	AppliedAt  time.Time `json:"applied_at"`
}

// Entry is one revoked certificate (and, when known, the device that held it).
type Entry struct {
	EventID  string `json:"event_id"`
	Serial   string `json:"serial_hex,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// DeviceDeny deny-lists DeviceID itself (all of its certificates); otherwise only Serial is
	// denied.
	DeviceDeny bool       `json:"device_deny"`
	RevokedAt  time.Time  `json:"revoked_at"`
	AppliedAt  time.Time  `json:"applied_at"`
	Source     string     `json:"source"`
	Kicked     bool       `json:"kicked"`
	KickedAt   *time.Time `json:"kicked_at,omitempty"`
	// KickSkipped records that no kick was needed: the live session was known to use a different
	// (current) certificate than the revoked serial.
	KickSkipped bool `json:"kick_skipped,omitempty"`
}

type snapshot struct {
	Format   int       `json:"format"`
	SavedAt  time.Time `json:"saved_at"`
	Entries  []Entry   `json:"entries"`
	Releases []Release `json:"releases,omitempty"`
}

// Cache is a concurrency-safe revocation store indexed by event id, device id and serial.
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]*Entry // by event id
	byDevice map[string]*Entry
	bySerial map[string]*Entry
	releases map[string]*Release  // by event id
	released map[string]time.Time // device id -> latest released_at
	path     string
	now      func() time.Time
}

// NewCache creates a Cache persisted at path (empty disables persistence).
func NewCache(path string, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{
		entries:  make(map[string]*Entry),
		byDevice: make(map[string]*Entry),
		bySerial: make(map[string]*Entry),
		releases: make(map[string]*Release),
		released: make(map[string]time.Time),
		path:     path,
		now:      now,
	}
}

// Path returns the snapshot path ("" when persistence is disabled).
func (c *Cache) Path() string { return c.path }

// Load restores entries from the snapshot file. A missing file is not an error. It returns the
// number of entries restored.
func (c *Cache) Load() (int, error) {
	if c.path == "" {
		return 0, nil
	}
	raw, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("revocation snapshot: read: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return 0, fmt.Errorf("revocation snapshot: decode: %w", err)
	}
	// Format 1 snapshots predate serial-scoped revocations: every entry that named a device
	// deny-listed it. Keep that (fail-closed) meaning for restored entries.
	legacy := snap.Format < 2
	c.mu.Lock()
	defer c.mu.Unlock()
	// Releases first, so device-level entries they lifted are not re-indexed.
	for i := range snap.Releases {
		r := snap.Releases[i]
		if r.EventID == "" || r.DeviceID == "" || r.ReleasedAt.IsZero() {
			continue
		}
		if _, dup := c.releases[r.EventID]; dup {
			continue
		}
		c.indexRelease(&r)
	}
	n := 0
	for i := range snap.Entries {
		e := snap.Entries[i]
		e.Serial = NormalizeSerial(e.Serial)
		if e.EventID == "" || (e.DeviceID == "" && e.Serial == "") {
			continue
		}
		if _, dup := c.entries[e.EventID]; dup {
			continue
		}
		if legacy && e.DeviceID != "" {
			e.DeviceDeny = true
		}
		c.index(&e)
		n++
	}
	return n, nil
}

// Upsert adds e unless an entry with the same event id exists, or e carries only a serial that is
// already known. It returns whether the entry was added; err reports snapshot persistence
// problems (the in-memory state is updated regardless so denials never depend on the disk).
func (c *Cache) Upsert(e Entry) (bool, error) {
	e.Serial = NormalizeSerial(e.Serial)
	if e.EventID == "" {
		return false, errors.New("revocation: entry without event id")
	}
	if e.DeviceID == "" && e.Serial == "" {
		return false, errors.New("revocation: entry needs a device id or a serial")
	}
	if e.Source == "" {
		e.Source = SourceEvent
	}
	if e.AppliedAt.IsZero() {
		e.AppliedAt = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.entries[e.EventID]; dup {
		return false, nil
	}
	if _, dup := c.releases[e.EventID]; dup {
		return false, nil
	}
	if e.DeviceID == "" && e.Serial != "" {
		if _, known := c.bySerial[e.Serial]; known {
			return false, nil
		}
	}
	c.index(&e)
	return true, c.saveLocked()
}

func (c *Cache) index(e *Entry) {
	c.entries[e.EventID] = e
	// A device-level deny revoked at or before the device's latest release no longer applies.
	if e.DeviceID != "" && e.DeviceDeny && e.RevokedAt.After(c.released[e.DeviceID]) {
		if cur, ok := c.byDevice[e.DeviceID]; !ok || !e.RevokedAt.Before(cur.RevokedAt) {
			c.byDevice[e.DeviceID] = e
		}
	}
	if e.Serial != "" {
		if cur, ok := c.bySerial[e.Serial]; !ok || cur.DeviceID == "" {
			c.bySerial[e.Serial] = e
		}
	}
}

// Release applies a device_release event (see the package comment). It returns whether the event
// was new and whether it removed the device's active device-level deny; err reports snapshot
// persistence problems (the in-memory state is updated regardless).
func (c *Cache) Release(r Release) (added, lifted bool, err error) {
	if r.EventID == "" {
		return false, false, errors.New("revocation: release without event id")
	}
	if r.DeviceID == "" || r.ReleasedAt.IsZero() {
		return false, false, errors.New("revocation: release needs a device id and released_at")
	}
	if r.AppliedAt.IsZero() {
		r.AppliedAt = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.releases[r.EventID]; dup {
		return false, false, nil
	}
	if _, dup := c.entries[r.EventID]; dup {
		return false, false, nil
	}
	lifted = c.indexRelease(&r)
	return true, lifted, c.saveLocked()
}

// indexRelease records r, advances the device's release watermark and drops the device-level deny
// it covers. It reports whether a deny was dropped. The caller holds the write lock.
func (c *Cache) indexRelease(r *Release) bool {
	c.releases[r.EventID] = r
	if r.ReleasedAt.After(c.released[r.DeviceID]) {
		c.released[r.DeviceID] = r.ReleasedAt
	}
	cur, ok := c.byDevice[r.DeviceID]
	if ok && !cur.RevokedAt.After(c.released[r.DeviceID]) {
		delete(c.byDevice, r.DeviceID)
		return true
	}
	return false
}

// ReleasedAt returns the latest released_at applied for the device (zero when never released).
func (c *Cache) ReleasedAt(deviceID string) time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.released[deviceID]
}

// Releases returns a copy of the applied releases, oldest first.
func (c *Cache) Releases() []Release {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.releaseListLocked()
}

func (c *Cache) releaseListLocked() []Release {
	out := make([]Release, 0, len(c.releases))
	for _, r := range c.releases {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReleasedAt.Equal(out[j].ReleasedAt) {
			return out[i].ReleasedAt.Before(out[j].ReleasedAt)
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}

// IsRevokedDevice reports whether the device id itself is deny-listed (a device-level revocation;
// serial-scoped revocations of one of its certificates do not count).
func (c *Cache) IsRevokedDevice(deviceID string) bool {
	if deviceID == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.byDevice[deviceID]
	return ok
}

// IsRevokedSerial reports whether the certificate serial (any hex spelling) has been revoked.
func (c *Cache) IsRevokedSerial(serial string) bool {
	s := NormalizeSerial(serial)
	if s == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.bySerial[s]
	return ok
}

// Get returns the entry for an event id.
func (c *Cache) Get(eventID string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[eventID]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// MarkKicked records that the broker session for the entry's device was terminated.
func (c *Cache) MarkKicked(eventID string) error { return c.markKicked(eventID, false) }

// MarkKickSkipped records that the entry needs no kick (the live session uses another
// certificate); it is not retried.
func (c *Cache) MarkKickSkipped(eventID string) error { return c.markKicked(eventID, true) }

func (c *Cache) markKicked(eventID string, skipped bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[eventID]
	if !ok {
		return fmt.Errorf("revocation: unknown event %q", eventID)
	}
	if e.Kicked {
		return nil
	}
	t := c.now()
	e.Kicked = true
	e.KickedAt = &t
	e.KickSkipped = skipped
	return c.saveLocked()
}

// Unkicked lists entries that name a device whose session has not been kicked yet (restart
// recovery), oldest first.
func (c *Cache) Unkicked() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []Entry
	for _, e := range c.entries {
		if e.DeviceID != "" && !e.Kicked {
			out = append(out, *e)
		}
	}
	sortEntries(out)
	return out
}

// Len returns the number of entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Entries returns a copy of all entries ordered by revoked_at then event id (a stable order for
// cursor pagination).
func (c *Cache) Entries() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Entry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, *e)
	}
	sortEntries(out)
	return out
}

func sortEntries(list []Entry) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].RevokedAt.Equal(list[j].RevokedAt) {
			return list[i].RevokedAt.Before(list[j].RevokedAt)
		}
		return list[i].EventID < list[j].EventID
	})
}

// saveLocked writes the snapshot atomically; the caller holds the write lock.
func (c *Cache) saveLocked() error {
	if c.path == "" {
		return nil
	}
	snap := snapshot{Format: snapshotFormat, SavedAt: c.now(), Entries: make([]Entry, 0, len(c.entries))}
	for _, e := range c.entries {
		snap.Entries = append(snap.Entries, *e)
	}
	sortEntries(snap.Entries)
	snap.Releases = c.releaseListLocked()
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("revocation snapshot: encode: %w", err)
	}
	return writeAtomic(c.path, raw)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("revocation snapshot: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".revocations-*.tmp")
	if err != nil {
		return fmt.Errorf("revocation snapshot: temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("revocation snapshot: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("revocation snapshot: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("revocation snapshot: rename: %w", err)
	}
	return nil
}

// NormalizeSerial canonicalises a certificate serial: lower-case hex without 0x prefix, colons,
// spaces or leading zeros. Non-hex input yields "".
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// SerialFromBigInt renders a certificate serial number in the canonical form used by the cache.
func SerialFromBigInt(n *big.Int) string {
	if n == nil {
		return ""
	}
	return NormalizeSerial(n.Text(16))
}

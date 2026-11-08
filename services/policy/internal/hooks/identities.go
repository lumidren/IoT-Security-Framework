// Package hooks implements the EMQX HTTP authentication and authorization backends.
package hooks

import (
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
)

// IdentityCache remembers the session attributes issued at authn so that authz can fall back to
// them when EMQX does not forward client_attrs (versions before 5.7). Entries outlive the maximum
// session expiry (7 days) by default.
type IdentityCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]identityEntry
}

type identityEntry struct {
	attrs   engine.Attrs
	expires time.Time
}

// NewIdentityCache creates a cache with the given TTL (default 8 days) and size bound
// (default 200000 entries).
func NewIdentityCache(ttl time.Duration, max int, now func() time.Time) *IdentityCache {
	if ttl <= 0 {
		ttl = 8 * 24 * time.Hour
	}
	if max <= 0 {
		max = 200000
	}
	if now == nil {
		now = time.Now
	}
	return &IdentityCache{ttl: ttl, max: max, now: now, entries: make(map[string]identityEntry)}
}

// Put stores attrs for clientID.
func (c *IdentityCache) Put(clientID string, attrs engine.Attrs) {
	if clientID == "" {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		for k, v := range c.entries {
			if !now.Before(v.expires) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < c.max {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[clientID] = identityEntry{attrs: attrs, expires: now.Add(c.ttl)}
}

// Get returns the attributes stored for clientID if present and fresh.
func (c *IdentityCache) Get(clientID string) (engine.Attrs, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[clientID]
	if !ok {
		return engine.Attrs{}, false
	}
	if !c.now().Before(e.expires) {
		delete(c.entries, clientID)
		return engine.Attrs{}, false
	}
	return e.attrs, true
}

// Delete forgets clientID.
func (c *IdentityCache) Delete(clientID string) {
	c.mu.Lock()
	delete(c.entries, clientID)
	c.mu.Unlock()
}

// Len returns the number of stored identities.
func (c *IdentityCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

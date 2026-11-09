package mgmt

import (
	"sync"
	"time"
)

// DefaultReplayCacheSize bounds a ReplayCache created with size <= 0.
const DefaultReplayCacheSize = 100000

// ReplayCache remembers accepted JWT ids until the token can no longer be
// valid (exp + ClockLeeway), so a captured service token is accepted once per
// service instance (THREAT_MODEL T-50). It is bounded: when full, expired
// entries are dropped first and then the oldest entries are evicted.
type ReplayCache struct {
	mu    sync.Mutex
	max   int
	seen  map[string]time.Time // key -> forget after
	order []replayEntry        // insertion order
	head  int
}

type replayEntry struct {
	key     string
	expires time.Time
}

// NewReplayCache returns a cache holding at most size ids.
func NewReplayCache(size int) *ReplayCache {
	if size <= 0 {
		size = DefaultReplayCacheSize
	}
	return &ReplayCache{max: size, seen: map[string]time.Time{}}
}

// Use records key until expires and reports whether it was unused. A key
// whose previous use has expired counts as unused.
func (c *ReplayCache) Use(key string, expires, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.seen[key]; ok && now.Before(until) {
		return false
	}
	c.purge(now)
	for len(c.seen) >= c.max && c.head < len(c.order) {
		c.pop()
	}
	c.seen[key] = expires
	c.order = append(c.order, replayEntry{key: key, expires: expires})
	return true
}

// Len returns the number of remembered ids.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// purge drops expired (or superseded) entries from the front of the
// insertion order and compacts the backing slice.
func (c *ReplayCache) purge(now time.Time) {
	for c.head < len(c.order) {
		e := c.order[c.head]
		if until, ok := c.seen[e.key]; ok && until.Equal(e.expires) && now.Before(until) {
			break
		}
		c.pop()
	}
	if c.head > 1024 && c.head*2 > len(c.order) {
		c.order = append([]replayEntry(nil), c.order[c.head:]...)
		c.head = 0
	}
}

// pop removes the oldest entry (and its key, if the entry is still current).
func (c *ReplayCache) pop() {
	e := c.order[c.head]
	c.order[c.head] = replayEntry{}
	c.head++
	if until, ok := c.seen[e.key]; ok && until.Equal(e.expires) {
		delete(c.seen, e.key)
	}
}

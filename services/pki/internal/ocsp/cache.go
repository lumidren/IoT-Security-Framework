package ocsp

import (
	"crypto/x509/pkix"
	"sync"
	"time"
)

type pkixAlgorithmIdentifier = pkix.AlgorithmIdentifier

type cachedResponse struct {
	der       []byte
	status    string
	expiresAt time.Time
	serial    string
}

// cache is a small TTL cache of nonce-less responses keyed by certID.
type cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]cachedResponse
	// bySerial indexes cache keys per serial so revocations can evict every
	// hash-algorithm variant at once.
	bySerial map[string]map[string]struct{}
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, entries: map[string]cachedResponse{}, bySerial: map[string]map[string]struct{}{}}
}

func (c *cache) get(key, serial string, now time.Time) (cachedResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return cachedResponse{}, false
	}
	if !now.Before(e.expiresAt) {
		c.remove(key, serial)
		return cachedResponse{}, false
	}
	return e, true
}

func (c *cache) put(key, serial string, resp cachedResponse, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp.expiresAt = now.Add(c.ttl)
	resp.serial = serial
	c.entries[key] = resp
	keys := c.bySerial[serial]
	if keys == nil {
		keys = map[string]struct{}{}
		c.bySerial[serial] = keys
	}
	keys[key] = struct{}{}
	// Opportunistic expiry sweep keeps the map bounded under churn.
	if len(c.entries) > 10000 {
		for k, e := range c.entries {
			if !now.Before(e.expiresAt) {
				c.remove(k, e.serial)
			}
		}
	}
}

func (c *cache) invalidate(serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.bySerial[serial] {
		delete(c.entries, key)
	}
	delete(c.bySerial, serial)
}

// remove must be called with the lock held.
func (c *cache) remove(key, serial string) {
	delete(c.entries, key)
	if keys := c.bySerial[serial]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(c.bySerial, serial)
		}
	}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

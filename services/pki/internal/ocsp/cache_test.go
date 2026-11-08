package ocsp

import (
	"fmt"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	t.Parallel()
	now := time.Now()
	c := newCache(time.Minute)
	if _, ok := c.get("k", "1", now); ok {
		t.Fatal("empty cache hit")
	}
	c.put("k-sha1", "1", cachedResponse{der: []byte{1}, status: "good"}, now)
	c.put("k-sha256", "1", cachedResponse{der: []byte{2}, status: "good"}, now)
	c.put("other", "2", cachedResponse{der: []byte{3}, status: "revoked"}, now)
	if r, ok := c.get("k-sha1", "1", now.Add(30*time.Second)); !ok || r.der[0] != 1 {
		t.Fatal("expected hit")
	}
	if _, ok := c.get("k-sha1", "1", now.Add(2*time.Minute)); ok {
		t.Fatal("expired entry served")
	}
	if c.len() != 2 {
		t.Fatalf("len %d after expiry removal", c.len())
	}
	c.invalidate("1")
	if _, ok := c.get("k-sha256", "1", now); ok {
		t.Fatal("invalidated entry served")
	}
	if _, ok := c.get("other", "2", now); !ok {
		t.Fatal("unrelated serial was invalidated")
	}
	c.invalidate("missing")
	// The sweep removes expired entries once the map grows large.
	for i := 0; i < 10001; i++ {
		c.put(fmt.Sprintf("e%d", i), fmt.Sprintf("s%d", i), cachedResponse{der: []byte{1}}, now.Add(-2*time.Minute))
	}
	c.put("fresh", "fresh", cachedResponse{der: []byte{1}}, now)
	if c.len() > 2 {
		t.Fatalf("sweep did not run: %d entries", c.len())
	}
}

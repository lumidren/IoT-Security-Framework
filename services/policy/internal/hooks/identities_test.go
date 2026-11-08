package hooks

import (
	"sync"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
)

func TestIdentityCache(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	c := NewIdentityCache(time.Minute, 2, clock)
	attrs := engine.Attrs{TenantID: "t", DeviceID: "dev-8f3a1c2b9d4e5f60", Kind: "device"}
	c.Put("", attrs)
	if c.Len() != 0 {
		t.Fatal("empty client id must be ignored")
	}
	c.Put("a", attrs)
	if got, ok := c.Get("a"); !ok || got != attrs {
		t.Fatalf("Get(a) = %+v, %v", got, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Fatal("Get(missing) should be false")
	}
	advance(61 * time.Second)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry must not be returned")
	}
	if c.Len() != 0 {
		t.Fatal("expired entry should be dropped on read")
	}

	c.Put("a", attrs)
	c.Put("b", attrs)
	c.Put("c", attrs)
	if c.Len() > 2 {
		t.Fatalf("Len = %d, want <= 2 (bounded)", c.Len())
	}
	advance(2 * time.Minute)
	c.Put("d", attrs) // expired entries are purged first
	if _, ok := c.Get("d"); !ok {
		t.Fatal("new entry missing after purge")
	}
	c.Delete("d")
	if _, ok := c.Get("d"); ok {
		t.Fatal("Delete did not remove the entry")
	}

	def := NewIdentityCache(0, 0, nil)
	if def.ttl != 8*24*time.Hour || def.max != 200000 || def.now == nil {
		t.Errorf("defaults = %+v", def)
	}
}

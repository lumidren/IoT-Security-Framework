package est

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimitConfig configures the token buckets guarding the nonce and
// enrollment endpoints. Zero values take the defaults below.
type RateLimitConfig struct {
	// DeviceBurst / DevicePerMinute bound requests per authenticated device.
	DeviceBurst     int
	DevicePerMinute int
	// IPBurst / IPPerMinute bound requests per source IP. Factory floors sit
	// behind NAT, so the IP limits are deliberately generous.
	IPBurst     int
	IPPerMinute int
}

// Default rate limits.
const (
	DefaultDeviceBurst     = 10
	DefaultDevicePerMinute = 30
	DefaultIPBurst         = 300
	DefaultIPPerMinute     = 1200
)

func (c RateLimitConfig) withDefaults() RateLimitConfig {
	if c.DeviceBurst <= 0 {
		c.DeviceBurst = DefaultDeviceBurst
	}
	if c.DevicePerMinute <= 0 {
		c.DevicePerMinute = DefaultDevicePerMinute
	}
	if c.IPBurst <= 0 {
		c.IPBurst = DefaultIPBurst
	}
	if c.IPPerMinute <= 0 {
		c.IPPerMinute = DefaultIPPerMinute
	}
	return c
}

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a keyed token bucket.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	burst   float64
	rate    float64 // tokens per second
}

func newLimiter(burst, perMinute int) *limiter {
	return &limiter{buckets: map[string]*bucket{}, burst: float64(burst), rate: float64(perMinute) / 60}
}

// allow consumes one token for key. When the bucket is empty it reports how
// long the caller must wait for the next token.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= 10000 {
			l.sweep(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// sweep drops buckets that have refilled completely (idle long enough).
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

func (l *limiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// clientIP extracts the source IP of a request (without the port).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimit enforces the per-source-IP bucket and, when deviceID is known,
// the per-device bucket. On exhaustion it answers 429 with Retry-After and
// returns false; callers must stop processing.
func (h *Handler) rateLimit(w http.ResponseWriter, r *http.Request, op, deviceID string) bool {
	now := h.now()
	checks := []struct {
		l   *limiter
		key string
	}{{h.ipLimiter, "ip:" + clientIP(r)}}
	if deviceID != "" {
		checks = append(checks, struct {
			l   *limiter
			key string
		}{h.deviceLimiter, "dev:" + deviceID})
	}
	for _, c := range checks {
		ok, wait := c.l.allow(c.key, now)
		if ok {
			continue
		}
		secs := int(math.Ceil(wait.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		e := &httpError{status: http.StatusTooManyRequests, msg: "rate limit exceeded for " + c.key[:strings_index(c.key)]}
		attrs := []any{"limit_key", c.key, "retry_after_s", secs}
		if deviceID != "" {
			attrs = append(attrs, "device_id", deviceID)
		}
		h.fail(w, r, op, e, attrs...)
		return false
	}
	return true
}

// strings_index returns the length of the key prefix ("ip" or "dev") so the
// error message names the limit class without leaking the keyed value.
func strings_index(key string) int {
	for i, c := range key {
		if c == ':' {
			return i
		}
	}
	return len(key)
}

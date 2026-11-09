package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Dispatcher defaults.
const (
	// DefaultBaseBackoff is the delay after the first failed attempt; it
	// doubles per failure up to DefaultMaxBackoff.
	DefaultBaseBackoff = 500 * time.Millisecond
	// DefaultMaxBackoff caps the retry delay (THREAT_MODEL T-26).
	DefaultMaxBackoff = 30 * time.Second
	// DefaultPollInterval is how often the dispatcher looks for due events.
	DefaultPollInterval = time.Second
	// DefaultAttemptTimeout bounds one delivery attempt (all endpoints).
	DefaultAttemptTimeout = 10 * time.Second
	// DefaultBatchSize bounds the events claimed per poll.
	DefaultBatchSize = 100
)

// ErrInFlight is returned by Attempt when the event is already being
// delivered by this dispatcher.
var ErrInFlight = errors.New("revocation: event delivery already in flight")

// OutboxStore is the part of store.Store the dispatcher needs.
type OutboxStore interface {
	ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*store.OutboxEvent, error)
	RecordOutboxAttempt(ctx context.Context, eventID string, attempts int, next time.Time, lastErr string) error
	AckOutbox(ctx context.Context, eventID string, at time.Time) error
	CountPendingOutbox(ctx context.Context) (int, error)
}

// DispatcherOptions configures a Dispatcher. Zero values take the defaults.
type DispatcherOptions struct {
	Publisher Publisher
	Metrics   *metrics.Metrics
	Logger    *slog.Logger
	Clock     func() time.Time
	// After is the timer used by Run (tests inject a fake).
	After          func(time.Duration) <-chan time.Time
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	PollInterval   time.Duration
	AttemptTimeout time.Duration
	// Lease is how long a claimed event is hidden from other dispatchers
	// (default AttemptTimeout + 5 s).
	Lease     time.Duration
	BatchSize int
}

// Dispatcher delivers the revocation outbox: every pending event is
// published until the Publisher reports that all Policy endpoints
// acknowledged it, with exponential backoff (BaseBackoff doubling, capped at
// MaxBackoff) between attempts. Pending rows survive restarts because they
// live in the store.
type Dispatcher struct {
	store OutboxStore
	opts  DispatcherOptions
	wake  chan struct{}

	mu       sync.Mutex
	inflight map[string]bool
}

// NewDispatcher returns a dispatcher over st.
func NewDispatcher(st OutboxStore, opts DispatcherOptions) *Dispatcher {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Publisher == nil {
		opts.Publisher = NoopPublisher{Logger: opts.Logger}
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.After == nil {
		opts.After = time.After
	}
	if opts.BaseBackoff <= 0 {
		opts.BaseBackoff = DefaultBaseBackoff
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = DefaultMaxBackoff
	}
	if opts.MaxBackoff < opts.BaseBackoff {
		opts.MaxBackoff = opts.BaseBackoff
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.AttemptTimeout <= 0 {
		opts.AttemptTimeout = DefaultAttemptTimeout
	}
	if opts.Lease <= 0 {
		opts.Lease = opts.AttemptTimeout + 5*time.Second
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}
	return &Dispatcher{store: st, opts: opts, wake: make(chan struct{}, 1), inflight: map[string]bool{}}
}

// Lease returns how long a freshly written or claimed event is reserved for
// the dispatcher that holds it.
func (d *Dispatcher) Lease() time.Duration { return d.opts.Lease }

// Backoff returns the delay after the given number of failed attempts
// (>= 1): BaseBackoff * 2^(attempts-1), capped at MaxBackoff.
func (d *Dispatcher) Backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	delay := d.opts.BaseBackoff
	for i := 1; i < attempts; i++ {
		delay *= 2
		if delay >= d.opts.MaxBackoff {
			return d.opts.MaxBackoff
		}
	}
	if delay > d.opts.MaxBackoff {
		return d.opts.MaxBackoff
	}
	return delay
}

// Notify wakes Run for an immediate pass.
func (d *Dispatcher) Notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Attempt delivers one outbox event once. On success the event is
// acknowledged in the store and the end-to-end latency (CreatedAt -> ack) is
// observed; on failure the attempt is recorded with the next retry time.
// The returned error is the delivery error (or ErrInFlight).
func (d *Dispatcher) Attempt(ctx context.Context, ev *store.OutboxEvent) error {
	d.mu.Lock()
	if d.inflight[ev.EventID] {
		d.mu.Unlock()
		return ErrInFlight
	}
	d.inflight[ev.EventID] = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.inflight, ev.EventID)
		d.mu.Unlock()
	}()

	log := d.opts.Logger.With("event_id", ev.EventID, "tenant_id", ev.TenantID, "attempt", ev.Attempts+1)
	var event Event
	err := json.Unmarshal(ev.Payload, &event)
	if err == nil {
		actx, cancel := context.WithTimeout(ctx, d.opts.AttemptTimeout)
		start := d.opts.Clock()
		err = d.opts.Publisher.Publish(actx, event)
		cancel()
		d.opts.Metrics.RevocationPublishLatency.Observe(d.opts.Clock().Sub(start).Seconds())
	} else {
		err = fmt.Errorf("revocation: undecodable outbox payload: %w", err)
	}
	// Bookkeeping must not depend on the caller's (request) context.
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := d.opts.Clock()
	if err != nil {
		attempts := ev.Attempts + 1
		next := now.Add(d.Backoff(attempts))
		d.opts.Metrics.RevocationPublishAttempts.WithLabelValues("error").Inc()
		d.opts.Metrics.RevocationPublishFailures.Inc()
		if rerr := d.store.RecordOutboxAttempt(bctx, ev.EventID, attempts, next, truncate(err.Error(), 1024)); rerr != nil {
			log.Error("cannot record revocation delivery attempt", "error", rerr.Error())
		}
		log.Warn("revocation event delivery failed; will retry", "error", err.Error(), "retry_at", next)
		return err
	}
	d.opts.Metrics.RevocationPublishAttempts.WithLabelValues("ok").Inc()
	if aerr := d.store.AckOutbox(bctx, ev.EventID, now); aerr != nil {
		// The row stays pending and is delivered again later; the Policy
		// service deduplicates by event_id.
		log.Error("cannot acknowledge delivered revocation event", "error", aerr.Error())
	}
	total := now.Sub(ev.CreatedAt)
	d.opts.Metrics.RevocationLatency.Observe(total.Seconds())
	log.Info("revocation event delivered", "total_ms", total.Milliseconds())
	return nil
}

// ProcessDue claims every due event and attempts it once. It returns the
// number delivered.
func (d *Dispatcher) ProcessDue(ctx context.Context) (int, error) {
	defer d.RefreshPending(ctx)
	evs, err := d.store.ClaimOutbox(ctx, d.opts.Clock(), d.opts.Lease, d.opts.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("revocation: claim outbox: %w", err)
	}
	delivered := 0
	for _, ev := range evs {
		if ctx.Err() != nil {
			return delivered, ctx.Err()
		}
		if d.Attempt(ctx, ev) == nil {
			delivered++
		}
	}
	return delivered, nil
}

// RefreshPending updates ironmesh_revocation_outbox_pending.
func (d *Dispatcher) RefreshPending(ctx context.Context) {
	n, err := d.store.CountPendingOutbox(context.WithoutCancel(ctx))
	if err != nil {
		d.opts.Logger.Error("cannot count pending revocation events", "error", err.Error())
		return
	}
	d.opts.Metrics.RevocationOutboxPending.Set(float64(n))
}

// Run processes the outbox every PollInterval (or when notified) until ctx
// ends. Events pending from before a restart are picked up on the first pass.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		if _, err := d.ProcessDue(ctx); err != nil && ctx.Err() == nil {
			d.opts.Logger.Error("revocation outbox pass failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-d.opts.After(d.opts.PollInterval):
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

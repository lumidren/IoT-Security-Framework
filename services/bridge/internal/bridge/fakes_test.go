package bridge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	tenant   = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	dev      = "dev-8f3a1c2b9d4e5f60"
	otherDev = "dev-0123456789abcdef"
)

var fixedNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newMetrics() *Metrics { return NewMetrics(prometheus.NewRegistry()) }

// fakeProducer records produced records and can fail a configurable number of times or block.
type fakeProducer struct {
	mu       sync.Mutex
	records  []Record
	failures int
	err      error
	block    chan struct{}
	calls    int
}

func (p *fakeProducer) Produce(ctx context.Context, rec Record) error {
	p.mu.Lock()
	p.calls++
	block := p.block
	fail := p.failures > 0
	if fail {
		p.failures--
	}
	err := p.err
	p.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("kafka unavailable")
	}
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.records = append(p.records, rec)
	p.mu.Unlock()
	return nil
}

func (p *fakeProducer) Records() []Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Record(nil), p.records...)
}

func (p *fakeProducer) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// fakeSource hands pre-built messages to the handler and then waits for ctx.
type fakeSource struct {
	messages []*Message
	runErr   error
}

func (s *fakeSource) Run(ctx context.Context, handle Handler) error {
	for _, m := range s.messages {
		handle(ctx, m)
	}
	<-ctx.Done()
	return s.runErr
}

func headerValue(rec Record, key string) (string, bool) {
	for _, h := range rec.Headers {
		if h.Key == key {
			return h.Value, true
		}
	}
	return "", false
}

func testMessage(topic string, props map[string]string, ack func() error) *Message {
	return NewMessage(topic, []byte("cose"), 1, false, props, fixedNow, ack)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

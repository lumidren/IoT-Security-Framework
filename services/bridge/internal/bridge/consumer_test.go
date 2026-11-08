package bridge

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newForwarder(t *testing.T, p Producer, m *Metrics) *Forwarder {
	t.Helper()
	f, err := NewForwarder(ForwarderConfig{Producer: p, IngestTopic: "im.ingest", Metrics: m, Logger: discardLogger(), Clock: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNewConsumerValidation(t *testing.T) {
	m := newMetrics()
	f := newForwarder(t, &fakeProducer{}, m)
	if _, err := NewConsumer(ConsumerConfig{Forwarder: f, Metrics: m}); err == nil {
		t.Error("missing source should fail")
	}
	if _, err := NewConsumer(ConsumerConfig{Source: &fakeSource{}, Metrics: m}); err == nil {
		t.Error("missing forwarder should fail")
	}
	c, err := NewConsumer(ConsumerConfig{Source: &fakeSource{}, Forwarder: f, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	if cap(c.sem) != 1024 || c.retryBase != 100*time.Millisecond || c.retryMax != 5*time.Second || c.log == nil {
		t.Errorf("defaults not applied: %+v", c)
	}
	if c.backoff(1) != 100*time.Millisecond || c.backoff(3) != 400*time.Millisecond || c.backoff(20) != 5*time.Second {
		t.Errorf("backoff = %v %v %v", c.backoff(1), c.backoff(3), c.backoff(20))
	}
}

func TestConsumerForwardsThenAcks(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{}
	var acks atomic.Int32
	var ackedBeforeProduce atomic.Bool
	msg := testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", map[string]string{"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}, func() error {
		if p.Calls() == 0 {
			ackedBeforeProduce.Store(true)
		}
		acks.Add(1)
		return nil
	})
	src := &fakeSource{messages: []*Message{msg}, runErr: errors.New("source closed")}
	c, err := NewConsumer(ConsumerConfig{Source: src, Forwarder: newForwarder(t, p, m), Metrics: m, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	waitFor(t, "ack", func() bool { return acks.Load() == 1 })
	cancel()
	if err := <-done; err == nil || err.Error() != "source closed" {
		t.Errorf("Run returned %v", err)
	}
	if ackedBeforeProduce.Load() {
		t.Fatal("message was acknowledged before Kafka confirmed the write")
	}
	recs := p.Records()
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	if v, _ := headerValue(recs[0], HeaderTraceParent); v != "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01" {
		t.Errorf("traceparent header = %q", v)
	}
	if got := testutil.ToFloat64(m.Messages.WithLabelValues("telemetry")); got != 1 {
		t.Errorf("messages total = %v", got)
	}
	if got := testutil.ToFloat64(m.Inflight); got != 0 {
		t.Errorf("inflight after completion = %v", got)
	}
	if !msg.Acked() {
		t.Error("message should be marked acked")
	}
}

func TestConsumerRetriesUntilKafkaAcks(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{failures: 2}
	var acks atomic.Int32
	msg := testMessage("im/v1/"+tenant+"/"+dev+"/events", nil, func() error { acks.Add(1); return nil })
	c, err := NewConsumer(ConsumerConfig{Source: &fakeSource{messages: []*Message{msg}}, Forwarder: newForwarder(t, p, m), Metrics: m, Logger: discardLogger(), RetryBase: time.Millisecond, RetryMax: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = c.Run(ctx) }()
	waitFor(t, "ack after retries", func() bool { return acks.Load() == 1 })
	cancel()
	if p.Calls() != 3 {
		t.Errorf("produce calls = %d, want 3", p.Calls())
	}
	if got := testutil.ToFloat64(m.ForwardErrors); got != 2 {
		t.Errorf("forward errors = %v, want 2", got)
	}
}

func TestConsumerDropsUnforwardableMessagesWithAck(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{}
	var acks atomic.Int32
	ack := func() error { acks.Add(1); return nil }
	msgs := []*Message{
		testMessage("garbage/topic", nil, ack),
		testMessage("im/v1/"+tenant+"/"+dev+"/cmd/req", nil, ack), // downlink, not ingest
	}
	c, err := NewConsumer(ConsumerConfig{Source: &fakeSource{messages: msgs}, Forwarder: newForwarder(t, p, m), Metrics: m, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = c.Run(ctx) }()
	waitFor(t, "two acks", func() bool { return acks.Load() == 2 })
	cancel()
	if len(p.Records()) != 0 {
		t.Error("dropped messages must not reach Kafka")
	}
	if got := testutil.ToFloat64(m.Dropped.WithLabelValues("invalid_topic")); got != 1 {
		t.Errorf("dropped invalid_topic = %v", got)
	}
	if got := testutil.ToFloat64(m.Dropped.WithLabelValues("downlink")); got != 1 {
		t.Errorf("dropped downlink = %v", got)
	}
}

func TestConsumerAckErrorIsCounted(t *testing.T) {
	m := newMetrics()
	msg := testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", nil, func() error { return errors.New("connection lost") })
	c, err := NewConsumer(ConsumerConfig{Source: &fakeSource{messages: []*Message{msg}}, Forwarder: newForwarder(t, &fakeProducer{}, m), Metrics: m, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = c.Run(ctx) }()
	waitFor(t, "ack error", func() bool { return testutil.ToFloat64(m.AckErrors) == 1 })
	cancel()
}

func TestConsumerLeavesMessageUnackedOnShutdown(t *testing.T) {
	m := newMetrics()
	p := &fakeProducer{err: errors.New("kafka down for good")}
	var acks atomic.Int32
	msg := testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", nil, func() error { acks.Add(1); return nil })
	c, err := NewConsumer(ConsumerConfig{Source: &fakeSource{messages: []*Message{msg}}, Forwarder: newForwarder(t, p, m), Metrics: m, Logger: discardLogger(), RetryBase: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	waitFor(t, "retries", func() bool { return p.Calls() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if acks.Load() != 0 || msg.Acked() {
		t.Error("a message that never reached Kafka must stay unacknowledged")
	}
}

func TestConsumerBoundsInflight(t *testing.T) {
	m := newMetrics()
	release := make(chan struct{})
	p := &fakeProducer{block: release}
	msgs := make([]*Message, 3)
	var acks atomic.Int32
	for i := range msgs {
		msgs[i] = testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", nil, func() error { acks.Add(1); return nil })
	}
	c, err := NewConsumer(ConsumerConfig{Source: &fakeSource{}, Forwarder: newForwarder(t, p, m), Metrics: m, Logger: discardLogger(), MaxInflight: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.handle(ctx, msgs[0])
	c.handle(ctx, msgs[1])
	waitFor(t, "two inflight", func() bool { return testutil.ToFloat64(m.Inflight) == 2 })

	third := make(chan struct{})
	go func() { c.handle(ctx, msgs[2]); close(third) }()
	select {
	case <-third:
		t.Fatal("third message was admitted above the in-flight bound")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-third:
	case <-time.After(3 * time.Second):
		t.Fatal("third message never admitted after capacity freed")
	}
	waitFor(t, "all acks", func() bool { return acks.Load() == 3 })
	c.wg.Wait()
	if got := testutil.ToFloat64(m.Inflight); got != 0 {
		t.Errorf("inflight = %v", got)
	}

	// handle gives up acquiring a slot once the context is cancelled.
	full, fullCancel := context.WithCancel(context.Background())
	blocked := &fakeProducer{block: make(chan struct{})}
	c2, _ := NewConsumer(ConsumerConfig{Source: &fakeSource{}, Forwarder: newForwarder(t, blocked, m), Metrics: m, Logger: discardLogger(), MaxInflight: 1})
	c2.handle(full, testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", nil, nil))
	fullCancel()
	done := make(chan struct{})
	go func() { c2.handle(full, testMessage("im/v1/"+tenant+"/"+dev+"/telemetry", nil, nil)); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handle should return once ctx is cancelled")
	}
	c2.wg.Wait()
}

func TestMessageAckIdempotentAndNil(t *testing.T) {
	calls := 0
	msg := NewMessage("t", nil, 1, false, nil, fixedNow, func() error { calls++; return nil })
	if err := msg.Ack(); err != nil {
		t.Fatal(err)
	}
	if err := msg.Ack(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !msg.Acked() {
		t.Errorf("ack calls = %d acked=%v", calls, msg.Acked())
	}
	if err := NewMessage("t", nil, 0, false, nil, fixedNow, nil).Ack(); err != nil {
		t.Errorf("nil ack should be a no-op: %v", err)
	}
}

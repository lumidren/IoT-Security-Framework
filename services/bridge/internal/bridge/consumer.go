package bridge

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Message is one inbound MQTT PUBLISH together with its acknowledgement.
type Message struct {
	Topic          string
	Payload        []byte
	QoS            byte
	Retain         bool
	UserProperties map[string]string
	ReceivedAt     time.Time

	ack   func() error
	acked atomic.Bool
}

// NewMessage builds a Message; ack may be nil (QoS 0 or test messages).
func NewMessage(topic string, payload []byte, qos byte, retain bool, props map[string]string, receivedAt time.Time, ack func() error) *Message {
	return &Message{Topic: topic, Payload: payload, QoS: qos, Retain: retain, UserProperties: props, ReceivedAt: receivedAt, ack: ack}
}

// Ack acknowledges the message to the broker exactly once.
func (m *Message) Ack() error {
	if !m.acked.CompareAndSwap(false, true) || m.ack == nil {
		return nil
	}
	return m.ack()
}

// Acked reports whether Ack has been called.
func (m *Message) Acked() bool { return m.acked.Load() }

// Handler receives inbound messages.
type Handler func(ctx context.Context, msg *Message)

// Source delivers MQTT messages to a Handler until ctx is cancelled. *MQTTSource is the
// production implementation; tests supply fakes.
type Source interface {
	Run(ctx context.Context, handle Handler) error
}

// ConsumerConfig configures a Consumer.
type ConsumerConfig struct {
	Source    Source
	Forwarder *Forwarder
	// MaxInflight bounds messages between receipt and acknowledgement (default 1024).
	MaxInflight int
	Metrics     *Metrics
	Logger      *slog.Logger
	// RetryBase / RetryMax shape the exponential backoff between failed forward attempts
	// (defaults 100ms / 5s).
	RetryBase time.Duration
	RetryMax  time.Duration
}

// Consumer pulls messages from a Source, forwards each one and acknowledges it only after the
// Kafka broker confirmed the write (at-least-once). In-flight work is bounded by a semaphore.
type Consumer struct {
	source    Source
	forwarder *Forwarder
	sem       chan struct{}
	metrics   *Metrics
	log       *slog.Logger
	retryBase time.Duration
	retryMax  time.Duration
	wg        sync.WaitGroup
}

// NewConsumer validates cfg and returns a Consumer.
func NewConsumer(cfg ConsumerConfig) (*Consumer, error) {
	if cfg.Source == nil || cfg.Forwarder == nil || cfg.Metrics == nil {
		return nil, errors.New("consumer: source, forwarder and metrics are required")
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 1024
	}
	c := &Consumer{
		source:    cfg.Source,
		forwarder: cfg.Forwarder,
		sem:       make(chan struct{}, cfg.MaxInflight),
		metrics:   cfg.Metrics,
		log:       cfg.Logger,
		retryBase: cfg.RetryBase,
		retryMax:  cfg.RetryMax,
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.retryBase <= 0 {
		c.retryBase = 100 * time.Millisecond
	}
	if c.retryMax <= 0 {
		c.retryMax = 5 * time.Second
	}
	return c, nil
}

// Run consumes until ctx is cancelled, then waits for in-flight messages to finish.
func (c *Consumer) Run(ctx context.Context) error {
	err := c.source.Run(ctx, c.handle)
	c.wg.Wait()
	return err
}

// handle is invoked by the Source for every message. It blocks while the in-flight bound is
// reached, which back-pressures the MQTT receive loop.
func (c *Consumer) handle(ctx context.Context, msg *Message) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	c.metrics.Inflight.Inc()
	c.wg.Add(1)
	go func() {
		defer func() {
			<-c.sem
			c.metrics.Inflight.Dec()
			c.wg.Done()
		}()
		c.process(ctx, msg)
	}()
}

func (c *Consumer) process(ctx context.Context, msg *Message) {
	for attempt := 1; ; attempt++ {
		err := c.forwarder.Forward(ctx, msg)
		if err == nil || errors.Is(err, ErrDrop) {
			if err != nil {
				c.log.Debug("message dropped", "topic", msg.Topic, "reason", err.Error())
			}
			if ackErr := msg.Ack(); ackErr != nil {
				c.metrics.AckErrors.Inc()
				c.log.Warn("mqtt ack failed; broker will redeliver", "topic", msg.Topic, "err", ackErr.Error())
			}
			return
		}
		delay := c.backoff(attempt)
		c.log.Warn("forward failed; retrying", "topic", msg.Topic, "attempt", attempt, "retry_in", delay.String(), "err", err.Error())
		select {
		case <-ctx.Done():
			c.log.Info("shutting down with message unacknowledged; broker will redeliver", "topic", msg.Topic)
			return
		case <-time.After(delay):
		}
	}
}

func (c *Consumer) backoff(attempt int) time.Duration {
	d := c.retryBase
	for i := 1; i < attempt && d < c.retryMax; i++ {
		d *= 2
	}
	if d > c.retryMax {
		d = c.retryMax
	}
	return d
}

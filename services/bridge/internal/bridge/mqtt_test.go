package bridge

import (
	"context"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/packets"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeBroker is a minimal MQTT 5 server: it accepts one client, answers CONNECT/SUBSCRIBE/PINGREQ
// and records the PUBACKs it receives.
type fakeBroker struct {
	t        *testing.T
	ln       net.Listener
	subs     chan string
	acks     chan uint16
	ready    chan net.Conn
	closed   chan struct{}
	mu       sync.Mutex
	conn     net.Conn
	sessPres bool
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{t: t, ln: ln, subs: make(chan string, 8), acks: make(chan uint16, 64), ready: make(chan net.Conn, 1), closed: make(chan struct{})}
	go b.serve()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *fakeBroker) serve() {
	raw, err := b.ln.Accept()
	if err != nil {
		return
	}
	conn := packets.NewThreadSafeConn(raw)
	b.mu.Lock()
	b.conn = conn
	b.mu.Unlock()
	defer func() {
		raw.Close()
		close(b.closed)
	}()
	for {
		cp, err := packets.ReadPacket(conn)
		if err != nil {
			return
		}
		switch p := cp.Content.(type) {
		case *packets.Connect:
			ca := packets.NewControlPacket(packets.CONNACK)
			ack := ca.Content.(*packets.Connack)
			ack.ReasonCode = 0
			ack.SessionPresent = b.sessPres
			ack.Properties = &packets.Properties{}
			if _, err := ca.WriteTo(conn); err != nil {
				return
			}
			b.ready <- conn
		case *packets.Subscribe:
			sa := packets.NewControlPacket(packets.SUBACK)
			s := sa.Content.(*packets.Suback)
			s.PacketID = p.PacketID
			s.Properties = &packets.Properties{}
			for _, sub := range p.Subscriptions {
				b.subs <- sub.Topic
				s.Reasons = append(s.Reasons, 1)
			}
			if _, err := sa.WriteTo(conn); err != nil {
				return
			}
		case *packets.Puback:
			b.acks <- p.PacketID
		case *packets.Pingreq:
			if _, err := packets.NewControlPacket(packets.PINGRESP).WriteTo(conn); err != nil {
				return
			}
		case *packets.Disconnect:
			return
		}
	}
}

func (b *fakeBroker) publish(topic string, payload []byte, pid uint16, user []packets.User) {
	b.t.Helper()
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()
	pub := packets.NewControlPacket(packets.PUBLISH)
	p := pub.Content.(*packets.Publish)
	p.Topic = topic
	p.Payload = payload
	p.QoS = 1
	p.PacketID = pid
	p.Properties = &packets.Properties{User: user}
	if _, err := pub.WriteTo(conn); err != nil {
		b.t.Fatalf("broker publish: %v", err)
	}
}

func dialer(addr string) func(context.Context, autopaho.ClientConfig, *url.URL) (net.Conn, error) {
	return func(ctx context.Context, _ autopaho.ClientConfig, _ *url.URL) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func TestNewMQTTSourceValidation(t *testing.T) {
	u, _ := url.Parse("ssl://emqx:8883")
	if _, err := NewMQTTSource(MQTTConfig{ClientID: "svc-bridge", TopicFilter: "x"}); err == nil {
		t.Error("missing URL should fail")
	}
	if _, err := NewMQTTSource(MQTTConfig{ServerURL: u, TopicFilter: "x"}); err == nil {
		t.Error("missing client id should fail")
	}
	if _, err := NewMQTTSource(MQTTConfig{ServerURL: u, ClientID: "svc-bridge"}); err == nil {
		t.Error("missing filter should fail")
	}
	s, err := NewMQTTSource(MQTTConfig{ServerURL: u, ClientID: "svc-bridge", TopicFilter: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.KeepAlive != 60 || s.cfg.SessionExpiry != 7*24*3600 || s.cfg.ReceiveMaximum != 1024 || s.cfg.ConnectRetryDelay != 2*time.Second || s.cfg.ConnectTimeout != 10*time.Second || s.log == nil || s.now == nil {
		t.Errorf("defaults not applied: %+v", s.cfg)
	}
	if s.Connected() {
		t.Error("should start disconnected")
	}
}

func TestMQTTSourceEndToEnd(t *testing.T) {
	broker := newFakeBroker(t)
	m := newMetrics()
	u, _ := url.Parse("mqtt://" + broker.ln.Addr().String())
	src, err := NewMQTTSource(MQTTConfig{
		ServerURL:         u,
		ClientID:          "svc-bridge",
		TopicFilter:       "$share/bridge/im/v1/#",
		ReceiveMaximum:    32,
		ConnectRetryDelay: 50 * time.Millisecond,
		ConnectTimeout:    5 * time.Second,
		AttemptConnection: dialer(broker.ln.Addr().String()),
		Logger:            discardLogger(),
		Metrics:           m,
		Clock:             func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}

	received := make(chan *Message, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, func(_ context.Context, msg *Message) { received <- msg })
	}()

	select {
	case <-broker.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("client never connected")
	}
	select {
	case filter := <-broker.subs:
		if filter != "$share/bridge/im/v1/#" {
			t.Errorf("subscribed to %q", filter)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never subscribed")
	}
	waitFor(t, "connected flag", src.Connected)
	if got := testutil.ToFloat64(m.MQTTConnected); got != 1 {
		t.Errorf("mqtt connected gauge = %v", got)
	}

	topic := "im/v1/" + tenant + "/" + dev + "/telemetry"
	broker.publish(topic, []byte("cose-bytes"), 7, []packets.User{{Key: "traceparent", Value: traceparent}})
	broker.publish(topic, []byte("second"), 8, nil)

	var first, second *Message
	for i := 0; i < 2; i++ {
		select {
		case msg := <-received:
			if string(msg.Payload) == "cose-bytes" {
				first = msg
			} else {
				second = msg
			}
		case <-time.After(5 * time.Second):
			t.Fatal("message not delivered to handler")
		}
	}
	if first == nil || second == nil {
		t.Fatal("did not receive both messages")
	}
	if first.Topic != topic || first.QoS != 1 || first.Retain || !first.ReceivedAt.Equal(fixedNow) || first.UserProperties["traceparent"] != traceparent {
		t.Errorf("first message = %+v", first)
	}
	if second.UserProperties != nil {
		t.Errorf("second message should have no user properties: %v", second.UserProperties)
	}

	// Nothing is acknowledged until the handler decides so.
	select {
	case pid := <-broker.acks:
		t.Fatalf("unexpected early PUBACK for %d", pid)
	case <-time.After(100 * time.Millisecond):
	}
	// Acking the second message first exercises in-order delivery of acks: paho holds it back
	// until the first is acknowledged.
	if err := second.Ack(); err != nil {
		t.Fatal(err)
	}
	select {
	case pid := <-broker.acks:
		t.Fatalf("PUBACK %d sent before the earlier message was acknowledged", pid)
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Ack(); err != nil {
		t.Fatal(err)
	}
	var acked []uint16
	for len(acked) < 2 {
		select {
		case pid := <-broker.acks:
			acked = append(acked, pid)
		case <-time.After(5 * time.Second):
			t.Fatalf("expected two PUBACKs, got %v", acked)
		}
	}
	if acked[0] != 7 || acked[1] != 8 {
		t.Errorf("PUBACK order = %v, want [7 8]", acked)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if src.Connected() {
		t.Error("should be disconnected after Run returns")
	}
	select {
	case <-broker.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("broker connection was not closed")
	}
}

func TestMQTTSourceRunStopsWhileBrokerUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	u, _ := url.Parse("mqtt://" + addr)
	src, err := NewMQTTSource(MQTTConfig{ServerURL: u, ClientID: "svc-bridge", TopicFilter: "im/v1/#", ConnectRetryDelay: 20 * time.Millisecond, ConnectTimeout: 200 * time.Millisecond, AttemptConnection: dialer(addr), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := src.Run(ctx, func(context.Context, *Message) {}); err != nil {
		t.Errorf("Run returned %v", err)
	}
	if src.Connected() {
		t.Error("never connected, must report disconnected")
	}
}

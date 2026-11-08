package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// MQTTConfig configures the paho.golang (MQTT 5) Source.
type MQTTConfig struct {
	ServerURL   *url.URL
	ClientID    string
	TopicFilter string
	TLS         *tls.Config
	// KeepAlive in seconds (default 60).
	KeepAlive uint16
	// SessionExpiry in seconds (default 7 days).
	SessionExpiry uint32
	// ReceiveMaximum advertised in CONNECT; should match the consumer's in-flight bound.
	ReceiveMaximum    uint16
	ConnectRetryDelay time.Duration
	ConnectTimeout    time.Duration
	// AttemptConnection overrides how the network connection is established (tests).
	AttemptConnection func(context.Context, autopaho.ClientConfig, *url.URL) (net.Conn, error)
	Logger            *slog.Logger
	Metrics           *Metrics
	Clock             func() time.Time
}

// MQTTSource subscribes to the shared subscription as svc-bridge with manual acknowledgements.
type MQTTSource struct {
	cfg       MQTTConfig
	connected atomic.Bool
	now       func() time.Time
	log       *slog.Logger
}

// NewMQTTSource validates cfg and returns the Source.
func NewMQTTSource(cfg MQTTConfig) (*MQTTSource, error) {
	if cfg.ServerURL == nil {
		return nil, errors.New("mqtt: server URL is required")
	}
	if cfg.ClientID == "" || cfg.TopicFilter == "" {
		return nil, errors.New("mqtt: client id and topic filter are required")
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 60
	}
	if cfg.SessionExpiry == 0 {
		cfg.SessionExpiry = 7 * 24 * 3600
	}
	if cfg.ReceiveMaximum == 0 {
		cfg.ReceiveMaximum = 1024
	}
	if cfg.ConnectRetryDelay <= 0 {
		cfg.ConnectRetryDelay = 2 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	s := &MQTTSource{cfg: cfg, now: cfg.Clock, log: cfg.Logger}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// Connected reports whether a broker session is currently up.
func (s *MQTTSource) Connected() bool { return s.connected.Load() }

// Run connects (retrying forever), subscribes on every (re)connection and dispatches PUBLISH
// packets to handle until ctx is cancelled. Messages are acknowledged only through Message.Ack.
func (s *MQTTSource) Run(ctx context.Context, handle Handler) error {
	cfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{s.cfg.ServerURL},
		TlsCfg:                        s.cfg.TLS,
		KeepAlive:                     s.cfg.KeepAlive,
		CleanStartOnInitialConnection: false,
		SessionExpiryInterval:         s.cfg.SessionExpiry,
		ConnectRetryDelay:             s.cfg.ConnectRetryDelay,
		ConnectTimeout:                s.cfg.ConnectTimeout,
		AttemptConnection:             s.cfg.AttemptConnection,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, ca *paho.Connack) {
			s.setConnected(true)
			s.log.Info("mqtt connected", "session_present", ca.SessionPresent, "server", s.cfg.ServerURL.Host)
			go s.subscribe(ctx, cm)
		},
		OnConnectionDown: func() bool {
			s.setConnected(false)
			s.log.Warn("mqtt connection lost; reconnecting")
			return true
		},
		OnConnectError: func(err error) {
			s.log.Warn("mqtt connect attempt failed", "err", err.Error())
		},
		ClientConfig: paho.ClientConfig{
			ClientID:                   s.cfg.ClientID,
			EnableManualAcknowledgment: true,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					s.onPublish(ctx, handle, pr)
					return true, nil
				},
			},
			OnClientError: func(err error) {
				s.log.Warn("mqtt client error", "err", err.Error())
			},
			OnServerDisconnect: func(d *paho.Disconnect) {
				reason := ""
				if d.Properties != nil {
					reason = d.Properties.ReasonString
				}
				s.log.Warn("mqtt server disconnect", "reason_code", d.ReasonCode, "reason", reason)
			},
		},
	}
	cfg.ConnectPacketBuilder = func(c *paho.Connect, _ *url.URL) (*paho.Connect, error) {
		if c.Properties == nil {
			c.Properties = &paho.ConnectProperties{}
		}
		rm := s.cfg.ReceiveMaximum
		c.Properties.ReceiveMaximum = &rm
		return c, nil
	}

	cm, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		return fmt.Errorf("mqtt: start connection manager: %w", err)
	}
	select {
	case <-ctx.Done():
	case <-cm.Done():
	}
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = cm.Disconnect(dctx)
	select {
	case <-cm.Done():
	case <-dctx.Done():
	}
	s.setConnected(false)
	return nil
}

func (s *MQTTSource) setConnected(up bool) {
	s.connected.Store(up)
	if s.cfg.Metrics != nil {
		if up {
			s.cfg.Metrics.MQTTConnected.Set(1)
		} else {
			s.cfg.Metrics.MQTTConnected.Set(0)
		}
	}
}

func (s *MQTTSource) subscribe(ctx context.Context, cm *autopaho.ConnectionManager) {
	sctx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
	defer cancel()
	suback, err := cm.Subscribe(sctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{Topic: s.cfg.TopicFilter, QoS: 1}},
	})
	if err != nil {
		s.log.Error("mqtt subscribe failed", "filter", s.cfg.TopicFilter, "err", err.Error())
		return
	}
	for _, reason := range suback.Reasons {
		if reason >= 0x80 {
			s.log.Error("mqtt subscription rejected by broker", "filter", s.cfg.TopicFilter, "reason_code", reason)
			return
		}
	}
	s.log.Info("mqtt subscribed", "filter", s.cfg.TopicFilter)
}

func (s *MQTTSource) onPublish(ctx context.Context, handle Handler, pr paho.PublishReceived) {
	pkt := pr.Packet
	var props map[string]string
	if pkt.Properties != nil && len(pkt.Properties.User) > 0 {
		props = make(map[string]string, len(pkt.Properties.User))
		for _, u := range pkt.Properties.User {
			props[u.Key] = u.Value
		}
	}
	client := pr.Client
	ack := func() error {
		if pkt.QoS == 0 || client == nil {
			return nil
		}
		return client.Ack(pkt)
	}
	handle(ctx, NewMessage(pkt.Topic, pkt.Payload, pkt.QoS, pkt.Retain, props, s.now(), ack))
}

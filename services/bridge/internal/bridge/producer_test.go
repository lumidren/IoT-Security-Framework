package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
)

func TestNewKafkaProducerValidation(t *testing.T) {
	if _, err := NewKafkaProducer(KafkaConfig{}); err == nil {
		t.Error("no brokers should fail")
	}
}

func TestKafkaProducerRoundTrip(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "im.ingest"))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	p, err := NewKafkaProducer(KafkaConfig{Brokers: cluster.ListenAddrs(), ClientID: "bridge-test", Logger: discardLogger(), Linger: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	rec := Record{
		Topic:     "im.ingest",
		Key:       []byte(tenant + "/" + dev),
		Value:     []byte("payload"),
		Timestamp: fixedNow,
		Headers:   []Header{{Key: "mqtt_topic", Value: "im/v1/t/d/telemetry"}, {Key: "traceparent", Value: "00-aa-bb-01"}},
	}
	if err := p.Produce(ctx, rec); err != nil {
		t.Fatalf("Produce: %v", err)
	}

	consumer, err := kgo.NewClient(kgo.SeedBrokers(cluster.ListenAddrs()...), kgo.ConsumeTopics("im.ingest"), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	fetches := consumer.PollFetches(ctx)
	if errs := fetches.Errors(); len(errs) > 0 {
		t.Fatalf("fetch errors: %v", errs)
	}
	var got []*kgo.Record
	fetches.EachRecord(func(r *kgo.Record) { got = append(got, r) })
	if len(got) != 1 {
		t.Fatalf("fetched %d records, want 1", len(got))
	}
	r := got[0]
	if string(r.Key) != tenant+"/"+dev || string(r.Value) != "payload" || len(r.Headers) != 2 {
		t.Errorf("record = key:%s value:%s headers:%d", r.Key, r.Value, len(r.Headers))
	}
	if r.Headers[1].Key != "traceparent" || string(r.Headers[1].Value) != "00-aa-bb-01" {
		t.Errorf("headers = %+v", r.Headers)
	}
	if r.Timestamp.Before(time.Now().Add(-time.Minute)) {
		t.Errorf("timestamp = %v, want produce time", r.Timestamp)
	}
}

func TestKafkaProducerErrors(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "im.ingest"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewKafkaProducer(KafkaConfig{Brokers: cluster.ListenAddrs(), DeliveryTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Produce(cancelled, Record{Topic: "im.ingest", Value: []byte("x")}); err == nil {
		t.Error("cancelled context should fail the produce")
	}
	cluster.Close()
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if err := p.Produce(ctx, Record{Topic: "im.ingest", Value: []byte("x")}); err == nil {
		t.Error("produce against a closed cluster should fail")
	}
}

func TestSlogKgoLogger(t *testing.T) {
	l := &slogKgoLogger{log: discardLogger()}
	if l.Level() != kgo.LogLevelInfo {
		t.Errorf("Level = %v", l.Level())
	}
	for _, lvl := range []kgo.LogLevel{kgo.LogLevelError, kgo.LogLevelWarn, kgo.LogLevelInfo, kgo.LogLevelDebug} {
		l.Log(lvl, "msg", "k", "v")
	}
}

package bridge

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newEventsHandler(t *testing.T, p Producer, token string) (*EventsHandler, *Metrics) {
	t.Helper()
	m := newMetrics()
	h, err := NewEventsHandler(EventsConfig{Producer: p, Token: token, Metrics: m, Logger: discardLogger(), Clock: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	return h, m
}

func postEvents(h http.Handler, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/emqx/events", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewEventsHandlerValidation(t *testing.T) {
	if _, err := NewEventsHandler(EventsConfig{Metrics: newMetrics()}); err == nil {
		t.Error("missing producer should fail")
	}
	if _, err := NewEventsHandler(EventsConfig{Producer: &fakeProducer{}}); err == nil {
		t.Error("missing metrics should fail")
	}
	h, err := NewEventsHandler(EventsConfig{Producer: &fakeProducer{}, Metrics: newMetrics()})
	if err != nil {
		t.Fatal(err)
	}
	if h.topic != "im.auth" || h.maxBody != 1<<20 || h.log == nil || h.now == nil {
		t.Errorf("defaults not applied: %+v", h)
	}
}

func TestEventsAuthAndMethod(t *testing.T) {
	h, _ := newEventsHandler(t, &fakeProducer{}, "secret")
	req := httptest.NewRequest(http.MethodGet, "/emqx/events", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", rec.Code)
	}
	if rec := postEvents(h, `{"event":"client.connected","clientid":"`+dev+`"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token = %d", rec.Code)
	}
	if rec := postEvents(h, `{"event":"client.connected","clientid":"`+dev+`"}`, "wrong"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d", rec.Code)
	}
	if rec := postEvents(h, `{"event":"client.connected","clientid":"`+dev+`"}`, "secret"); rec.Code != http.StatusOK {
		t.Errorf("good token = %d %s", rec.Code, rec.Body.String())
	}
}

func TestEventsNormalizationAndForwarding(t *testing.T) {
	p := &fakeProducer{}
	h, m := newEventsHandler(t, p, "")
	body := `[
	 {"event":"client.connected","clientid":"` + dev + `","username":"` + dev + `","peername":"10.1.2.3:51234","timestamp":1762171200000,"node":"emqx@n1","client_attrs":{"tenant_id":"` + tenant + `"}},
	 {"event":"client.check_authn_complete","clientid":"dev-ffffffffffffffff","peername":"10.1.2.4:1","reason_code":"not_authorized"},
	 {"event":"client.check_authn_complete","clientid":"` + dev + `","reason_code":"success"},
	 {"event":"client.check_authz_complete","clientid":"` + dev + `","topic":"im/v1/x/y/telemetry","action":"publish","result":"deny","peerhost":"10.1.2.3"},
	 {"event":"client.check_authz_complete","clientid":"` + dev + `","topic":"t","action":"publish","result":"allow"},
	 {"event":"client.authenticate failed","clientid":"svc-rogue","reason":"bad cert"},
	 {"event":"client.authorize denied","clientid":"` + otherDev + `","topic":"$SYS/#","action":"subscribe"},
	 {"event":"client.authenticate","clientid":"` + otherDev + `","result":"deny"},
	 {"event":"session.subscribed","clientid":"` + dev + `"},
	 {"event":"client.connected","clientid":""},
	 {"event":"client.disconnected","clientid":"` + dev + `","reason":"normal","peername":"[::1]:5"}
	]`
	rec := postEvents(h, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var summary map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["accepted"] != 7 || summary["ignored"] != 4 {
		t.Errorf("summary = %v", summary)
	}
	recs := p.Records()
	if len(recs) != 7 {
		t.Fatalf("records = %d", len(recs))
	}
	var first AuthEvent
	if err := json.Unmarshal(recs[0].Value, &first); err != nil {
		t.Fatal(err)
	}
	if first.Event != EventConnected || first.ClientID != dev || first.PeerHost != "10.1.2.3" || first.DeviceID != dev || first.TenantID != tenant || first.Node != "emqx@n1" || !first.At.Equal(time.UnixMilli(1762171200000).UTC()) {
		t.Errorf("first = %+v", first)
	}
	if recs[0].Topic != "im.auth" || string(recs[0].Key) != dev {
		t.Errorf("record = topic:%s key:%s", recs[0].Topic, recs[0].Key)
	}
	for _, k := range []string{"event", "clientid", HeaderReceivedAt, HeaderDeviceID, HeaderTenantID} {
		if _, ok := headerValue(recs[0], k); !ok {
			t.Errorf("header %s missing", k)
		}
	}
	kinds := make([]string, 0, len(recs))
	for _, r := range recs {
		var ev AuthEvent
		_ = json.Unmarshal(r.Value, &ev)
		kinds = append(kinds, ev.Event)
	}
	want := []string{EventConnected, EventAuthnFailed, EventAuthzDenied, EventAuthnFailed, EventAuthzDenied, EventAuthnFailed, EventDisconnected}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
	var authz AuthEvent
	_ = json.Unmarshal(recs[2].Value, &authz)
	if authz.Topic != "im/v1/x/y/telemetry" || authz.Action != "publish" || authz.PeerHost != "10.1.2.3" || !authz.At.Equal(fixedNow) {
		t.Errorf("authz event = %+v", authz)
	}
	var authn AuthEvent
	_ = json.Unmarshal(recs[1].Value, &authn)
	if authn.Reason != "not_authorized" || authn.PeerHost != "10.1.2.4" {
		t.Errorf("authn event = %+v", authn)
	}
	var disc AuthEvent
	_ = json.Unmarshal(recs[6].Value, &disc)
	if disc.PeerHost != "::1" || disc.Reason != "normal" {
		t.Errorf("disconnect event = %+v", disc)
	}
	if got := testutil.ToFloat64(m.AuthEvents.WithLabelValues(EventAuthnFailed)); got != 3 {
		t.Errorf("authn_failed counter = %v", got)
	}
	if got := testutil.ToFloat64(m.AuthEvents.WithLabelValues("ignored")); got != 4 {
		t.Errorf("ignored counter = %v", got)
	}
	// connected then disconnected: gauge back to zero.
	if got := testutil.ToFloat64(m.ConnectedDevices); got != 0 || h.ConnectedDevices() != 0 {
		t.Errorf("connected devices = %v / %d", got, h.ConnectedDevices())
	}
}

func TestEventsConnectedGauge(t *testing.T) {
	h, m := newEventsHandler(t, &fakeProducer{}, "")
	postEvents(h, `{"event":"client.connected","clientid":"`+dev+`"}`, "")
	postEvents(h, `{"event":"client.connected","clientid":"`+dev+`"}`, "") // duplicate connect counts once
	postEvents(h, `{"event":"client.connected","clientid":"`+otherDev+`"}`, "")
	postEvents(h, `{"event":"client.connected","clientid":"svc-bridge"}`, "") // services are not devices
	if got := testutil.ToFloat64(m.ConnectedDevices); got != 2 {
		t.Errorf("connected = %v, want 2", got)
	}
	postEvents(h, `{"event":"client.disconnected","clientid":"`+dev+`"}`, "")
	postEvents(h, `{"event":"client.disconnected","clientid":"`+dev+`"}`, "") // never below zero
	if got := testutil.ToFloat64(m.ConnectedDevices); got != 1 {
		t.Errorf("connected after disconnects = %v, want 1", got)
	}
}

func TestEventsBodyErrorsAndProducerFailure(t *testing.T) {
	p := &fakeProducer{}
	h, _ := newEventsHandler(t, p, "")
	if rec := postEvents(h, `{bad json`, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json = %d", rec.Code)
	}
	if rec := postEvents(h, `[{"event":1}]`, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad array = %d", rec.Code)
	}
	if rec := postEvents(h, `   `, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty = %d", rec.Code)
	}
	small, _ := NewEventsHandler(EventsConfig{Producer: p, Metrics: newMetrics(), MaxBodyBytes: 10})
	if rec := postEvents(small, `{"event":"client.connected","clientid":"`+dev+`"}`, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized = %d", rec.Code)
	}
	failing, _ := newEventsHandler(t, &fakeProducer{err: errors.New("kafka down")}, "")
	if rec := postEvents(failing, `{"event":"client.connected","clientid":"`+dev+`"}`, ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("producer failure = %d", rec.Code)
	}
}

func TestEventsHookTokenHeader(t *testing.T) {
	h, _ := newEventsHandler(t, &fakeProducer{}, "secret")
	post := func(headers map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, "/emqx/events", strings.NewReader(`{"event":"client.connected","clientid":"`+dev+`"}`))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := post(map[string]string{HeaderHookToken: "secret"}); c != http.StatusOK {
		t.Errorf("hook token header = %d", c)
	}
	if c := post(map[string]string{HeaderHookToken: "wrong"}); c != http.StatusUnauthorized {
		t.Errorf("wrong hook token = %d", c)
	}
	// A wrong hook token is not rescued by a valid bearer token.
	if c := post(map[string]string{HeaderHookToken: "wrong", "Authorization": "Bearer secret"}); c != http.StatusUnauthorized {
		t.Errorf("wrong hook token + bearer = %d", c)
	}
}

// TestEventsEMQXRuleEnginePayloads feeds the bodies the EMQX 5.8 HTTP action produces for the
// rule in deploy/emqx/emqx.conf (SELECT * from the four $events topics, empty body template, so
// the whole event map is posted).
func TestEventsEMQXRuleEnginePayloads(t *testing.T) {
	p := &fakeProducer{}
	h, _ := newEventsHandler(t, p, "secret")
	bodies := []string{
		`{"event":"client.connected","id":"0006","clientid":"` + dev + `","username":"` + dev + `","mountpoint":"undefined","peername":"10.1.2.3:51234","sockname":"0.0.0.0:8883","proto_name":"MQTT","proto_ver":5,"keepalive":60,"clean_start":false,"expiry_interval":604800,"is_bridge":false,"connected_at":1762171200000,"conn_props":{"Session-Expiry-Interval":604800,"User-Property":{}},"receive_maximum":32,"client_attrs":{"tenant_id":"` + tenant + `","device_id":"` + dev + `","kind":"device"},"timestamp":1762171200001,"node":"emqx@127.0.0.1"}`,
		`{"event":"client.disconnected","clientid":"` + dev + `","username":"` + dev + `","reason":"normal","peername":"10.1.2.3:51234","sockname":"0.0.0.0:8883","proto_name":"MQTT","proto_ver":5,"disconnect_props":{},"disconnected_at":1762171260000,"client_attrs":{"tenant_id":"` + tenant + `"},"timestamp":1762171260001,"node":"emqx@127.0.0.1"}`,
		`{"event":"client.check_authn_complete","clientid":"` + otherDev + `","username":"` + otherDev + `","peername":"10.1.2.9:4000","reason_code":"not_authorized","is_anonymous":false,"is_superuser":false,"timestamp":1762171300000,"node":"emqx@127.0.0.1"}`,
		`{"event":"client.check_authz_complete","clientid":"` + dev + `","username":"` + dev + `","peerhost":"10.1.2.3","topic":"im/v1/` + tenant + `/` + otherDev + `/telemetry","action":"publish","authz_source":"http","result":"deny","client_attrs":{"tenant_id":"` + tenant + `"},"timestamp":1762171400000,"node":"emqx@127.0.0.1"}`,
	}
	for _, b := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/emqx/events", strings.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderHookToken, "secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"accepted":1`) {
			t.Fatalf("body %s -> %d %s", b[:40], rec.Code, rec.Body.String())
		}
	}
	recs := p.Records()
	if len(recs) != 4 {
		t.Fatalf("records = %d", len(recs))
	}
	want := []string{EventConnected, EventDisconnected, EventAuthnFailed, EventAuthzDenied}
	for i, r := range recs {
		var ev AuthEvent
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Event != want[i] {
			t.Errorf("record %d event = %s want %s", i, ev.Event, want[i])
		}
	}
}

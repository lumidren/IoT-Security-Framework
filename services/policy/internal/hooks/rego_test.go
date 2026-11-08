package hooks

import (
	"context"
	"strings"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
)

// TestRegoUnitTestsRunFromGo executes policy/rego/mqtt_acl_test.rego with the OPA Go test runner
// (no OPA CLI needed) so the Rego suite is part of `go test`.
func TestRegoUnitTestsRunFromGo(t *testing.T) {
	src, tests, err := engine.EmbeddedSources()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := engine.RunInvariants(context.Background(), src, tests)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Failures) > 0 {
		t.Fatalf("%d Rego tests failed:\n%s", len(rep.Failures), strings.Join(rep.Failures, "\n"))
	}
	if rep.Total < 45 {
		t.Errorf("expected >= 45 Rego tests, got %d", rep.Total)
	}
}

// TestPolicyTable drives every contract rule through the production authz path (identity
// resolution, decision cache, OPA evaluation) exactly as EMQX would.
func TestPolicyTable(t *testing.T) {
	env := newAuthzEnv(t, nil, nil)
	ctx := context.Background()

	deviceAttrs := engine.Attrs{TenantID: tenant, DeviceID: dev, Kind: "device"}
	serviceAttrs := engine.Attrs{Kind: "service"}
	req := func(client string, attrs engine.Attrs, action, topic string, qos int, retain bool) AuthzRequest {
		return AuthzRequest{ClientID: client, Username: client, Topic: topic, Action: action, QoS: FlexInt(qos), Retain: FlexBool(retain), ClientAttrs: attrs}
	}
	other := func(class string) string { return "im/v1/" + tenant + "/" + otherDev + "/" + class }
	foreign := func(class string) string { return "im/v1/" + otherTenant + "/" + dev + "/" + class }

	cases := []struct {
		name  string
		req   AuthzRequest
		allow bool
	}{
		// --- device publish ---
		{"device publish telemetry", req(dev, deviceAttrs, "publish", own("telemetry"), 1, false), true},
		{"device publish events", req(dev, deviceAttrs, "publish", own("events"), 1, false), true},
		{"device publish shadow/reported", req(dev, deviceAttrs, "publish", own("shadow/reported"), 1, false), true},
		{"device publish cmd/ack", req(dev, deviceAttrs, "publish", own("cmd/ack"), 1, false), true},
		{"device publish ota/status", req(dev, deviceAttrs, "publish", own("ota/status"), 0, false), true},
		{"device publish other device", req(dev, deviceAttrs, "publish", other("telemetry"), 1, false), false},
		{"device publish other tenant", req(dev, deviceAttrs, "publish", foreign("telemetry"), 1, false), false},
		{"device publish retained telemetry", req(dev, deviceAttrs, "publish", own("telemetry"), 1, true), false},
		{"device publish qos2", req(dev, deviceAttrs, "publish", own("telemetry"), 2, false), false},
		{"device publish to shadow/desired", req(dev, deviceAttrs, "publish", own("shadow/desired"), 1, false), false},
		{"device publish to cmd/req", req(dev, deviceAttrs, "publish", own("cmd/req"), 1, false), false},
		{"device publish to config", req(dev, deviceAttrs, "publish", own("config"), 1, false), false},
		{"device publish unknown class", req(dev, deviceAttrs, "publish", own("debug"), 1, false), false},
		{"device publish extra segment", req(dev, deviceAttrs, "publish", own("telemetry/extra"), 1, false), false},
		{"device publish wrong version", req(dev, deviceAttrs, "publish", "im/v2/"+tenant+"/"+dev+"/telemetry", 1, false), false},
		{"device publish leading slash", req(dev, deviceAttrs, "publish", "/"+own("telemetry"), 1, false), false},
		{"device publish trailing slash", req(dev, deviceAttrs, "publish", own("telemetry")+"/", 1, false), false},
		{"device publish uppercase class", req(dev, deviceAttrs, "publish", own("TELEMETRY"), 1, false), false},
		{"device publish $SYS", req(dev, deviceAttrs, "publish", "$SYS/brokers", 1, false), false},
		{"device publish wildcard", req(dev, deviceAttrs, "publish", "im/v1/"+tenant+"/+/telemetry", 1, false), false},
		{"device publish empty topic", req(dev, deviceAttrs, "publish", "", 1, false), false},
		// --- device subscribe ---
		{"device subscribe shadow/desired", req(dev, deviceAttrs, "subscribe", own("shadow/desired"), 1, false), true},
		{"device subscribe cmd/req", req(dev, deviceAttrs, "subscribe", own("cmd/req"), 1, false), true},
		{"device subscribe ota/notify", req(dev, deviceAttrs, "subscribe", own("ota/notify"), 1, false), true},
		{"device subscribe config", req(dev, deviceAttrs, "subscribe", own("config"), 0, false), true},
		{"device subscribe other device cmd/req", req(dev, deviceAttrs, "subscribe", other("cmd/req"), 1, false), false},
		{"device subscribe other tenant", req(dev, deviceAttrs, "subscribe", foreign("cmd/req"), 1, false), false},
		{"device subscribe own telemetry", req(dev, deviceAttrs, "subscribe", own("telemetry"), 1, false), false},
		{"device subscribe hash wildcard", req(dev, deviceAttrs, "subscribe", "im/v1/"+tenant+"/"+dev+"/#", 1, false), false},
		{"device subscribe plus wildcard", req(dev, deviceAttrs, "subscribe", "im/v1/"+tenant+"/"+dev+"/cmd/+", 1, false), false},
		{"device subscribe root wildcard", req(dev, deviceAttrs, "subscribe", "#", 1, false), false},
		{"device subscribe shared", req(dev, deviceAttrs, "subscribe", "$share/bridge/im/v1/#", 1, false), false},
		{"device subscribe $SYS", req(dev, deviceAttrs, "subscribe", "$SYS/#", 1, false), false},
		{"device subscribe qos2", req(dev, deviceAttrs, "subscribe", own("cmd/req"), 2, false), false},
		// --- identity edge cases ---
		{"device attrs for other client", req(otherDev, deviceAttrs, "publish", own("telemetry"), 1, false), false},
		{"device claiming service kind", req(dev, engine.Attrs{TenantID: tenant, DeviceID: dev, Kind: "service"}, "subscribe", "$share/bridge/im/v1/#", 1, false), false},
		{"unknown kind", req(dev, engine.Attrs{TenantID: tenant, DeviceID: dev, Kind: "admin"}, "publish", own("telemetry"), 1, false), false},
		{"missing attrs", req(dev, engine.Attrs{}, "publish", own("telemetry"), 1, false), false},
		{"bad action", req(dev, deviceAttrs, "read", own("telemetry"), 1, false), false},
		// --- bridge ---
		{"bridge shared subscription", req("svc-bridge", serviceAttrs, "subscribe", "$share/bridge/im/v1/#", 1, false), true},
		{"bridge bare filter (prefix stripped by EMQX)", req("svc-bridge", serviceAttrs, "subscribe", "im/v1/#", 1, false), true},
		{"bridge other group", req("svc-bridge", serviceAttrs, "subscribe", "$share/other/im/v1/#", 1, false), false},
		{"bridge narrower filter", req("svc-bridge", serviceAttrs, "subscribe", "$share/bridge/im/v1/+/+/telemetry", 1, false), false},
		{"bridge publish", req("svc-bridge", serviceAttrs, "publish", own("cmd/req"), 1, false), false},
		{"bridge qos2", req("svc-bridge", serviceAttrs, "subscribe", "$share/bridge/im/v1/#", 2, false), false},
		{"bridge $SYS", req("svc-bridge", serviceAttrs, "subscribe", "$SYS/#", 1, false), false},
		// --- registry ---
		{"registry publish cmd/req", req("svc-registry", serviceAttrs, "publish", own("cmd/req"), 1, false), true},
		{"registry publish other tenant device", req("svc-registry", serviceAttrs, "publish", "im/v1/"+otherTenant+"/"+otherDev+"/shadow/desired", 1, false), true},
		{"registry publish retained config", req("svc-registry", serviceAttrs, "publish", own("config"), 1, true), true},
		{"registry publish retained shadow/desired", req("svc-registry", serviceAttrs, "publish", own("shadow/desired"), 1, true), true},
		{"registry publish retained ota/notify", req("svc-registry", serviceAttrs, "publish", own("ota/notify"), 1, true), true},
		{"registry publish retained cmd/req", req("svc-registry", serviceAttrs, "publish", own("cmd/req"), 1, true), false},
		{"registry publish telemetry", req("svc-registry", serviceAttrs, "publish", own("telemetry"), 1, false), false},
		{"registry publish wildcard", req("svc-registry", serviceAttrs, "publish", "im/v1/+/+/cmd/req", 1, false), false},
		{"registry publish bad device id", req("svc-registry", serviceAttrs, "publish", "im/v1/"+tenant+"/dev-xyz/cmd/req", 1, false), false},
		{"registry publish bad tenant", req("svc-registry", serviceAttrs, "publish", "im/v1/tenant/"+dev+"/cmd/req", 1, false), false},
		{"registry publish qos2", req("svc-registry", serviceAttrs, "publish", own("cmd/req"), 2, false), false},
		{"registry subscribe", req("svc-registry", serviceAttrs, "subscribe", "im/v1/#", 1, false), false},
		{"registry $SYS", req("svc-registry", serviceAttrs, "publish", "$SYS/brokers", 1, false), false},
		{"unknown service", req("svc-other", serviceAttrs, "subscribe", "$share/bridge/im/v1/#", 1, false), false},
	}
	if len(cases) < 40 {
		t.Fatalf("table has %d cases, want >= 40", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := env.authz.Decide(ctx, tc.req)
			if got != tc.allow {
				t.Fatalf("allow = %v (reason %s), want %v", got, reason, tc.allow)
			}
		})
	}
}

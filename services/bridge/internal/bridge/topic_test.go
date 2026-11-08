package bridge

import (
	"errors"
	"testing"
)

func TestParseTopicValid(t *testing.T) {
	cases := map[string]struct {
		class  Class
		ingest bool
	}{
		"telemetry":       {ClassTelemetry, true},
		"events":          {ClassEvents, true},
		"shadow/reported": {ClassShadowReported, true},
		"cmd/ack":         {ClassCmdAck, true},
		"ota/status":      {ClassOtaStatus, true},
		"shadow/desired":  {ClassShadowDesired, false},
		"cmd/req":         {ClassCmdReq, false},
		"ota/notify":      {ClassOtaNotify, false},
		"config":          {ClassConfig, false},
	}
	for path, want := range cases {
		raw := "im/v1/" + tenant + "/" + dev + "/" + path
		got, err := ParseTopic(raw)
		if err != nil {
			t.Errorf("ParseTopic(%q) error: %v", raw, err)
			continue
		}
		if got.Tenant != tenant || got.Device != dev || got.Class != want.class || got.Raw != raw || got.Ingest() != want.ingest {
			t.Errorf("ParseTopic(%q) = %+v ingest=%v", raw, got, got.Ingest())
		}
		if got.Key() != tenant+"/"+dev {
			t.Errorf("Key = %q", got.Key())
		}
	}
}

func TestParseTopicInvalid(t *testing.T) {
	bad := []string{
		"",
		"im",
		"im/v1",
		"im/v1/" + tenant,
		"im/v1/" + tenant + "/" + dev,
		"im/v1/" + tenant + "/" + dev + "/",
		"im/v1/" + tenant + "/" + dev + "/debug",
		"im/v1/" + tenant + "/" + dev + "/telemetry/extra",
		"im/v1/" + tenant + "/" + dev + "/shadow/reported/x",
		"im/v2/" + tenant + "/" + dev + "/telemetry",
		"IM/v1/" + tenant + "/" + dev + "/telemetry",
		"/im/v1/" + tenant + "/" + dev + "/telemetry",
		"im/v1/not-a-uuid/" + dev + "/telemetry",
		"im/v1/" + tenant + "/dev-XYZ/telemetry",
		"im/v1/" + tenant + "/" + dev + "/TELEMETRY",
		"im/v1/+/" + dev + "/telemetry",
		"im/v1/" + tenant + "/" + dev + "/#",
		"$share/bridge/im/v1/" + tenant + "/" + dev + "/telemetry",
		"$SYS/brokers",
	}
	for _, raw := range bad {
		if _, err := ParseTopic(raw); !errors.Is(err, ErrInvalidTopic) {
			t.Errorf("ParseTopic(%q) = %v, want ErrInvalidTopic", raw, err)
		}
	}
}

func TestIsDeviceID(t *testing.T) {
	if !IsDeviceID(dev) || IsDeviceID("svc-bridge") || IsDeviceID("dev-123") {
		t.Error("IsDeviceID mismatch")
	}
}

package bridge

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Class is the normalised message class carried in the msg_class Kafka header.
type Class string

// Message classes (DESIGN_CONTRACT.md section 4 topic table).
const (
	ClassTelemetry      Class = "telemetry"
	ClassEvents         Class = "events"
	ClassShadowReported Class = "shadow_reported"
	ClassCmdAck         Class = "cmd_ack"
	ClassOtaStatus      Class = "ota_status"
	ClassShadowDesired  Class = "shadow_desired"
	ClassCmdReq         Class = "cmd_req"
	ClassOtaNotify      Class = "ota_notify"
	ClassConfig         Class = "config"
)

var (
	tenantRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	deviceRe = regexp.MustCompile(`^dev-[0-9a-f]{16}$`)

	classByPath = map[string]Class{
		"telemetry":       ClassTelemetry,
		"events":          ClassEvents,
		"shadow/reported": ClassShadowReported,
		"cmd/ack":         ClassCmdAck,
		"ota/status":      ClassOtaStatus,
		"shadow/desired":  ClassShadowDesired,
		"cmd/req":         ClassCmdReq,
		"ota/notify":      ClassOtaNotify,
		"config":          ClassConfig,
	}

	ingestClasses = map[Class]bool{
		ClassTelemetry: true, ClassEvents: true, ClassShadowReported: true, ClassCmdAck: true, ClassOtaStatus: true,
	}
)

// ErrInvalidTopic is returned for anything that is not im/v1/<tenant uuid>/<device id>/<class>.
var ErrInvalidTopic = errors.New("bridge: topic does not match im/v1/<tenant>/<device>/<class>")

// Topic is a parsed IronMesh topic.
type Topic struct {
	Tenant string
	Device string
	Class  Class
	Raw    string
}

// Ingest reports whether the class is device-originated and therefore belongs on im.ingest.
func (t Topic) Ingest() bool { return ingestClasses[t.Class] }

// Key is the Kafka record key: <tenant>/<device>.
func (t Topic) Key() string { return t.Tenant + "/" + t.Device }

// ParseTopic validates and splits a concrete MQTT topic. Wildcards, shared-subscription prefixes,
// unknown classes and malformed ids are rejected.
func ParseTopic(raw string) (Topic, error) {
	parts := strings.Split(raw, "/")
	if len(parts) < 5 || len(parts) > 6 {
		return Topic{}, fmt.Errorf("%w: %q has %d segments", ErrInvalidTopic, raw, len(parts))
	}
	if parts[0] != "im" || parts[1] != "v1" {
		return Topic{}, fmt.Errorf("%w: %q does not start with im/v1", ErrInvalidTopic, raw)
	}
	if !tenantRe.MatchString(parts[2]) {
		return Topic{}, fmt.Errorf("%w: tenant %q is not a UUID", ErrInvalidTopic, parts[2])
	}
	if !deviceRe.MatchString(parts[3]) {
		return Topic{}, fmt.Errorf("%w: device %q is not a device id", ErrInvalidTopic, parts[3])
	}
	class, ok := classByPath[strings.Join(parts[4:], "/")]
	if !ok {
		return Topic{}, fmt.Errorf("%w: unknown class %q", ErrInvalidTopic, strings.Join(parts[4:], "/"))
	}
	return Topic{Tenant: parts[2], Device: parts[3], Class: class, Raw: raw}, nil
}

// IsDeviceID reports whether s is a device id (used to classify EMQX client ids).
func IsDeviceID(s string) bool { return deviceRe.MatchString(s) }

# IronMesh MQTT access-control policy.
#
# This file implements DESIGN_CONTRACT.md section 4 (topic scheme and rules) exactly. It is embedded
# into the policy service binary and evaluated for every EMQX authorization request. Anything that
# is not explicitly allowed below is denied (`default allow := false`).
#
# Input shape (built by internal/hooks/authz.go from the EMQX HTTP authorizer request):
#
#   {
#     "clientid":     "dev-8f3a1c2b9d4e5f60",   # equals the certificate CN (verified at authn)
#     "username":     "dev-8f3a1c2b9d4e5f60",
#     "topic":        "im/v1/<tenant>/<device>/telemetry",
#     "action":       "publish" | "subscribe",
#     "qos":          0 | 1 | 2,
#     "retain":       true | false,
#     "client_attrs": {"tenant_id": "<uuid>", "device_id": "dev-...", "kind": "device" | "service"}
#   }
#
# client_attrs are the attributes the authn hook attached to the session; they are derived from the
# verified client certificate, never from anything the client sent.
package ironmesh.mqtt

default allow := false

# ---------------------------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------------------------

# Device -> cloud topics (devices publish, the bridge consumes).
device_pub_classes := {"telemetry", "events", "shadow/reported", "cmd/ack", "ota/status"}

# Cloud -> device topics (devices subscribe, the registry publishes).
device_sub_classes := {"shadow/desired", "cmd/req", "ota/notify", "config"}

registry_pub_classes := device_sub_classes

# Retained messages are permitted only on these classes.
retain_allowed_classes := {"shadow/desired", "ota/notify", "config"}

all_classes := device_pub_classes | device_sub_classes

tenant_id_pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`

device_id_pattern := `^dev-[0-9a-f]{16}$`

# The shared subscription of the bridge. EMQX strips the `$share/<group>/` prefix before calling
# the authorizer on some versions, so the bare filter is accepted for svc-bridge as well.
bridge_filters := {"$share/bridge/im/v1/#", "im/v1/#"}

# ---------------------------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------------------------

kind := input.client_attrs.kind

action := input.action

qos := to_number(input.qos)

retain if input.retain == true

is_device if {
	kind == "device"
	input.client_attrs.device_id == input.clientid
	regex.match(device_id_pattern, input.clientid)
}

is_bridge if {
	kind == "service"
	input.clientid == "svc-bridge"
}

is_registry if {
	kind == "service"
	input.clientid == "svc-registry"
}

# ---------------------------------------------------------------------------------------------
# Topic parsing
# ---------------------------------------------------------------------------------------------

segments := split(input.topic, "/")

# `topic` is defined only for a concrete, well-formed IronMesh topic:
# im/v1/<tenant uuid>/<device id>/<class>. Wildcards, $SYS, extra or missing segments and
# unknown classes leave it undefined, which denies every rule that depends on it.
topic := {"tenant": segments[2], "device": segments[3], "class": class} if {
	count(segments) >= 5
	count(segments) <= 6
	segments[0] == "im"
	segments[1] == "v1"
	regex.match(tenant_id_pattern, segments[2])
	regex.match(device_id_pattern, segments[3])
	class := concat("/", array.slice(segments, 4, count(segments)))
	class in all_classes
}

sys_topic if startswith(input.topic, "$SYS")

has_wildcard if contains(input.topic, "#")

has_wildcard if contains(input.topic, "+")

owns_topic if {
	topic.tenant == input.client_attrs.tenant_id
	topic.device == input.client_attrs.device_id
}

# ---------------------------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------------------------

# Devices may publish only to their own pub topics, QoS <= 1, never retained.
allow if {
	is_device
	action == "publish"
	owns_topic
	topic.class in device_pub_classes
	qos <= 1
	not retain
}

# Devices may subscribe only to their own sub topics; wildcards never parse into `topic`.
allow if {
	is_device
	action == "subscribe"
	owns_topic
	topic.class in device_sub_classes
	qos <= 1
}

# ---------------------------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------------------------

# svc-bridge may subscribe to the shared subscription and nothing else.
allow if {
	is_bridge
	action == "subscribe"
	input.topic in bridge_filters
	qos <= 1
}

# ---------------------------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------------------------

# svc-registry may publish to the cloud -> device topics of any device; retain only where the
# contract permits it (shadow/desired, ota/notify, config).
allow if {
	is_registry
	action == "publish"
	topic.class in registry_pub_classes
	qos <= 1
	registry_retain_ok
}

registry_retain_ok if not retain

registry_retain_ok if topic.class in retain_allowed_classes

# ---------------------------------------------------------------------------------------------
# Diagnostics (never used for the decision; logged by the policy service)
# ---------------------------------------------------------------------------------------------

reasons contains "sys_topic" if sys_topic

reasons contains "bad_action" if not action in {"publish", "subscribe"}

reasons contains "unknown_identity" if {
	not is_device
	not is_bridge
	not is_registry
}

reasons contains "malformed_topic" if {
	not topic
	not sys_topic
	not input.topic in bridge_filters
}

reasons contains "wildcard" if {
	has_wildcard
	not is_bridge
}

reasons contains "qos_too_high" if qos > 1

reasons contains "retain_not_allowed" if {
	retain
	is_device
}

reasons contains "retain_not_allowed" if {
	retain
	is_registry
	topic
	not topic.class in retain_allowed_classes
}

reasons contains "not_owner" if {
	is_device
	topic
	not owns_topic
}

reasons contains "class_not_allowed" if {
	is_device
	action == "publish"
	topic
	not topic.class in device_pub_classes
}

reasons contains "class_not_allowed" if {
	is_device
	action == "subscribe"
	topic
	not topic.class in device_sub_classes
}

reasons contains "class_not_allowed" if {
	is_registry
	topic
	not topic.class in registry_pub_classes
}

reasons contains "action_not_allowed" if {
	is_bridge
	action != "subscribe"
}

reasons contains "action_not_allowed" if {
	is_registry
	action != "publish"
}

reasons contains "filter_not_allowed" if {
	is_bridge
	action == "subscribe"
	not input.topic in bridge_filters
}

decision := {"allow": allow, "reasons": reasons}

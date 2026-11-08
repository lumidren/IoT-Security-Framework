# OPA unit tests for the IronMesh MQTT ACL (DESIGN_CONTRACT.md section 4).
# Run with `opa test policy/rego` or through `go test ./internal/hooks/...` (rego_test.go).
package ironmesh.mqtt_test

import data.ironmesh.mqtt

tenant := "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"

other_tenant := "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"

dev := "dev-8f3a1c2b9d4e5f60"

other_dev := "dev-0123456789abcdef"

device_attrs := {"tenant_id": tenant, "device_id": dev, "kind": "device"}

service_attrs := {"tenant_id": "", "device_id": "", "kind": "service"}

own(class) := sprintf("im/v1/%s/%s/%s", [tenant, dev, class])

device_req(action, topic, qos, retain) := {
	"clientid": dev,
	"username": dev,
	"topic": topic,
	"action": action,
	"qos": qos,
	"retain": retain,
	"client_attrs": device_attrs,
}

service_req(cn, action, topic, qos, retain) := {
	"clientid": cn,
	"username": cn,
	"topic": topic,
	"action": action,
	"qos": qos,
	"retain": retain,
	"client_attrs": service_attrs,
}

# --- devices: publish -------------------------------------------------------------------------

test_device_publish_own_telemetry_allowed if {
	mqtt.allow with input as device_req("publish", own("telemetry"), 1, false)
}

test_device_publish_all_own_pub_classes_allowed if {
	every class in {"telemetry", "events", "shadow/reported", "cmd/ack", "ota/status"} {
		mqtt.allow with input as device_req("publish", own(class), 1, false)
	}
}

test_device_publish_qos0_allowed if {
	mqtt.allow with input as device_req("publish", own("events"), 0, false)
}

test_device_publish_cross_device_denied if {
	topic := sprintf("im/v1/%s/%s/telemetry", [tenant, other_dev])
	not mqtt.allow with input as device_req("publish", topic, 1, false)
}

test_device_publish_cross_tenant_denied if {
	topic := sprintf("im/v1/%s/%s/telemetry", [other_tenant, dev])
	not mqtt.allow with input as device_req("publish", topic, 1, false)
}

test_device_publish_retain_on_telemetry_denied if {
	not mqtt.allow with input as device_req("publish", own("telemetry"), 1, true)
}

test_device_publish_qos2_denied if {
	not mqtt.allow with input as device_req("publish", own("telemetry"), 2, false)
}

test_device_publish_to_sub_class_denied if {
	every class in {"shadow/desired", "cmd/req", "ota/notify", "config"} {
		not mqtt.allow with input as device_req("publish", own(class), 1, false)
	}
}

test_device_publish_unknown_class_denied if {
	not mqtt.allow with input as device_req("publish", own("debug"), 1, false)
}

test_device_publish_malformed_topic_denied if {
	every topic in {
		"",
		"im",
		"im/v1",
		sprintf("im/v1/%s", [tenant]),
		sprintf("im/v1/%s/%s", [tenant, dev]),
		sprintf("im/v1/%s/%s/", [tenant, dev]),
		sprintf("im/v2/%s/%s/telemetry", [tenant, dev]),
		sprintf("/im/v1/%s/%s/telemetry", [tenant, dev]),
		sprintf("im/v1/%s/%s/telemetry/extra", [tenant, dev]),
		sprintf("im/v1/%s/%s/shadow/reported/extra", [tenant, dev]),
		sprintf("im/v1/%s/%s/TELEMETRY", [tenant, dev]),
		sprintf("IM/v1/%s/%s/telemetry", [tenant, dev]),
		sprintf("im/v1/not-a-uuid/%s/telemetry", [dev]),
		sprintf("im/v1/%s/dev-123/telemetry", [tenant]),
	} {
		not mqtt.allow with input as device_req("publish", topic, 1, false)
	}
}

test_device_publish_sys_denied if {
	not mqtt.allow with input as device_req("publish", "$SYS/brokers", 1, false)
}

test_device_publish_wildcard_denied if {
	not mqtt.allow with input as device_req("publish", sprintf("im/v1/%s/+/telemetry", [tenant]), 1, false)
}

# --- devices: subscribe -----------------------------------------------------------------------

test_device_subscribe_own_cmd_req_allowed if {
	mqtt.allow with input as device_req("subscribe", own("cmd/req"), 1, false)
}

test_device_subscribe_all_own_sub_classes_allowed if {
	every class in {"shadow/desired", "cmd/req", "ota/notify", "config"} {
		mqtt.allow with input as device_req("subscribe", own(class), 1, false)
	}
}

test_device_subscribe_other_device_cmd_req_denied if {
	topic := sprintf("im/v1/%s/%s/cmd/req", [tenant, other_dev])
	not mqtt.allow with input as device_req("subscribe", topic, 1, false)
}

test_device_subscribe_other_tenant_denied if {
	topic := sprintf("im/v1/%s/%s/cmd/req", [other_tenant, dev])
	not mqtt.allow with input as device_req("subscribe", topic, 1, false)
}

test_device_subscribe_wildcard_denied if {
	every topic in {
		sprintf("im/v1/%s/%s/#", [tenant, dev]),
		sprintf("im/v1/%s/%s/+", [tenant, dev]),
		sprintf("im/v1/%s/%s/cmd/+", [tenant, dev]),
		sprintf("im/v1/%s/+/cmd/req", [tenant]),
		"im/v1/#",
		"#",
		"+/+/+/+/+/+",
		"$share/bridge/im/v1/#",
	} {
		not mqtt.allow with input as device_req("subscribe", topic, 1, false)
	}
}

test_device_subscribe_pub_class_denied if {
	not mqtt.allow with input as device_req("subscribe", own("telemetry"), 1, false)
}

test_device_subscribe_qos2_denied if {
	not mqtt.allow with input as device_req("subscribe", own("cmd/req"), 2, false)
}

test_device_subscribe_sys_denied if {
	every topic in {"$SYS/#", "$SYS/brokers/+/clients/#", "$SYS"} {
		not mqtt.allow with input as device_req("subscribe", topic, 1, false)
	}
}

# --- devices: identity edge cases -------------------------------------------------------------

test_device_attrs_mismatch_denied if {
	# client_attrs.device_id must equal the authenticated clientid.
	req := object.union(device_req("publish", own("telemetry"), 1, false), {"clientid": other_dev, "username": other_dev})
	not mqtt.allow with input as req
}

test_device_claiming_service_cn_denied if {
	req := object.union(device_req("subscribe", "$share/bridge/im/v1/#", 1, false), {"clientid": "svc-bridge"})
	not mqtt.allow with input as req
}

test_unknown_kind_denied if {
	req := object.union(device_req("publish", own("telemetry"), 1, false), {"client_attrs": {"tenant_id": tenant, "device_id": dev, "kind": "admin"}})
	not mqtt.allow with input as req
}

test_missing_attrs_denied if {
	not mqtt.allow with input as {"clientid": dev, "topic": own("telemetry"), "action": "publish", "qos": 1, "retain": false}
}

test_bad_action_denied if {
	not mqtt.allow with input as device_req("read", own("telemetry"), 1, false)
}

# --- bridge -----------------------------------------------------------------------------------

test_bridge_shared_subscription_allowed if {
	mqtt.allow with input as service_req("svc-bridge", "subscribe", "$share/bridge/im/v1/#", 1, false)
}

test_bridge_bare_filter_allowed if {
	# EMQX may strip the $share/<group>/ prefix before authorizing.
	mqtt.allow with input as service_req("svc-bridge", "subscribe", "im/v1/#", 1, false)
}

test_bridge_publish_denied if {
	not mqtt.allow with input as service_req("svc-bridge", "publish", own("cmd/req"), 1, false)
	not mqtt.allow with input as service_req("svc-bridge", "publish", own("telemetry"), 1, false)
}

test_bridge_other_filters_denied if {
	every topic in {
		"$share/other/im/v1/#",
		"$share/bridge/im/v1/+/+/telemetry",
		"#",
		"$SYS/#",
		own("telemetry"),
		"im/v2/#",
	} {
		not mqtt.allow with input as service_req("svc-bridge", "subscribe", topic, 1, false)
	}
}

test_bridge_qos2_denied if {
	not mqtt.allow with input as service_req("svc-bridge", "subscribe", "$share/bridge/im/v1/#", 2, false)
}

# --- registry ---------------------------------------------------------------------------------

test_registry_publish_cmd_req_allowed if {
	mqtt.allow with input as service_req("svc-registry", "publish", own("cmd/req"), 1, false)
}

test_registry_publish_any_device_allowed if {
	topic := sprintf("im/v1/%s/%s/shadow/desired", [other_tenant, other_dev])
	mqtt.allow with input as service_req("svc-registry", "publish", topic, 1, false)
}

test_registry_publish_retain_on_config_allowed if {
	mqtt.allow with input as service_req("svc-registry", "publish", own("config"), 1, true)
}

test_registry_publish_retain_on_shadow_desired_and_ota_notify_allowed if {
	mqtt.allow with input as service_req("svc-registry", "publish", own("shadow/desired"), 1, true)
	mqtt.allow with input as service_req("svc-registry", "publish", own("ota/notify"), 1, true)
}

test_registry_publish_retain_on_cmd_req_denied if {
	not mqtt.allow with input as service_req("svc-registry", "publish", own("cmd/req"), 1, true)
}

test_registry_publish_device_pub_class_denied if {
	every class in {"telemetry", "events", "shadow/reported", "cmd/ack", "ota/status"} {
		not mqtt.allow with input as service_req("svc-registry", "publish", own(class), 1, false)
	}
}

test_registry_subscribe_denied if {
	not mqtt.allow with input as service_req("svc-registry", "subscribe", own("telemetry"), 1, false)
	not mqtt.allow with input as service_req("svc-registry", "subscribe", "im/v1/#", 1, false)
}

test_registry_qos2_denied if {
	not mqtt.allow with input as service_req("svc-registry", "publish", own("cmd/req"), 2, false)
}

test_registry_wildcard_publish_denied if {
	not mqtt.allow with input as service_req("svc-registry", "publish", "im/v1/+/+/cmd/req", 1, false)
}

test_registry_malformed_device_denied if {
	not mqtt.allow with input as service_req("svc-registry", "publish", sprintf("im/v1/%s/dev-xyz/cmd/req", [tenant]), 1, false)
	not mqtt.allow with input as service_req("svc-registry", "publish", sprintf("im/v1/tenant/%s/cmd/req", [dev]), 1, false)
}

test_registry_sys_denied if {
	not mqtt.allow with input as service_req("svc-registry", "publish", "$SYS/brokers", 1, false)
}

test_unknown_service_denied if {
	not mqtt.allow with input as service_req("svc-other", "subscribe", "$share/bridge/im/v1/#", 1, false)
	not mqtt.allow with input as service_req("svc-other", "publish", own("cmd/req"), 1, false)
}

# --- diagnostics ------------------------------------------------------------------------------

test_decision_reasons_for_cross_tenant if {
	topic := sprintf("im/v1/%s/%s/telemetry", [other_tenant, dev])
	d := mqtt.decision with input as device_req("publish", topic, 1, false)
	d.allow == false
	"not_owner" in d.reasons
}

test_decision_reasons_for_sys if {
	d := mqtt.decision with input as device_req("subscribe", "$SYS/#", 1, false)
	"sys_topic" in d.reasons
}

test_decision_allow_has_no_reasons if {
	d := mqtt.decision with input as device_req("publish", own("telemetry"), 1, false)
	d.allow == true
	count(d.reasons) == 0
}

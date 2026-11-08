import type { PolicyDocument, PolicyHistoryEntry } from '@/lib/api/schemas';
import { DAY, iso } from './seed';

/** Condensed form of services/policy/policy/rego/mqtt_acl.rego (DESIGN_CONTRACT §4). */
export const POLICY_REGO = `# IronMesh MQTT access-control policy.
#
# Implements DESIGN_CONTRACT.md section 4 (topic scheme and rules). Anything not explicitly
# allowed below is denied (default allow := false).
package ironmesh.mqtt

default allow := false

# Device -> cloud topics (devices publish, the bridge consumes).
device_pub_classes := {"telemetry", "events", "shadow/reported", "cmd/ack", "ota/status"}

# Cloud -> device topics (devices subscribe, the registry publishes).
device_sub_classes := {"shadow/desired", "cmd/req", "ota/notify", "config"}

registry_pub_classes := device_sub_classes

# Retained messages are permitted only on these classes.
retain_allowed_classes := {"shadow/desired", "ota/notify", "config"}

all_classes := device_pub_classes | device_sub_classes

tenant_id_pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

device_id_pattern := "^dev-[0-9a-f]{16}$"

bridge_filters := {"$share/bridge/im/v1/#", "im/v1/#"}

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

segments := split(input.topic, "/")

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

owns_topic if {
	topic.tenant == input.client_attrs.tenant_id
	topic.device == input.client_attrs.device_id
}

# Devices may publish only to their own pub topics, QoS <= 1, never retained.
allow if {
	is_device
	action == "publish"
	owns_topic
	topic.class in device_pub_classes
	qos <= 1
	not retain
}

# Devices may subscribe only to their own sub topics; wildcards never parse into topic.
allow if {
	is_device
	action == "subscribe"
	owns_topic
	topic.class in device_sub_classes
	qos <= 1
}

# svc-bridge may subscribe to the shared subscription and nothing else.
allow if {
	is_bridge
	action == "subscribe"
	input.topic in bridge_filters
	qos <= 1
}

# svc-registry may publish to the cloud -> device topics of any device; retain only where allowed.
allow if {
	is_registry
	action == "publish"
	topic.class in registry_pub_classes
	qos <= 1
	registry_retain_ok
}

registry_retain_ok if not retain

registry_retain_ok if topic.class in retain_allowed_classes
`;

export const POLICY_SHA = '7c9e4a1f0b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b';

export function buildPolicy(now: number): {
  policy: PolicyDocument;
  history: PolicyHistoryEntry[];
} {
  const history: PolicyHistoryEntry[] = [
    {
      version: 7,
      updated_at: iso(now - 4 * DAY),
      updated_by: 'user:owner@acme.example',
      message: 'Deny QoS 2 for devices (contract §4)',
      sha256_hex: POLICY_SHA,
    },
    {
      version: 6,
      updated_at: iso(now - 19 * DAY),
      updated_by: 'user:owner@acme.example',
      message: 'Allow retained ota/notify from svc-registry',
      sha256_hex: '3b1f2e4d5c6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e',
    },
    {
      version: 5,
      updated_at: iso(now - 41 * DAY),
      updated_by: 'user:owner@acme.example',
      message: 'Tighten topic regex to the dev-<16 hex> id format',
      sha256_hex: 'a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeeff',
    },
    {
      version: 4,
      updated_at: iso(now - 90 * DAY),
      updated_by: 'user:platform-admin',
      message: 'Initial tenant policy imported from the embedded default',
      sha256_hex: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    },
  ];
  const policy: PolicyDocument = {
    version: 7,
    updated_at: iso(now - 4 * DAY),
    updated_by: 'user:owner@acme.example',
    rego: POLICY_REGO,
    sha256_hex: POLICY_SHA,
  };
  return { policy, history };
}

export interface EvalInput {
  clientid: string;
  username: string;
  tenant_id: string;
  device_id: string;
  kind: string;
  topic: string;
  action: string;
  qos: number;
  retain: boolean;
}

const DEVICE_PUB = new Set(['telemetry', 'events', 'shadow/reported', 'cmd/ack', 'ota/status']);
const DEVICE_SUB = new Set(['shadow/desired', 'cmd/req', 'ota/notify', 'config']);
const RETAIN_OK = new Set(['shadow/desired', 'ota/notify', 'config']);
const BRIDGE_FILTERS = new Set(['$share/bridge/im/v1/#', 'im/v1/#']);
const TENANT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DEVICE_RE = /^dev-[0-9a-f]{16}$/;

/** TypeScript re-implementation of the policy so dry-runs behave like the real service in demo mode. */
export function evaluatePolicy(input: EvalInput): {
  result: 'allow' | 'deny';
  matched_rules: string[];
  trace: string[];
} {
  const trace: string[] = [];
  const matched: string[] = [];
  const segments = input.topic.split('/');
  let topic: { tenant: string; device: string; cls: string } | null = null;
  if (
    segments.length >= 5 &&
    segments.length <= 6 &&
    segments[0] === 'im' &&
    segments[1] === 'v1' &&
    TENANT_RE.test(segments[2] ?? '') &&
    DEVICE_RE.test(segments[3] ?? '')
  ) {
    const cls = segments.slice(4).join('/');
    if (DEVICE_PUB.has(cls) || DEVICE_SUB.has(cls)) {
      topic = { tenant: segments[2]!, device: segments[3]!, cls };
    }
  }
  trace.push(
    topic
      ? `topic parsed: tenant=${topic.tenant} device=${topic.device} class=${topic.cls}`
      : 'topic undefined: not a well-formed im/v1/<tenant>/<device>/<class> topic',
  );

  const isDevice =
    input.kind === 'device' && input.device_id === input.clientid && DEVICE_RE.test(input.clientid);
  const isBridge = input.kind === 'service' && input.clientid === 'svc-bridge';
  const isRegistry = input.kind === 'service' && input.clientid === 'svc-registry';
  trace.push(`is_device=${isDevice} is_bridge=${isBridge} is_registry=${isRegistry}`);
  const owns = Boolean(
    topic && topic.tenant === input.tenant_id && topic.device === input.device_id,
  );
  if (topic) trace.push(`owns_topic=${owns}`);
  trace.push(`action=${input.action} qos=${input.qos} retain=${input.retain}`);

  if (
    isDevice &&
    input.action === 'publish' &&
    owns &&
    topic &&
    DEVICE_PUB.has(topic.cls) &&
    input.qos <= 1 &&
    !input.retain
  ) {
    matched.push('allow[device_publish_own_topic]');
  }
  if (
    isDevice &&
    input.action === 'subscribe' &&
    owns &&
    topic &&
    DEVICE_SUB.has(topic.cls) &&
    input.qos <= 1
  ) {
    matched.push('allow[device_subscribe_own_topic]');
  }
  if (
    isBridge &&
    input.action === 'subscribe' &&
    BRIDGE_FILTERS.has(input.topic) &&
    input.qos <= 1
  ) {
    matched.push('allow[bridge_shared_subscription]');
  }
  if (
    isRegistry &&
    input.action === 'publish' &&
    topic &&
    DEVICE_SUB.has(topic.cls) &&
    input.qos <= 1 &&
    (!input.retain || RETAIN_OK.has(topic.cls))
  ) {
    matched.push('allow[registry_publish_cloud_to_device]');
  }

  if (matched.length === 0) {
    if (!isDevice && !isBridge && !isRegistry) trace.push('reason: unknown_identity');
    if (!topic && !BRIDGE_FILTERS.has(input.topic)) trace.push('reason: malformed_topic');
    if (topic && isDevice && !owns) trace.push('reason: not_owner');
    if (input.qos > 1) trace.push('reason: qos_too_high');
    if (input.retain && isDevice) trace.push('reason: retain_not_allowed');
    if (topic && isDevice && input.action === 'publish' && !DEVICE_PUB.has(topic.cls))
      trace.push('reason: class_not_allowed');
    if (topic && isDevice && input.action === 'subscribe' && !DEVICE_SUB.has(topic.cls))
      trace.push('reason: class_not_allowed');
    if (/[#+]/.test(input.topic) && !isBridge) trace.push('reason: wildcard');
    trace.push('=> default allow := false');
    return { result: 'deny', matched_rules: [], trace };
  }
  trace.push(`=> allow (${matched.length} rule${matched.length === 1 ? '' : 's'} matched)`);
  return { result: 'allow', matched_rules: matched, trace };
}

export interface CompileDiagnostic {
  line: number;
  col: number;
  message: string;
}

/** Cheap "compiler": catches the mistakes people make in demos (missing package, unbalanced braces, lost default). */
export function compilePolicy(rego: string): CompileDiagnostic[] {
  const diagnostics: CompileDiagnostic[] = [];
  const lines = rego.split('\n');
  if (!/^\s*package\s+ironmesh\.mqtt\s*$/m.test(rego)) {
    diagnostics.push({
      line: 1,
      col: 1,
      message: 'rego_parse_error: expected "package ironmesh.mqtt" declaration',
    });
  }
  let depth = 0;
  lines.forEach((line, index) => {
    let quote: '"' | '`' | null = null;
    for (let col = 0; col < line.length; col += 1) {
      const ch = line[col];
      if (quote) {
        if (ch === '\\' && quote === '"') col += 1;
        else if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === '`') {
        quote = ch;
        continue;
      }
      if (ch === '#') break;
      if (ch === '{') depth += 1;
      if (ch === '}') {
        depth -= 1;
        if (depth < 0) {
          diagnostics.push({
            line: index + 1,
            col: col + 1,
            message: 'rego_parse_error: unexpected "}"',
          });
          depth = 0;
        }
      }
    }
  });
  if (depth > 0) {
    diagnostics.push({
      line: lines.length,
      col: 1,
      message: `rego_parse_error: ${depth} unclosed "{"`,
    });
  }
  if (!/default\s+allow\s*:=\s*false/.test(rego)) {
    diagnostics.push({
      line: 1,
      col: 1,
      message:
        'invariant test failed: test_default_deny (policy must declare "default allow := false")',
    });
  }
  if (/allow\s*:=\s*true/.test(rego)) {
    diagnostics.push({
      line: lines.findIndex((l) => /allow\s*:=\s*true/.test(l)) + 1,
      col: 1,
      message: 'invariant test failed: test_no_unconditional_allow',
    });
  }
  return diagnostics;
}

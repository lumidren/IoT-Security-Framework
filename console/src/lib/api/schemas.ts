/**
 * Zod schemas for every model the console consumes. Hand-derived from docs/API_CONTRACT.md; the
 * field names and enums here are the binding contract and must be kept in sync with that file.
 */
import { z } from 'zod';

// ----------------------------------------------------------------------------------------------
// Shared
// ----------------------------------------------------------------------------------------------

export const RoleSchema = z.enum(['owner', 'admin', 'operator', 'viewer', 'factory']);
export type Role = z.infer<typeof RoleSchema>;

export const DeviceStateSchema = z.enum([
  'manufactured',
  'provisioned',
  'active',
  'quarantined',
  'decommissioned',
]);
export type DeviceState = z.infer<typeof DeviceStateSchema>;
export const DEVICE_STATES = DeviceStateSchema.options;

export const AssuranceLevelSchema = z.enum(['hardware', 'software']);
export type AssuranceLevel = z.infer<typeof AssuranceLevelSchema>;

export const SeTypeSchema = z.enum(['atecc608', 'tpm2', 'optee', 'software']);
export type SeType = z.infer<typeof SeTypeSchema>;

export const CertStatusSchema = z.enum(['valid', 'expiring', 'expired', 'revoked', 'none']);
export type CertStatus = z.infer<typeof CertStatusSchema>;

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low']);
export type Severity = z.infer<typeof SeveritySchema>;
export const SEVERITIES = SeveritySchema.options;

const jsonObject = z.record(z.string(), z.unknown());
export type JsonObject = z.infer<typeof jsonObject>;

export function pageSchema<T extends z.ZodType>(item: T) {
  return z.object({
    items: z.array(item),
    next_cursor: z.string().nullable(),
  });
}
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

/** RFC 9457 problem details. `errors` carries validation errors / compiler diagnostics. */
export const ProblemErrorSchema = z.looseObject({
  message: z.string().optional(),
  msg: z.string().optional(),
  detail: z.string().optional(),
  field: z.string().optional(),
  loc: z.array(z.union([z.string(), z.number()])).optional(),
  line: z.number().optional(),
  col: z.number().optional(),
  code: z.string().optional(),
});
export type ProblemError = z.infer<typeof ProblemErrorSchema>;

export const ProblemDetailsSchema = z.looseObject({
  type: z.string().optional(),
  title: z.string(),
  status: z.number().int(),
  detail: z.string().nullable().optional(),
  instance: z.string().nullable().optional(),
  errors: z.array(ProblemErrorSchema).optional(),
});
export type ProblemDetails = z.infer<typeof ProblemDetailsSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.1 Tenant
// ----------------------------------------------------------------------------------------------

export const TenantSettingsSchema = z.object({
  allow_software_keys: z.boolean(),
  auto_quarantine: z.boolean(),
  operational_cert_ttl_hours: z.number().int(),
  default_group: z.string().nullable(),
  require_manual_approval: z.boolean().optional(),
});
export type TenantSettings = z.infer<typeof TenantSettingsSchema>;

export const TenantSchema = z.object({
  id: z.string(),
  name: z.string(),
  settings: TenantSettingsSchema,
  created_at: z.string(),
});
export type Tenant = z.infer<typeof TenantSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.2 Devices
// ----------------------------------------------------------------------------------------------

export const DeviceCertSchema = z.object({
  serial_hex: z.string().nullable(),
  not_after: z.string().nullable(),
  status: CertStatusSchema,
});
export type DeviceCert = z.infer<typeof DeviceCertSchema>;

export const LocationSchema = z.object({ lat: z.number(), lon: z.number() });
export type Location = z.infer<typeof LocationSchema>;

export const DeviceSummarySchema = z.object({
  id: z.string(),
  tenant_id: z.string(),
  product: z.string(),
  hw_revision: z.string(),
  state: DeviceStateSchema,
  assurance_level: AssuranceLevelSchema.nullable(),
  se_type: SeTypeSchema.nullable(),
  groups: z.array(z.string()),
  tags: z.record(z.string(), z.string()),
  connected: z.boolean(),
  last_seen_at: z.string().nullable(),
  fw_version: z.string().nullable(),
  fw_hash_hex: z.string().nullable(),
  cert: DeviceCertSchema,
  location: LocationSchema.nullable(),
  open_alerts: z.number().int(),
});
export type DeviceSummary = z.infer<typeof DeviceSummarySchema>;

/** Telemetry body (DESIGN_CONTRACT §5) as a JSON sample; devices send a subset of the fields. */
export const TelemetrySampleSchema = z.looseObject({
  ts: z.string(),
  cpu_pct: z.number().nullable().optional(),
  mem_pct: z.number().nullable().optional(),
  net_rx_bytes: z.number().nullable().optional(),
  net_tx_bytes: z.number().nullable().optional(),
  temp_c: z.number().nullable().optional(),
  uptime_s: z.number().nullable().optional(),
  auth_failures: z.number().nullable().optional(),
  fw_version: z.string().nullable().optional(),
  proc_count: z.number().nullable().optional(),
  top_procs: z.array(z.string()).nullable().optional(),
  rssi: z.number().nullable().optional(),
  free_heap: z.number().nullable().optional(),
  lat: z.number().nullable().optional(),
  lon: z.number().nullable().optional(),
});
export type TelemetrySample = z.infer<typeof TelemetrySampleSchema>;

export const CertificateSchema = z.object({
  serial_hex: z.string(),
  not_before: z.string(),
  not_after: z.string(),
  revoked_at: z.string().nullable(),
  revocation_reason: z.string().nullable(),
  issuer: z.string(),
});
export type Certificate = z.infer<typeof CertificateSchema>;

export const DeviceDetailSchema = DeviceSummarySchema.extend({
  bootstrap_serial_hex: z.string().nullable(),
  created_at: z.string(),
  provisioned_at: z.string().nullable(),
  activated_at: z.string().nullable(),
  quarantined_at: z.string().nullable(),
  quarantine_reason: z.string().nullable(),
  decommissioned_at: z.string().nullable(),
  twin_version: z.number().int(),
  last_telemetry: TelemetrySampleSchema.nullable(),
  certificates: z.array(CertificateSchema),
});
export type DeviceDetail = z.infer<typeof DeviceDetailSchema>;

export const CreateDeviceInputSchema = z.object({
  id: z.string().optional(),
  product: z.string().min(1),
  hw_revision: z.string().min(1),
  se_type: SeTypeSchema,
  bootstrap_serial_hex: z.string().min(1),
  tags: z.record(z.string(), z.string()).optional(),
});
export type CreateDeviceInput = z.infer<typeof CreateDeviceInputSchema>;

export const TimelineKindSchema = z.enum([
  'lifecycle',
  'connect',
  'disconnect',
  'enroll',
  'renew',
  'revoke',
  'command',
  'ota',
  'alert',
  'config',
  'twin',
  'authz_denied',
]);
export type TimelineKind = z.infer<typeof TimelineKindSchema>;
export const TIMELINE_KINDS = TimelineKindSchema.options;

export const TimelineEventSchema = z.object({
  id: z.string(),
  at: z.string(),
  kind: TimelineKindSchema,
  summary: z.string(),
  data: jsonObject.nullable(),
});
export type TimelineEvent = z.infer<typeof TimelineEventSchema>;

export const TelemetryMetricSchema = z.enum([
  'cpu_pct',
  'mem_pct',
  'temp_c',
  'net_rx_bytes',
  'net_tx_bytes',
  'rssi',
  'free_heap',
]);
export type TelemetryMetric = z.infer<typeof TelemetryMetricSchema>;
export const TELEMETRY_METRICS = TelemetryMetricSchema.options;

/** `[ts, value]`; `ts` is RFC 3339 (services may also emit epoch seconds). */
export const TelemetryPointSchema = z.tuple([
  z.union([z.string(), z.number()]),
  z.number().nullable(),
]);
export type TelemetryPoint = z.infer<typeof TelemetryPointSchema>;

export const TelemetrySeriesSchema = z.object({
  series: z.array(
    z.object({
      metric: z.string(),
      points: z.array(TelemetryPointSchema),
    }),
  ),
});
export type TelemetrySeries = z.infer<typeof TelemetrySeriesSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.3 Groups
// ----------------------------------------------------------------------------------------------

export const GroupSchema = z.object({
  slug: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  hardware_only: z.boolean(),
  member_count: z.number().int(),
  created_at: z.string(),
});
export type Group = z.infer<typeof GroupSchema>;

export const GroupMembersResultSchema = z.object({
  added: z.union([z.number().int(), z.array(z.string())]),
  removed: z.union([z.number().int(), z.array(z.string())]),
  rejected: z.array(z.object({ device_id: z.string(), reason: z.string() })),
});
export type GroupMembersResult = z.infer<typeof GroupMembersResultSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.4 Twin
// ----------------------------------------------------------------------------------------------

export const TwinSchema = z.object({
  device_id: z.string(),
  version: z.number().int(),
  desired: jsonObject,
  reported: jsonObject,
  delta: jsonObject,
  desired_updated_at: z.string().nullable(),
  reported_updated_at: z.string().nullable(),
});
export type Twin = z.infer<typeof TwinSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.5 Commands
// ----------------------------------------------------------------------------------------------

export const CommandStatusSchema = z.enum([
  'pending',
  'sent',
  'acked',
  'failed',
  'rejected',
  'expired',
]);
export type CommandStatus = z.infer<typeof CommandStatusSchema>;

export const CommandSchema = z.object({
  cmd_id: z.string(),
  device_id: z.string(),
  name: z.string(),
  args: jsonObject,
  idempotency_key: z.string().nullable(),
  status: CommandStatusSchema,
  created_by: z.string().nullable(),
  created_at: z.string(),
  sent_at: z.string().nullable(),
  acked_at: z.string().nullable(),
  expires_at: z.string().nullable(),
  result: z.unknown().nullable(),
  error: z.string().nullable(),
});
export type Command = z.infer<typeof CommandSchema>;

export const SendCommandInputSchema = z.object({
  name: z
    .string()
    .min(1, 'Command name is required')
    .max(64)
    .regex(/^[a-z][a-z0-9_.-]*$/, 'Use lower-case letters, digits, "_", "." or "-"'),
  args: jsonObject,
  ttl_s: z.number().int().min(30, 'Minimum TTL is 30 s').max(86400, 'Maximum TTL is 86400 s'),
  idempotency_key: z.string().min(8).optional(),
});
export type SendCommandInput = z.infer<typeof SendCommandInputSchema>;

export const CommandBatchSchema = z.object({
  batch_id: z.string(),
  commands: z.array(CommandSchema),
});
export type CommandBatch = z.infer<typeof CommandBatchSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.6 Config
// ----------------------------------------------------------------------------------------------

export const DeviceConfigSchema = z.object({
  version: z.number().int(),
  config: jsonObject,
  delivered_at: z.string().nullable(),
  acked_at: z.string().nullable(),
});
export type DeviceConfig = z.infer<typeof DeviceConfigSchema>;

export const PutConfigResultSchema = z.object({
  version: z.number().int(),
  published_at: z.string(),
});
export type PutConfigResult = z.infer<typeof PutConfigResultSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.7 Provisioning
// ----------------------------------------------------------------------------------------------

export const ProvisioningStateSchema = z.enum(['manufactured', 'provisioned', 'failed']);
export type ProvisioningState = z.infer<typeof ProvisioningStateSchema>;

export const ProvisioningItemSchema = z.object({
  device_id: z.string(),
  product: z.string(),
  se_type: SeTypeSchema.nullable(),
  state: ProvisioningStateSchema,
  bootstrap_serial_hex: z.string().nullable(),
  created_at: z.string(),
  last_attempt_at: z.string().nullable(),
  last_error: z.string().nullable(),
  attempts: z.number().int(),
});
export type ProvisioningItem = z.infer<typeof ProvisioningItemSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.8 Fleet
// ----------------------------------------------------------------------------------------------

export const FleetSummarySchema = z.object({
  devices_total: z.number().int(),
  by_state: z.record(z.string(), z.number().int()),
  connected: z.number().int(),
  disconnected: z.number().int(),
  assurance: z.object({ hardware: z.number().int(), software: z.number().int() }),
  certs: z.object({
    expiring_24h: z.number().int(),
    expiring_7d: z.number().int(),
    expired: z.number().int(),
    revoked: z.number().int(),
  }),
  firmware: z.array(z.object({ version: z.string(), count: z.number().int() })),
  alerts_open: z.object({
    critical: z.number().int(),
    high: z.number().int(),
    medium: z.number().int(),
    low: z.number().int(),
  }),
  campaigns_running: z.number().int(),
  map: z.array(
    z.object({
      device_id: z.string(),
      lat: z.number(),
      lon: z.number(),
      state: DeviceStateSchema,
      open_alerts: z.number().int(),
    }),
  ),
});
export type FleetSummary = z.infer<typeof FleetSummarySchema>;
export type FleetMapPoint = FleetSummary['map'][number];

export const FleetHealthSchema = z.object({
  connect_rate: z.number(),
  auth_failures: z.number(),
  msgs_per_s: z.number(),
  replay_rejected: z.number(),
  p99_ingest_ms: z.number(),
});
export type FleetHealth = z.infer<typeof FleetHealthSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.9 Audit
// ----------------------------------------------------------------------------------------------

export const AuditActorTypeSchema = z.enum(['user', 'api_key', 'service', 'system']);
export const AuditEventSchema = z.object({
  id: z.string(),
  at: z.string(),
  tenant_id: z.string(),
  actor: z.object({
    type: AuditActorTypeSchema,
    id: z.string(),
    name: z.string().nullable(),
  }),
  action: z.string(),
  target: z.object({ type: z.string(), id: z.string() }),
  outcome: z.enum(['success', 'failure']),
  ip: z.string().nullable(),
  request_id: z.string().nullable(),
  details: jsonObject.nullable(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.10 Users, API keys
// ----------------------------------------------------------------------------------------------

export const UserSchema = z.object({
  id: z.string(),
  email: z.string(),
  name: z.string().nullable(),
  role: RoleSchema,
  last_login_at: z.string().nullable(),
});
export type User = z.infer<typeof UserSchema>;

export const ApiKeySchema = z.object({
  id: z.string(),
  name: z.string(),
  prefix: z.string(),
  role: RoleSchema,
  scopes: z.array(z.string()),
  created_at: z.string(),
  last_used_at: z.string().nullable(),
  expires_at: z.string().nullable(),
});
export type ApiKey = z.infer<typeof ApiKeySchema>;

export const CreatedApiKeySchema = z.object({
  api_key: ApiKeySchema,
  secret: z.string(),
});
export type CreatedApiKey = z.infer<typeof CreatedApiKeySchema>;

export const CreateApiKeyInputSchema = z.object({
  name: z.string().min(1, 'Name is required').max(64),
  role: RoleSchema,
  scopes: z.array(z.string()).optional(),
  expires_at: z.string().optional(),
});
export type CreateApiKeyInput = z.infer<typeof CreateApiKeyInputSchema>;

// ----------------------------------------------------------------------------------------------
// Registry §1.11 WebSocket
// ----------------------------------------------------------------------------------------------

export const WsTicketSchema = z.object({
  ticket: z.string(),
  expires_in: z.number().int(),
  url: z.string().nullish(),
});
export type WsTicket = z.infer<typeof WsTicketSchema>;

export const WsFrameTypeSchema = z.enum([
  'device.connected',
  'device.disconnected',
  'device.state_changed',
  'device.telemetry',
  'twin.updated',
  'command.updated',
  'alert.created',
  'alert.updated',
  'campaign.updated',
  'provisioning.updated',
  'audit.created',
  'pong',
]);
export type WsFrameType = z.infer<typeof WsFrameTypeSchema>;

export const WsFrameSchema = z.object({
  type: z.string(),
  at: z.string(),
  data: z.unknown(),
});
export type WsFrame = z.infer<typeof WsFrameSchema>;

export const WsDeviceEventDataSchema = z.looseObject({
  device_id: z.string(),
  state: DeviceStateSchema.optional(),
  previous_state: DeviceStateSchema.optional(),
  connected: z.boolean().optional(),
});
export type WsDeviceEventData = z.infer<typeof WsDeviceEventDataSchema>;

export const WsTelemetryDataSchema = z.object({
  device_id: z.string(),
  sample: TelemetrySampleSchema,
});
export type WsTelemetryData = z.infer<typeof WsTelemetryDataSchema>;

// ----------------------------------------------------------------------------------------------
// OTA §2
// ----------------------------------------------------------------------------------------------

export const FirmwareSeveritySchema = z.enum(['normal', 'security']);
export type FirmwareSeverity = z.infer<typeof FirmwareSeveritySchema>;

export const FirmwareSchema = z.object({
  id: z.string(),
  product: z.string(),
  version: z.string(),
  version_code: z.number().int(),
  sha256_hex: z.string(),
  size: z.number().int(),
  created_at: z.string(),
  created_by: z.string().nullable(),
  signed_manifest_b64: z.string().nullable(),
  signing_key_id: z.string().nullable(),
  pq_signed: z.boolean(),
  notes: z.string().nullable(),
  severity: FirmwareSeveritySchema,
});
export type Firmware = z.infer<typeof FirmwareSchema>;

export const FirmwareMetadataSchema = z.object({
  product: z.string().min(1, 'Product is required'),
  version: z
    .string()
    .regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/, 'Version must be semver, e.g. 2.4.1'),
  version_code: z.number().int().min(1, 'Version code must be a positive integer'),
  notes: z.string().max(2000).optional(),
  severity: FirmwareSeveritySchema.optional(),
});
export type FirmwareMetadata = z.infer<typeof FirmwareMetadataSchema>;

export const StageCountsSchema = z.object({
  targeted: z.number().int(),
  notified: z.number().int(),
  downloading: z.number().int(),
  verifying: z.number().int(),
  applying: z.number().int(),
  success: z.number().int(),
  failed: z.number().int(),
  rolled_back: z.number().int(),
  rejected: z.number().int(),
});
export type StageCounts = z.infer<typeof StageCountsSchema>;

export const StageStateSchema = z.enum(['pending', 'running', 'dwelling', 'passed', 'halted']);
export type StageState = z.infer<typeof StageStateSchema>;

export const StageSchema = z.object({
  index: z.number().int(),
  percent: z.number().int().min(1).max(100),
  dwell_s: z.number().int().min(0),
  max_failure_rate: z.number().min(0).max(1),
  state: StageStateSchema,
  started_at: z.string().nullable(),
  finished_at: z.string().nullable(),
  counts: StageCountsSchema,
});
export type Stage = z.infer<typeof StageSchema>;

export const StageInputSchema = z.object({
  percent: z.number().int().min(1).max(100),
  dwell_s: z.number().int().min(0),
  max_failure_rate: z.number().min(0).max(1),
});
export type StageInput = z.infer<typeof StageInputSchema>;

export const CampaignTargetSchema = z.object({
  groups: z.array(z.string()),
  device_ids: z.array(z.string()),
  tags: z.record(z.string(), z.string()),
});
export type CampaignTarget = z.infer<typeof CampaignTargetSchema>;

export const CampaignStateSchema = z.enum([
  'draft',
  'running',
  'paused',
  'halted',
  'completed',
  'rolled_back',
  'cancelled',
]);
export type CampaignState = z.infer<typeof CampaignStateSchema>;
export const CAMPAIGN_STATES = CampaignStateSchema.options;

export const CampaignSchema = z.object({
  id: z.string(),
  name: z.string(),
  firmware: FirmwareSchema,
  target: CampaignTargetSchema,
  delta: z.boolean(),
  severity: FirmwareSeveritySchema,
  stages: z.array(StageSchema),
  current_stage: z.number().int(),
  state: CampaignStateSchema,
  halt_reason: z.string().nullable(),
  created_by: z.string().nullable(),
  created_at: z.string(),
  started_at: z.string().nullable(),
  finished_at: z.string().nullable(),
  parent_campaign_id: z.string().nullable(),
  totals: StageCountsSchema,
});
export type Campaign = z.infer<typeof CampaignSchema>;

export const CreateCampaignInputSchema = z.object({
  name: z.string().min(1, 'Name is required').max(120),
  firmware_id: z.string().min(1, 'Pick a firmware image'),
  target: CampaignTargetSchema,
  delta: z.boolean().optional(),
  severity: FirmwareSeveritySchema.optional(),
  stages: z.array(StageInputSchema).optional(),
});
export type CreateCampaignInput = z.infer<typeof CreateCampaignInputSchema>;

export const CampaignDeviceStateSchema = z.enum([
  'pending',
  'notified',
  'downloading',
  'verifying',
  'applying',
  'rebooting',
  'success',
  'failed',
  'rolled_back',
  'rejected',
]);
export type CampaignDeviceState = z.infer<typeof CampaignDeviceStateSchema>;

export const CampaignDeviceSchema = z.object({
  device_id: z.string(),
  state: CampaignDeviceStateSchema,
  progress_pct: z.number(),
  error: z.string().nullable(),
  notified_at: z.string().nullable(),
  updated_at: z.string(),
  fw_hash_hex: z.string().nullable(),
});
export type CampaignDevice = z.infer<typeof CampaignDeviceSchema>;

export const SigningKeySchema = z.object({
  key_id: z.string(),
  algorithm: z.enum(['Ed25519', 'ML-DSA-65']),
  public_key_b64: z.string(),
  active: z.boolean(),
  created_at: z.string(),
});
export type SigningKey = z.infer<typeof SigningKeySchema>;

// ----------------------------------------------------------------------------------------------
// Anomaly §3
// ----------------------------------------------------------------------------------------------

export const AlertRuleSchema = z.enum([
  'impossible_travel',
  'auth_burst',
  'topic_violation',
  'fw_hash_mismatch',
  'beaconing',
  'isolation_forest',
]);
export type AlertRule = z.infer<typeof AlertRuleSchema>;
export const ALERT_RULES = AlertRuleSchema.options;

export const AlertStateSchema = z.enum(['open', 'acked', 'resolved']);
export type AlertState = z.infer<typeof AlertStateSchema>;
export const ALERT_STATES = AlertStateSchema.options;

export const AlertActionSchema = z.object({
  type: z.enum(['quarantine', 'notify', 'none']),
  at: z.string(),
  result: z.string().nullable(),
});

export const AlertSchema = z.object({
  id: z.string(),
  tenant_id: z.string(),
  device_id: z.string(),
  rule: AlertRuleSchema,
  severity: SeveritySchema,
  score: z.number(),
  features: jsonObject,
  explanation: z.string(),
  created_at: z.string(),
  state: AlertStateSchema,
  acked_by: z.string().nullable(),
  resolved_by: z.string().nullable(),
  false_positive: z.boolean().optional(),
  actions: z.array(AlertActionSchema),
});
export type Alert = z.infer<typeof AlertSchema>;

export const RuleSchema = z.object({
  name: z.string(),
  enabled: z.boolean(),
  severity: SeveritySchema,
  params: jsonObject,
  description: z.string(),
  dry_run: z.boolean(),
});
export type Rule = z.infer<typeof RuleSchema>;

export const RuleDryRunResultSchema = z.object({
  would_fire: z.number().int(),
  sample: z.array(AlertSchema),
});

export const BaselineSchema = z.object({
  device_class: z.string(),
  samples: z.number().int(),
  trained_at: z.string().nullable(),
  score_threshold: z.number(),
  feature_means: z.record(z.string(), z.number()),
  recent_scores: z.array(z.tuple([z.union([z.string(), z.number()]), z.number()])),
});
export type Baseline = z.infer<typeof BaselineSchema>;

export const QuarantineEntrySchema = z.object({
  device_id: z.string(),
  quarantined_at: z.string(),
  reason: z.string(),
  alert_id: z.string().nullable(),
  by: z.string(),
});
export type QuarantineEntry = z.infer<typeof QuarantineEntrySchema>;

export const AnomalySettingsSchema = z.object({
  auto_quarantine: z.boolean(),
  quarantine_min_severity: SeveritySchema,
  siem: z.object({
    ecs_webhook_url: z.string().nullable(),
    syslog_host: z.string().nullable(),
    syslog_port: z.number().int().nullable(),
    enabled: z.boolean(),
  }),
});
export type AnomalySettings = z.infer<typeof AnomalySettingsSchema>;

// ----------------------------------------------------------------------------------------------
// Policy §4
// ----------------------------------------------------------------------------------------------

export const PolicyDocumentSchema = z.object({
  version: z.number().int(),
  updated_at: z.string(),
  updated_by: z.string().nullable(),
  rego: z.string(),
  sha256_hex: z.string(),
});
export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;

export const SavePolicyResultSchema = z.object({
  version: z.number().int(),
  sha256_hex: z.string(),
});
export type SavePolicyResult = z.infer<typeof SavePolicyResultSchema>;

export const PolicyEvaluateInputSchema = z.object({
  clientid: z.string().min(1, 'Client id is required'),
  username: z.string().min(1, 'Username is required'),
  tenant_id: z.string().min(1, 'Tenant id is required'),
  device_id: z.string().min(1, 'Device id is required'),
  kind: z.enum(['device', 'service']),
  topic: z.string().min(1, 'Topic is required'),
  action: z.enum(['publish', 'subscribe']),
  qos: z.number().int().min(0).max(2),
  retain: z.boolean(),
});
export type PolicyEvaluateInput = z.infer<typeof PolicyEvaluateInputSchema>;

export const PolicyEvaluateResultSchema = z.object({
  result: z.enum(['allow', 'deny']),
  matched_rules: z.array(z.string()),
  trace: z.array(z.string()),
  evaluated_version: z.number().int(),
});
export type PolicyEvaluateResult = z.infer<typeof PolicyEvaluateResultSchema>;

export const PolicyHistoryEntrySchema = z.object({
  version: z.number().int(),
  updated_at: z.string(),
  updated_by: z.string().nullable(),
  message: z.string().nullable(),
  sha256_hex: z.string(),
});
export type PolicyHistoryEntry = z.infer<typeof PolicyHistoryEntrySchema>;

export const RevocationSchema = z.object({
  serial_hex: z.string(),
  device_id: z.string(),
  tenant_id: z.string(),
  reason: z.string(),
  revoked_at: z.string(),
  applied_at: z.string().nullable(),
  kicked: z.boolean(),
});
export type Revocation = z.infer<typeof RevocationSchema>;

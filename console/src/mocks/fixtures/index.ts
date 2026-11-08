import type {
  Alert,
  ApiKey,
  AuditEvent,
  Campaign,
  CampaignDevice,
  Command,
  DeviceConfig,
  Firmware,
  Group,
  PolicyDocument,
  PolicyHistoryEntry,
  QuarantineEntry,
  Rule,
  SigningKey,
  Tenant,
  TimelineEvent,
  User,
} from '@/lib/api/schemas';
import { buildApiKeys, buildAudit, buildTenant, buildUsers } from './access';
import { RULES, buildAlerts } from './alerts';
import { buildCampaigns, buildFirmware } from './campaigns';
import { buildDevices, type DeviceFixture } from './devices';
import { buildPolicy } from './policy';
import { HOUR, createRng, hashSeed, int, iso, pick, uuid } from './seed';
import { buildConfigs, buildTimelines } from './timeline';

export interface Fixtures {
  now: number;
  tenant: Tenant;
  devices: DeviceFixture[];
  groups: Group[];
  timeline: Map<string, TimelineEvent[]>;
  configs: Map<string, DeviceConfig>;
  commands: Map<string, Command[]>;
  firmware: Firmware[];
  signingKeys: SigningKey[];
  campaigns: Campaign[];
  campaignDevices: Map<string, CampaignDevice[]>;
  alerts: Alert[];
  quarantine: QuarantineEntry[];
  rules: Rule[];
  policy: PolicyDocument;
  policyHistory: PolicyHistoryEntry[];
  audit: AuditEvent[];
  users: User[];
  apiKeys: ApiKey[];
}

function buildCommands(now: number, devices: DeviceFixture[]): Map<string, Command[]> {
  const out = new Map<string, Command[]>();
  const names = ['reboot', 'rotate_logs', 'set_log_level', 'run_diagnostics', 'resync_time'];
  for (const device of devices) {
    if (device.detail.state !== 'active') continue;
    const rng = createRng(hashSeed(device.detail.id));
    const count = int(rng, 1, 4);
    const commands: Command[] = [];
    for (let i = 0; i < count; i += 1) {
      const createdAt = now - int(rng, 1, 72) * HOUR;
      const status = pick(rng, ['acked', 'acked', 'acked', 'sent', 'failed', 'expired'] as const);
      const name = pick(rng, names);
      commands.push({
        cmd_id: uuid(rng),
        device_id: device.detail.id,
        name,
        args: name === 'set_log_level' ? { level: 'debug', duration_s: 900 } : {},
        idempotency_key: uuid(rng),
        status,
        created_by: 'user:ops-lead',
        created_at: iso(createdAt),
        sent_at: iso(createdAt + 1200),
        acked_at: status === 'acked' || status === 'failed' ? iso(createdAt + 4800) : null,
        expires_at: iso(createdAt + 300_000),
        result: status === 'acked' ? { ok: true } : null,
        error:
          status === 'failed'
            ? 'device returned status 2 (failed): service restart timed out'
            : null,
      });
    }
    commands.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    out.set(device.detail.id, commands);
  }
  return out;
}

/** Builds the full fixture set anchored at `now`. Pure and deterministic apart from `now`. */
export function buildFixtures(now: number = Date.now()): Fixtures {
  const { devices, groups } = buildDevices(now);
  const { firmware, signingKeys } = buildFirmware(now);
  const { campaigns, campaignDevices } = buildCampaigns(now, firmware, devices);
  const { alerts, quarantine } = buildAlerts(now, devices);
  const { policy, history } = buildPolicy(now);
  return {
    now,
    tenant: buildTenant(now),
    devices,
    groups,
    timeline: buildTimelines(now, devices),
    configs: buildConfigs(now, devices),
    commands: buildCommands(now, devices),
    firmware,
    signingKeys,
    campaigns,
    campaignDevices,
    alerts,
    quarantine,
    rules: RULES,
    policy,
    policyHistory: history,
    audit: buildAudit(
      now,
      devices,
      campaigns.map((c) => c.id),
    ),
    users: buildUsers(now),
    apiKeys: buildApiKeys(now),
  };
}

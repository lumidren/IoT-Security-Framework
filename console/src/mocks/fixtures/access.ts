import type { ApiKey, AuditEvent, Tenant, User } from '@/lib/api/schemas';
import { DEMO_TENANT_ID, DEMO_TENANT_NAME } from '@/lib/env';
import { DAY, HOUR, createRng, int, iso, pick, uuid } from './seed';
import type { DeviceFixture } from './devices';

export function buildTenant(now: number): Tenant {
  return {
    id: DEMO_TENANT_ID,
    name: DEMO_TENANT_NAME,
    settings: {
      allow_software_keys: true,
      auto_quarantine: true,
      operational_cert_ttl_hours: 336,
      default_group: 'lab-sensors',
      require_manual_approval: true,
    },
    created_at: iso(now - 400 * DAY),
  };
}

export function buildUsers(now: number): User[] {
  return [
    {
      id: 'u-owner',
      email: 'owner@acme.example',
      name: 'Ada Okafor',
      role: 'owner',
      last_login_at: iso(now - 2 * HOUR),
    },
    {
      id: 'u-admin',
      email: 'sec-admin@acme.example',
      name: 'Mikael Lindqvist',
      role: 'admin',
      last_login_at: iso(now - 26 * HOUR),
    },
    {
      id: 'u-ops',
      email: 'ops-lead@acme.example',
      name: 'Priya Raman',
      role: 'operator',
      last_login_at: iso(now - 40 * 60_000),
    },
    {
      id: 'u-viewer',
      email: 'auditor@acme.example',
      name: 'Jonas Weber',
      role: 'viewer',
      last_login_at: iso(now - 6 * DAY),
    },
    {
      id: 'u-factory',
      email: 'line-controller@factory.acme.example',
      name: 'Factory line controller',
      role: 'factory',
      last_login_at: iso(now - 3 * HOUR),
    },
  ];
}

export function buildApiKeys(now: number): ApiKey[] {
  return [
    {
      id: 'key-01',
      name: 'Factory provisioning line A',
      prefix: 'imk_7f3a',
      role: 'factory',
      scopes: ['devices:create'],
      created_at: iso(now - 200 * DAY),
      last_used_at: iso(now - 3 * HOUR),
      expires_at: null,
    },
    {
      id: 'key-02',
      name: 'CI release pipeline',
      prefix: 'imk_c01d',
      role: 'admin',
      scopes: ['firmware:upload', 'campaigns:create'],
      created_at: iso(now - 90 * DAY),
      last_used_at: iso(now - 9 * DAY),
      expires_at: iso(now + 275 * DAY),
    },
    {
      id: 'key-03',
      name: 'SIEM read-only',
      prefix: 'imk_5eed',
      role: 'viewer',
      scopes: ['audit:read', 'alerts:read'],
      created_at: iso(now - 30 * DAY),
      last_used_at: iso(now - 5 * 60_000),
      expires_at: null,
    },
  ];
}

const ACTIONS: Array<{ action: string; targetType: string; outcome: AuditEvent['outcome'] }> = [
  { action: 'device.quarantine', targetType: 'device', outcome: 'success' },
  { action: 'device.release', targetType: 'device', outcome: 'success' },
  { action: 'device.patch', targetType: 'device', outcome: 'success' },
  { action: 'command.send', targetType: 'device', outcome: 'success' },
  { action: 'twin.desired.patch', targetType: 'device', outcome: 'success' },
  { action: 'config.put', targetType: 'device', outcome: 'success' },
  { action: 'campaign.start', targetType: 'campaign', outcome: 'success' },
  { action: 'campaign.pause', targetType: 'campaign', outcome: 'success' },
  { action: 'firmware.upload', targetType: 'firmware', outcome: 'success' },
  { action: 'policy.put', targetType: 'policy', outcome: 'success' },
  { action: 'policy.put', targetType: 'policy', outcome: 'failure' },
  { action: 'alert.ack', targetType: 'alert', outcome: 'success' },
  { action: 'api_key.create', targetType: 'api_key', outcome: 'success' },
  { action: 'user.role.update', targetType: 'user', outcome: 'success' },
  { action: 'provisioning.approve', targetType: 'device', outcome: 'success' },
  { action: 'tenant.settings.patch', targetType: 'tenant', outcome: 'success' },
];

export function buildAudit(
  now: number,
  devices: DeviceFixture[],
  campaignIds: string[],
): AuditEvent[] {
  const rng = createRng(0x0a0d17);
  const actors = [
    { type: 'user' as const, id: 'u-owner', name: 'Ada Okafor' },
    { type: 'user' as const, id: 'u-admin', name: 'Mikael Lindqvist' },
    { type: 'user' as const, id: 'u-ops', name: 'Priya Raman' },
    { type: 'api_key' as const, id: 'key-02', name: 'CI release pipeline' },
    { type: 'service' as const, id: 'anomaly', name: 'anomaly engine' },
    { type: 'system' as const, id: 'scheduler', name: 'scheduler' },
  ];
  const events: AuditEvent[] = [];
  for (let i = 0; i < 80; i += 1) {
    const def = pick(rng, ACTIONS);
    const targetId =
      def.targetType === 'device'
        ? pick(rng, devices).detail.id
        : def.targetType === 'campaign'
          ? pick(rng, campaignIds)
          : def.targetType === 'policy'
            ? 'tenant-policy'
            : def.targetType === 'user'
              ? 'u-viewer'
              : def.targetType === 'api_key'
                ? 'key-03'
                : def.targetType === 'tenant'
                  ? DEMO_TENANT_ID
                  : uuid(rng);
    const actor =
      def.action.startsWith('device.quarantine') && rng() < 0.5
        ? actors[4]!
        : pick(rng, actors.slice(0, 4));
    events.push({
      id: uuid(rng),
      at: iso(now - int(rng, 1, 30 * 24) * HOUR - int(rng, 0, 3599) * 1000),
      tenant_id: DEMO_TENANT_ID,
      actor,
      action: def.action,
      target: { type: def.targetType, id: targetId },
      outcome: def.outcome,
      ip: actor.type === 'user' ? `10.20.${int(rng, 0, 255)}.${int(rng, 1, 254)}` : null,
      request_id: uuid(rng),
      details:
        def.outcome === 'failure'
          ? { error: 'validation failed', status: 422 }
          : def.action === 'command.send'
            ? { name: pick(rng, ['reboot', 'rotate_logs', 'set_log_level']), ttl_s: 300 }
            : { source: 'console' },
    });
  }
  events.sort((a, b) => (a.at < b.at ? 1 : -1));
  return events;
}

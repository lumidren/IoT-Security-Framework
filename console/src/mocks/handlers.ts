import { HttpResponse, delay, http, ws } from 'msw';
import type {
  Alert,
  ApiKey,
  AuditEvent,
  Campaign,
  CampaignDevice,
  Command,
  DeviceDetail,
  Firmware,
  Group,
  ProblemError,
  Stage,
  StageCounts,
  TimelineEvent,
  User,
} from '@/lib/api/schemas';
import { StageInputSchema } from '@/lib/api/schemas';
import { DEMO_TENANT_ID } from '@/lib/env';
import { validateStages } from '@/lib/stages';
import { db, findDevice, paginate, summaryOf, telemetryFor } from './db';
import { emptyCounts } from './fixtures/campaigns';
import { compilePolicy, evaluatePolicy } from './fixtures/policy';
import { createRng, hashSeed, hex, iso, uuid } from './fixtures/seed';

/** Simulated network latency; the browser worker sets this, Node tests leave it at 0. */
let latencyMs = 0;
export function setMockLatency(ms: number) {
  latencyMs = ms;
}

const rng = createRng(0x9e3779b9);
const R = '*/api/proxy/registry';
const O = '*/api/proxy/ota';
const A = '*/api/proxy/anomaly';
const P = '*/api/proxy/policy';

function problem(status: number, title: string, detail?: string, errors?: ProblemError[]) {
  return HttpResponse.json(
    { type: 'about:blank', title, status, detail, errors },
    { status, headers: { 'content-type': 'application/problem+json' } },
  );
}

async function readJson<T = Record<string, unknown>>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    return {} as T;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function audit(
  action: string,
  target: { type: string; id: string },
  outcome: AuditEvent['outcome'] = 'success',
  details: Record<string, unknown> = {},
) {
  const event: AuditEvent = {
    id: uuid(rng),
    at: nowIso(),
    tenant_id: DEMO_TENANT_ID,
    actor: { type: 'user', id: 'demo', name: 'Demo user' },
    action,
    target,
    outcome,
    ip: '127.0.0.1',
    request_id: uuid(rng),
    details,
  };
  db.audit.unshift(event);
  return event;
}

function timeline(
  deviceId: string,
  kind: TimelineEvent['kind'],
  summary: string,
  data: Record<string, unknown> = {},
) {
  const list = db.timeline.get(deviceId) ?? [];
  list.unshift({ id: uuid(rng), at: nowIso(), kind, summary, data });
  db.timeline.set(deviceId, list);
}

function recomputeGroupCounts() {
  for (const group of db.groups) {
    group.member_count = db.devices.filter((d) => d.detail.groups.includes(group.slug)).length;
  }
}

function computeDelta(desired: Record<string, unknown>, reported: Record<string, unknown>) {
  const delta: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(desired)) {
    if (JSON.stringify(reported[key]) !== JSON.stringify(value)) delta[key] = value;
  }
  return delta;
}

function deepMerge(base: Record<string, unknown>, patch: Record<string, unknown>) {
  const out: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) {
      delete out[key];
    } else if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      out[key] &&
      typeof out[key] === 'object' &&
      !Array.isArray(out[key])
    ) {
      out[key] = deepMerge(out[key] as Record<string, unknown>, value as Record<string, unknown>);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function matchesTarget(device: DeviceDetail, target: Campaign['target']): boolean {
  if (device.state !== 'active') return false;
  if (target.device_ids.includes(device.id)) return true;
  if (target.groups.some((g) => device.groups.includes(g))) {
    return Object.entries(target.tags).every(([k, v]) => device.tags[k] === v);
  }
  const tagEntries = Object.entries(target.tags);
  if (tagEntries.length > 0 && target.groups.length === 0) {
    return tagEntries.every(([k, v]) => device.tags[k] === v);
  }
  return false;
}

function sumCounts(stages: Stage[]): StageCounts {
  const total = emptyCounts();
  for (const s of stages)
    for (const key of Object.keys(total) as Array<keyof StageCounts>) total[key] += s.counts[key];
  return total;
}

// ----------------------------------------------------------------------------------------------
// Registry
// ----------------------------------------------------------------------------------------------

const registryHandlers = [
  http.get(`${R}/v1/tenants/me`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.tenant);
  }),
  http.patch(`${R}/v1/tenants/me/settings`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson(request);
    db.tenant = { ...db.tenant, settings: { ...db.tenant.settings, ...body } };
    audit('tenant.settings.patch', { type: 'tenant', id: db.tenant.id }, 'success', body);
    return HttpResponse.json(db.tenant);
  }),

  http.get(`${R}/v1/devices`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const state = url.searchParams.get('state');
    const group = url.searchParams.get('group');
    const tag = url.searchParams.get('tag');
    const q = url.searchParams.get('q')?.toLowerCase();
    const connected = url.searchParams.get('connected');
    const assurance = url.searchParams.get('assurance');
    let items = db.devices.map((d) => d.detail);
    if (state) items = items.filter((d) => state.split(',').includes(d.state));
    if (group) items = items.filter((d) => d.groups.includes(group));
    if (tag) {
      const [k, v] = tag.split(':');
      items = items.filter((d) => (k ? (v ? d.tags[k] === v : k in d.tags) : true));
    }
    if (q)
      items = items.filter(
        (d) =>
          d.id.includes(q) ||
          d.product.includes(q) ||
          Object.values(d.tags).some((t) => t.includes(q)),
      );
    if (connected === 'true') items = items.filter((d) => d.connected);
    if (connected === 'false') items = items.filter((d) => !d.connected);
    if (assurance) items = items.filter((d) => d.assurance_level === assurance);
    items = [...items].sort((a, b) => ((a.last_seen_at ?? '') < (b.last_seen_at ?? '') ? 1 : -1));
    const page = paginate(
      items.map(summaryOf),
      url.searchParams.get('cursor'),
      url.searchParams.get('limit'),
    );
    return HttpResponse.json(page);
  }),

  http.post(`${R}/v1/devices`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson<{
      id?: string;
      product?: string;
      hw_revision?: string;
      se_type?: DeviceDetail['se_type'];
      bootstrap_serial_hex?: string;
      tags?: Record<string, string>;
    }>(request);
    if (!body.product || !body.hw_revision || !body.se_type || !body.bootstrap_serial_hex) {
      return problem(422, 'Validation failed', undefined, [
        {
          field: 'product',
          message: 'product, hw_revision, se_type and bootstrap_serial_hex are required',
        },
      ]);
    }
    const id = body.id ?? `dev-${hex(rng, 16)}`;
    const detail: DeviceDetail = {
      id,
      tenant_id: DEMO_TENANT_ID,
      product: body.product,
      hw_revision: body.hw_revision,
      state: 'manufactured',
      assurance_level: null,
      se_type: body.se_type,
      groups: [],
      tags: body.tags ?? {},
      connected: false,
      last_seen_at: null,
      fw_version: null,
      fw_hash_hex: null,
      cert: { serial_hex: null, not_after: null, status: 'none' },
      location: null,
      open_alerts: 0,
      bootstrap_serial_hex: body.bootstrap_serial_hex,
      created_at: nowIso(),
      provisioned_at: null,
      activated_at: null,
      quarantined_at: null,
      quarantine_reason: null,
      decommissioned_at: null,
      twin_version: 0,
      last_telemetry: null,
      certificates: [],
    };
    db.devices.unshift({
      detail,
      twin: {
        device_id: id,
        version: 0,
        desired: {},
        reported: {},
        delta: {},
        desired_updated_at: null,
        reported_updated_at: null,
      },
      provisioning: {
        device_id: id,
        product: detail.product,
        se_type: detail.se_type,
        state: 'manufactured',
        bootstrap_serial_hex: detail.bootstrap_serial_hex,
        created_at: detail.created_at,
        last_attempt_at: null,
        last_error: null,
        attempts: 0,
      },
      platform: body.product.includes('esp32') ? 'esp32' : 'linux',
    });
    audit('device.create', { type: 'device', id });
    return HttpResponse.json(detail, { status: 201 });
  }),

  http.get(`${R}/v1/devices/:id`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    return HttpResponse.json(device.detail);
  }),

  http.patch(`${R}/v1/devices/:id`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const body = await readJson<{ tags?: Record<string, string>; groups?: string[] }>(request);
    if (body.groups) {
      const unknown = body.groups.filter((g) => !db.groups.some((x) => x.slug === g));
      if (unknown.length > 0)
        return problem(422, 'Validation failed', undefined, [
          { field: 'groups', message: `Unknown group(s): ${unknown.join(', ')}` },
        ]);
      const hardwareOnly = body.groups.filter(
        (g) => db.groups.find((x) => x.slug === g)?.hardware_only,
      );
      if (hardwareOnly.length > 0 && device.detail.assurance_level !== 'hardware') {
        return problem(
          422,
          'Validation failed',
          'Software-key devices cannot join hardware-only groups',
          [{ field: 'groups', message: `${hardwareOnly.join(', ')} require hardware assurance` }],
        );
      }
      device.detail.groups = body.groups;
    }
    if (body.tags) device.detail.tags = body.tags;
    recomputeGroupCounts();
    audit('device.patch', { type: 'device', id: device.detail.id }, 'success', body);
    return HttpResponse.json(device.detail);
  }),

  http.post(`${R}/v1/devices/:id/quarantine`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    if (device.detail.state === 'decommissioned')
      return problem(409, 'Conflict', 'Decommissioned devices cannot be quarantined.');
    const { reason } = await readJson<{ reason?: string }>(request);
    if (!reason || reason.trim().length < 3)
      return problem(422, 'Validation failed', undefined, [
        { field: 'reason', message: 'reason is required' },
      ]);
    const at = nowIso();
    device.detail.state = 'quarantined';
    device.detail.quarantined_at = at;
    device.detail.quarantine_reason = reason;
    device.detail.connected = false;
    if (device.detail.cert.serial_hex) {
      device.detail.cert = { ...device.detail.cert, status: 'revoked' };
      device.detail.certificates = device.detail.certificates.map((c) =>
        c.revoked_at ? c : { ...c, revoked_at: at, revocation_reason: 'quarantine' },
      );
    }
    db.quarantine.unshift({
      device_id: device.detail.id,
      quarantined_at: at,
      reason,
      alert_id: null,
      by: 'user:demo',
    });
    timeline(device.detail.id, 'revoke', 'All certificates revoked (quarantine); session kicked', {
      reason: 'quarantine',
    });
    timeline(device.detail.id, 'lifecycle', 'State changed → quarantined', {
      state: 'quarantined',
      reason,
    });
    audit('device.quarantine', { type: 'device', id: device.detail.id }, 'success', { reason });
    return HttpResponse.json(device.detail);
  }),

  http.post(`${R}/v1/devices/:id/release`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    if (device.detail.state !== 'quarantined')
      return problem(409, 'Conflict', 'Only quarantined devices can be released.');
    const { note } = await readJson<{ note?: string }>(request);
    device.detail.state = 'active';
    device.detail.quarantined_at = null;
    device.detail.quarantine_reason = null;
    device.detail.cert = { serial_hex: null, not_after: null, status: 'none' };
    db.quarantine = db.quarantine.filter((q) => q.device_id !== device.detail.id);
    timeline(
      device.detail.id,
      'lifecycle',
      'State changed quarantined → active (device must re-enroll)',
      { state: 'active', note },
    );
    audit('device.release', { type: 'device', id: device.detail.id }, 'success', { note });
    return HttpResponse.json(device.detail);
  }),

  http.post(`${R}/v1/devices/:id/decommission`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    if (device.detail.state === 'decommissioned')
      return problem(409, 'Conflict', 'Device is already decommissioned.');
    const { reason } = await readJson<{ reason?: string }>(request);
    const at = nowIso();
    device.detail.state = 'decommissioned';
    device.detail.decommissioned_at = at;
    device.detail.connected = false;
    device.detail.groups = [];
    if (device.detail.cert.serial_hex)
      device.detail.cert = { ...device.detail.cert, status: 'revoked' };
    device.detail.certificates = device.detail.certificates.map((c) =>
      c.revoked_at ? c : { ...c, revoked_at: at, revocation_reason: 'decommissioned' },
    );
    db.quarantine = db.quarantine.filter((q) => q.device_id !== device.detail.id);
    recomputeGroupCounts();
    timeline(device.detail.id, 'lifecycle', 'State changed → decommissioned (terminal)', {
      state: 'decommissioned',
      reason,
    });
    audit('device.decommission', { type: 'device', id: device.detail.id }, 'success', { reason });
    return HttpResponse.json(device.detail);
  }),

  http.get(`${R}/v1/devices/:id/timeline`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const url = new URL(request.url);
    const kinds = url.searchParams.get('kinds')?.split(',').filter(Boolean);
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    let items = db.timeline.get(device.detail.id) ?? [];
    if (kinds && kinds.length > 0) items = items.filter((e) => kinds.includes(e.kind));
    if (from) items = items.filter((e) => e.at >= from);
    if (to) items = items.filter((e) => e.at <= to);
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),

  http.get(`${R}/v1/devices/:id/telemetry`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const url = new URL(request.url);
    const to = Date.parse(url.searchParams.get('to') ?? '') || Date.now();
    const from = Date.parse(url.searchParams.get('from') ?? '') || to - 3_600_000;
    const metrics = (url.searchParams.get('metrics') ?? 'cpu_pct,mem_pct,temp_c')
      .split(',')
      .filter(Boolean);
    const supported =
      device.platform === 'esp32'
        ? metrics
        : metrics.filter((m) => m !== 'rssi' && m !== 'free_heap');
    return HttpResponse.json(
      telemetryFor(device.detail.id, from, to, supported, url.searchParams.get('step') ?? '60s'),
    );
  }),

  http.get(`${R}/v1/devices/:id/certificates`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    return HttpResponse.json(device.detail.certificates);
  }),

  http.get(`${R}/v1/groups`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.groups);
  }),
  http.post(`${R}/v1/groups`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson<{
      slug?: string;
      name?: string;
      description?: string;
      hardware_only?: boolean;
    }>(request);
    if (!body.slug || !/^[a-z0-9-]{1,48}$/.test(body.slug) || !body.name) {
      return problem(422, 'Validation failed', undefined, [
        { field: 'slug', message: 'slug must match [a-z0-9-]{1,48}' },
      ]);
    }
    if (db.groups.some((g) => g.slug === body.slug))
      return problem(409, 'Conflict', 'Group already exists');
    const group: Group = {
      slug: body.slug,
      name: body.name,
      description: body.description ?? null,
      hardware_only: body.hardware_only ?? false,
      member_count: 0,
      created_at: nowIso(),
    };
    db.groups.push(group);
    audit('group.create', { type: 'group', id: group.slug });
    return HttpResponse.json(group, { status: 201 });
  }),
  http.put(`${R}/v1/groups/:slug/members`, async ({ params, request }) => {
    await delay(latencyMs);
    const group = db.groups.find((g) => g.slug === params['slug']);
    if (!group) return problem(404, 'Group not found');
    const body = await readJson<{ add?: string[]; remove?: string[] }>(request);
    const added: string[] = [];
    const removed: string[] = [];
    const rejected: Array<{ device_id: string; reason: string }> = [];
    for (const id of body.add ?? []) {
      const device = findDevice(id);
      if (!device) {
        rejected.push({ device_id: id, reason: 'unknown device' });
        continue;
      }
      if (group.hardware_only && device.detail.assurance_level !== 'hardware') {
        rejected.push({
          device_id: id,
          reason: 'hardware_only group rejects software-key devices',
        });
        continue;
      }
      if (!device.detail.groups.includes(group.slug)) device.detail.groups.push(group.slug);
      added.push(id);
    }
    for (const id of body.remove ?? []) {
      const device = findDevice(id);
      if (device && device.detail.groups.includes(group.slug)) {
        device.detail.groups = device.detail.groups.filter((g) => g !== group.slug);
        removed.push(id);
      }
    }
    recomputeGroupCounts();
    audit('group.members.update', { type: 'group', id: group.slug }, 'success', {
      added: added.length,
      removed: removed.length,
      rejected: rejected.length,
    });
    return HttpResponse.json({ added, removed, rejected });
  }),

  http.get(`${R}/v1/devices/:id/twin`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    return HttpResponse.json(device.twin);
  }),
  http.patch(`${R}/v1/devices/:id/twin/desired`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const body = await readJson<{ patch?: Record<string, unknown>; expected_version?: number }>(
      request,
    );
    if (!body.patch || typeof body.patch !== 'object')
      return problem(422, 'Validation failed', undefined, [
        { field: 'patch', message: 'patch must be an object' },
      ]);
    if (body.expected_version !== undefined && body.expected_version !== device.twin.version) {
      return problem(
        409,
        'Version conflict',
        `Twin is at version ${device.twin.version}, expected ${body.expected_version}.`,
      );
    }
    device.twin.desired = deepMerge(device.twin.desired, body.patch);
    device.twin.version += 1;
    device.twin.desired_updated_at = nowIso();
    device.twin.delta = computeDelta(device.twin.desired, device.twin.reported);
    device.detail.twin_version = device.twin.version;
    timeline(device.detail.id, 'twin', `Desired state updated (version ${device.twin.version})`, {
      version: device.twin.version,
    });
    audit('twin.desired.patch', { type: 'device', id: device.detail.id }, 'success', {
      version: device.twin.version,
    });
    return HttpResponse.json(device.twin);
  }),
  http.delete(`${R}/v1/devices/:id/twin/desired/:path`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const path = decodeURIComponent(String(params['path'])).split('.');
    const desired = structuredClone(device.twin.desired);
    let cursor: Record<string, unknown> = desired;
    for (let i = 0; i < path.length - 1; i += 1) {
      const next = cursor[path[i] ?? ''];
      if (!next || typeof next !== 'object') return problem(404, 'Path not found');
      cursor = next as Record<string, unknown>;
    }
    delete cursor[path[path.length - 1] ?? ''];
    device.twin.desired = desired;
    device.twin.version += 1;
    device.twin.desired_updated_at = nowIso();
    device.twin.delta = computeDelta(device.twin.desired, device.twin.reported);
    device.detail.twin_version = device.twin.version;
    return HttpResponse.json(device.twin);
  }),

  http.post(`${R}/v1/devices/:id/commands`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const body = await readJson<{
      name?: string;
      args?: Record<string, unknown>;
      ttl_s?: number;
      idempotency_key?: string;
    }>(request);
    const key = request.headers.get('idempotency-key') ?? body.idempotency_key ?? null;
    const existing = key
      ? (db.commands.get(device.detail.id) ?? []).find((c) => c.idempotency_key === key)
      : undefined;
    if (existing)
      return HttpResponse.json(existing, {
        status: 202,
        headers: { 'idempotency-replayed': 'true' },
      });
    const errors: ProblemError[] = [];
    if (!body.name) errors.push({ field: 'name', message: 'name is required' });
    if (typeof body.ttl_s !== 'number' || body.ttl_s < 30 || body.ttl_s > 86400)
      errors.push({ field: 'ttl_s', message: 'ttl_s must be between 30 and 86400' });
    if (errors.length > 0) return problem(422, 'Validation failed', undefined, errors);
    const createdAt = Date.now();
    const command: Command = {
      cmd_id: uuid(rng),
      device_id: device.detail.id,
      name: body.name!,
      args: body.args ?? {},
      idempotency_key: key,
      status: 'pending',
      created_by: 'user:demo',
      created_at: iso(createdAt),
      sent_at: null,
      acked_at: null,
      expires_at: iso(createdAt + (body.ttl_s ?? 300) * 1000),
      result: null,
      error: null,
    };
    const list = db.commands.get(device.detail.id) ?? [];
    list.unshift(command);
    db.commands.set(device.detail.id, list);
    timeline(device.detail.id, 'command', `Command ${command.name} queued`, {
      cmd_id: command.cmd_id,
    });
    audit('command.send', { type: 'device', id: device.detail.id }, 'success', {
      name: command.name,
      ttl_s: body.ttl_s,
    });
    // Simulate the device lifecycle of the command.
    const connected = device.detail.connected;
    setTimeout(() => {
      command.status = 'sent';
      command.sent_at = nowIso();
    }, 1200);
    setTimeout(
      () => {
        if (connected) {
          command.status = 'acked';
          command.acked_at = nowIso();
          command.result = { ok: true };
        } else {
          command.status = 'expired';
          command.error = 'device offline until TTL expired';
        }
        timeline(device.detail.id, 'command', `Command ${command.name} ${command.status}`, {
          cmd_id: command.cmd_id,
        });
      },
      connected ? 3500 : 6000,
    );
    return HttpResponse.json(command, { status: 202 });
  }),
  http.get(`${R}/v1/devices/:id/commands`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    let items = db.commands.get(device.detail.id) ?? [];
    if (status) items = items.filter((c) => c.status === status);
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit'), 25),
    );
  }),
  http.get(`${R}/v1/commands/:cmdId`, async ({ params }) => {
    await delay(latencyMs);
    for (const list of db.commands.values()) {
      const found = list.find((c) => c.cmd_id === params['cmdId']);
      if (found) return HttpResponse.json(found);
    }
    return problem(404, 'Command not found');
  }),
  http.post(`${R}/v1/groups/:slug/commands`, async ({ params, request }) => {
    await delay(latencyMs);
    const group = db.groups.find((g) => g.slug === params['slug']);
    if (!group) return problem(404, 'Group not found');
    const body = await readJson<{
      name?: string;
      args?: Record<string, unknown>;
      ttl_s?: number;
      idempotency_key?: string;
    }>(request);
    if (!body.name)
      return problem(422, 'Validation failed', undefined, [
        { field: 'name', message: 'name is required' },
      ]);
    const commands: Command[] = [];
    for (const device of db.devices.filter(
      (d) => d.detail.groups.includes(group.slug) && d.detail.state === 'active',
    )) {
      const createdAt = Date.now();
      const command: Command = {
        cmd_id: uuid(rng),
        device_id: device.detail.id,
        name: body.name,
        args: body.args ?? {},
        idempotency_key: body.idempotency_key ?? null,
        status: 'sent',
        created_by: 'user:demo',
        created_at: iso(createdAt),
        sent_at: iso(createdAt),
        acked_at: null,
        expires_at: iso(createdAt + (body.ttl_s ?? 300) * 1000),
        result: null,
        error: null,
      };
      const list = db.commands.get(device.detail.id) ?? [];
      list.unshift(command);
      db.commands.set(device.detail.id, list);
      commands.push(command);
    }
    audit('command.send.group', { type: 'group', id: group.slug }, 'success', {
      name: body.name,
      count: commands.length,
    });
    return HttpResponse.json({ batch_id: uuid(rng), commands });
  }),

  http.get(`${R}/v1/devices/:id/config`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const config = db.configs.get(device.detail.id);
    if (!config) return problem(404, 'No configuration published for this device');
    return HttpResponse.json(config);
  }),
  http.put(`${R}/v1/devices/:id/config`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const body = await readJson<{ config?: Record<string, unknown> }>(request);
    if (!body.config || typeof body.config !== 'object')
      return problem(422, 'Validation failed', undefined, [
        { field: 'config', message: 'config must be an object' },
      ]);
    const previous = db.configs.get(device.detail.id);
    const version = (previous?.version ?? 0) + 1;
    const publishedAt = nowIso();
    db.configs.set(device.detail.id, {
      version,
      config: body.config,
      delivered_at: publishedAt,
      acked_at: null,
    });
    timeline(device.detail.id, 'config', `Encrypted configuration published (version ${version})`, {
      version,
    });
    audit('config.put', { type: 'device', id: device.detail.id }, 'success', { version });
    return HttpResponse.json({ version, published_at: publishedAt });
  }),

  http.get(`${R}/v1/provisioning`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const state = url.searchParams.get('state');
    let items = db.devices
      .map((d) => d.provisioning)
      .filter((p): p is NonNullable<typeof p> => p !== null);
    if (state) items = items.filter((p) => p.state === state);
    items = [...items].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
  http.post(`${R}/v1/provisioning/:id/approve`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device || !device.provisioning) return problem(404, 'Provisioning record not found');
    const at = nowIso();
    if (device.detail.state === 'manufactured') {
      device.detail.state = 'provisioned';
      device.detail.provisioned_at = at;
      device.provisioning.state = 'provisioned';
      device.provisioning.last_error = null;
      timeline(
        device.detail.id,
        'lifecycle',
        'State changed manufactured → provisioned (approved)',
        { state: 'provisioned' },
      );
    } else if (device.detail.state === 'provisioned') {
      device.detail.state = 'active';
      device.detail.activated_at = at;
      device.detail.assurance_level =
        device.detail.se_type === 'software' ? 'software' : 'hardware';
      device.provisioning = null;
      timeline(device.detail.id, 'lifecycle', 'State changed provisioned → active (approved)', {
        state: 'active',
      });
    } else {
      return problem(409, 'Conflict', `Device is ${device.detail.state}.`);
    }
    audit('provisioning.approve', { type: 'device', id: device.detail.id });
    return HttpResponse.json(summaryOf(device.detail));
  }),
  http.post(`${R}/v1/provisioning/:id/reject`, async ({ params, request }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device || !device.provisioning) return problem(404, 'Provisioning record not found');
    const { reason } = await readJson<{ reason?: string }>(request);
    device.provisioning.state = 'failed';
    device.provisioning.last_error = `rejected by operator: ${reason ?? 'no reason given'}`;
    device.provisioning.last_attempt_at = nowIso();
    device.provisioning.attempts += 1;
    timeline(device.detail.id, 'lifecycle', 'Provisioning rejected by operator', { reason });
    audit('provisioning.reject', { type: 'device', id: device.detail.id }, 'success', { reason });
    return HttpResponse.json(summaryOf(device.detail));
  }),

  http.get(`${R}/v1/fleet/summary`, async () => {
    await delay(latencyMs);
    const devices = db.devices.map((d) => d.detail);
    const byState: Record<string, number> = {
      manufactured: 0,
      provisioned: 0,
      active: 0,
      quarantined: 0,
      decommissioned: 0,
    };
    for (const d of devices) byState[d.state] = (byState[d.state] ?? 0) + 1;
    const now = Date.now();
    const certs = { expiring_24h: 0, expiring_7d: 0, expired: 0, revoked: 0 };
    for (const d of devices) {
      if (d.cert.status === 'revoked') certs.revoked += 1;
      else if (d.cert.status === 'expired') certs.expired += 1;
      else if (d.cert.not_after) {
        const left = Date.parse(d.cert.not_after) - now;
        if (left < 0) certs.expired += 1;
        else if (left < 86_400_000) {
          certs.expiring_24h += 1;
          certs.expiring_7d += 1;
        } else if (left < 7 * 86_400_000) certs.expiring_7d += 1;
      }
    }
    const firmwareCounts = new Map<string, number>();
    for (const d of devices)
      if (d.fw_version)
        firmwareCounts.set(
          `${d.product}/${d.fw_version}`,
          (firmwareCounts.get(`${d.product}/${d.fw_version}`) ?? 0) + 1,
        );
    const alertsOpen = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of db.alerts) if (a.state !== 'resolved') alertsOpen[a.severity] += 1;
    return HttpResponse.json({
      devices_total: devices.length,
      by_state: byState,
      connected: devices.filter((d) => d.connected).length,
      disconnected: devices.filter((d) => !d.connected && d.state === 'active').length,
      assurance: {
        hardware: devices.filter((d) => d.assurance_level === 'hardware').length,
        software: devices.filter((d) => d.assurance_level === 'software').length,
      },
      certs,
      firmware: [...firmwareCounts.entries()]
        .map(([version, count]) => ({ version, count }))
        .sort((a, b) => b.count - a.count),
      alerts_open: alertsOpen,
      campaigns_running: db.campaigns.filter((c) => c.state === 'running').length,
      map: devices
        .filter((d) => d.location)
        .map((d) => ({
          device_id: d.id,
          lat: d.location!.lat,
          lon: d.location!.lon,
          state: d.state,
          open_alerts: d.open_alerts,
        })),
    });
  }),
  http.get(`${R}/v1/fleet/health`, async () => {
    await delay(latencyMs);
    return HttpResponse.json({
      connect_rate: 0.42,
      auth_failures: 3,
      msgs_per_s: 118.6,
      replay_rejected: 0,
      p99_ingest_ms: 84,
    });
  }),

  http.get(`${R}/v1/audit/export`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    const items = db.audit.filter((e) => (!from || e.at >= from) && (!to || e.at <= to));
    const body = items.map((e) => JSON.stringify(e)).join('\n') + '\n';
    return new HttpResponse(body, {
      headers: {
        'content-type': 'application/x-ndjson',
        'content-disposition': 'attachment; filename="audit.ndjson"',
      },
    });
  }),
  http.get(`${R}/v1/audit`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const actor = url.searchParams.get('actor')?.toLowerCase();
    const action = url.searchParams.get('action');
    const targetType = url.searchParams.get('target_type');
    const targetId = url.searchParams.get('target_id');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    let items = db.audit;
    if (actor)
      items = items.filter(
        (e) =>
          e.actor.id.toLowerCase().includes(actor) ||
          (e.actor.name ?? '').toLowerCase().includes(actor),
      );
    if (action) items = items.filter((e) => e.action.startsWith(action));
    if (targetType) items = items.filter((e) => e.target.type === targetType);
    if (targetId) items = items.filter((e) => e.target.id === targetId);
    if (from) items = items.filter((e) => e.at >= from);
    if (to) items = items.filter((e) => e.at <= to);
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),

  http.get(`${R}/v1/users`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.users);
  }),
  http.put(`${R}/v1/users/:id/role`, async ({ params, request }) => {
    await delay(latencyMs);
    const user = db.users.find((u) => u.id === params['id']);
    if (!user) return problem(404, 'User not found');
    const { role } = await readJson<{ role?: User['role'] }>(request);
    if (!role)
      return problem(422, 'Validation failed', undefined, [
        { field: 'role', message: 'role is required' },
      ]);
    user.role = role;
    audit('user.role.update', { type: 'user', id: user.id }, 'success', { role });
    return HttpResponse.json(user);
  }),
  http.get(`${R}/v1/api-keys`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.apiKeys);
  }),
  http.post(`${R}/v1/api-keys`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson<{
      name?: string;
      role?: ApiKey['role'];
      scopes?: string[];
      expires_at?: string;
    }>(request);
    if (!body.name || !body.role)
      return problem(422, 'Validation failed', undefined, [
        { field: 'name', message: 'name and role are required' },
      ]);
    const prefix = `imk_${hex(rng, 4)}`;
    const apiKey: ApiKey = {
      id: `key-${hex(rng, 6)}`,
      name: body.name,
      prefix,
      role: body.role,
      scopes: body.scopes ?? [],
      created_at: nowIso(),
      last_used_at: null,
      expires_at: body.expires_at ?? null,
    };
    db.apiKeys.unshift(apiKey);
    audit('api_key.create', { type: 'api_key', id: apiKey.id }, 'success', { role: body.role });
    return HttpResponse.json(
      { api_key: apiKey, secret: `${prefix}_${hex(rng, 40)}` },
      { status: 201 },
    );
  }),
  http.delete(`${R}/v1/api-keys/:id`, async ({ params }) => {
    await delay(latencyMs);
    const before = db.apiKeys.length;
    db.apiKeys = db.apiKeys.filter((k) => k.id !== params['id']);
    if (db.apiKeys.length === before) return problem(404, 'API key not found');
    audit('api_key.revoke', { type: 'api_key', id: String(params['id']) });
    return new HttpResponse(null, { status: 204 });
  }),

  http.post(`${R}/v1/ws/ticket`, async () => {
    await delay(latencyMs);
    return HttpResponse.json({ ticket: `demo-${hex(rng, 16)}`, expires_in: 60 });
  }),
  http.post('*/api/ws/ticket', async () => {
    await delay(latencyMs);
    return HttpResponse.json({ ticket: `demo-${hex(rng, 16)}`, expires_in: 60, url: null });
  }),
];

// ----------------------------------------------------------------------------------------------
// OTA
// ----------------------------------------------------------------------------------------------

function startCampaign(campaign: Campaign) {
  const targets = db.devices
    .filter((d) => matchesTarget(d.detail, campaign.target))
    .map((d) => d.detail);
  const total = targets.length;
  let assigned = 0;
  const devices: CampaignDevice[] = [];
  campaign.stages.forEach((stage, index) => {
    const cumulative = Math.round((stage.percent / 100) * total);
    const count = Math.max(0, cumulative - assigned);
    stage.counts = emptyCounts();
    stage.counts.targeted = count;
    stage.state = index === 0 ? 'running' : 'pending';
    stage.started_at = index === 0 ? nowIso() : null;
    stage.finished_at = null;
    for (let i = 0; i < count; i += 1) {
      const device = targets[assigned + i];
      if (!device) break;
      devices.push({
        device_id: device.id,
        state: index === 0 ? 'notified' : 'pending',
        progress_pct: 0,
        error: null,
        notified_at: index === 0 ? nowIso() : null,
        updated_at: nowIso(),
        fw_hash_hex: null,
      });
    }
    if (index === 0) stage.counts.notified = count;
    assigned += count;
  });
  db.campaignDevices.set(campaign.id, devices);
  campaign.state = 'running';
  campaign.current_stage = 0;
  campaign.started_at = nowIso();
  campaign.totals = sumCounts(campaign.stages);
}

const otaHandlers = [
  http.get(`${O}/v1/firmware`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const product = url.searchParams.get('product');
    let items = [...db.firmware].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    if (product) items = items.filter((f) => f.product === product);
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
  http.get(`${O}/v1/firmware/:id`, async ({ params }) => {
    await delay(latencyMs);
    const fw = db.firmware.find((f) => f.id === params['id']);
    return fw ? HttpResponse.json(fw) : problem(404, 'Firmware not found');
  }),
  http.post(`${O}/v1/firmware`, async ({ request }) => {
    await delay(latencyMs);
    let form: FormData;
    try {
      form = await request.formData();
    } catch {
      return problem(
        415,
        'Unsupported media type',
        'Expected multipart/form-data with image and metadata parts.',
      );
    }
    const image = form.get('image');
    const metadataRaw = form.get('metadata');
    if (!(image instanceof Blob) || typeof metadataRaw !== 'string') {
      return problem(422, 'Validation failed', undefined, [
        { field: 'image', message: 'image (binary) and metadata (JSON) parts are required' },
      ]);
    }
    let metadata: {
      product?: string;
      version?: string;
      version_code?: number;
      notes?: string;
      severity?: Firmware['severity'];
    };
    try {
      metadata = JSON.parse(metadataRaw);
    } catch {
      return problem(422, 'Validation failed', undefined, [
        { field: 'metadata', message: 'metadata must be JSON' },
      ]);
    }
    const errors: ProblemError[] = [];
    if (!metadata.product) errors.push({ field: 'product', message: 'product is required' });
    if (!metadata.version || !/^\d+\.\d+\.\d+/.test(metadata.version))
      errors.push({ field: 'version', message: 'version must be semver' });
    if (typeof metadata.version_code !== 'number')
      errors.push({ field: 'version_code', message: 'version_code is required' });
    const latest = db.firmware
      .filter((f) => f.product === metadata.product)
      .reduce((max, f) => Math.max(max, f.version_code), 0);
    if (typeof metadata.version_code === 'number' && metadata.version_code <= latest) {
      errors.push({
        field: 'version_code',
        message: `version_code must exceed ${latest} (anti-rollback)`,
      });
    }
    if (errors.length > 0) return problem(422, 'Validation failed', undefined, errors);
    const fw: Firmware = {
      id: uuid(rng),
      product: metadata.product!,
      version: metadata.version!,
      version_code: metadata.version_code!,
      sha256_hex: hex(
        createRng(hashSeed(`${metadata.product}/${metadata.version}/${image.size}`)),
        64,
      ),
      size: image.size,
      created_at: nowIso(),
      created_by: 'user:demo',
      signed_manifest_b64: 'omdwYXlsb2FkWQEA' + 'A'.repeat(40),
      signing_key_id: 'ed25519-2026-01',
      pq_signed: true,
      notes: metadata.notes ?? null,
      severity: metadata.severity ?? 'normal',
    };
    db.firmware.unshift(fw);
    audit('firmware.upload', { type: 'firmware', id: fw.id }, 'success', {
      product: fw.product,
      version: fw.version,
    });
    return HttpResponse.json(fw, { status: 201 });
  }),
  http.get(`${O}/v1/signing-keys`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.signingKeys);
  }),

  http.get(`${O}/v1/campaigns`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const state = url.searchParams.get('state');
    let items = [...db.campaigns].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    if (state) items = items.filter((c) => state.split(',').includes(c.state));
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
  http.post(`${O}/v1/campaigns`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson<{
      name?: string;
      firmware_id?: string;
      target?: Campaign['target'];
      delta?: boolean;
      severity?: Firmware['severity'];
      stages?: Array<{ percent: number; dwell_s: number; max_failure_rate: number }>;
    }>(request);
    const errors: ProblemError[] = [];
    if (!body.name) errors.push({ field: 'name', message: 'name is required' });
    const firmware = db.firmware.find((f) => f.id === body.firmware_id);
    if (!firmware) errors.push({ field: 'firmware_id', message: 'unknown firmware' });
    if (
      !body.target ||
      (body.target.groups.length === 0 &&
        body.target.device_ids.length === 0 &&
        Object.keys(body.target.tags).length === 0)
    ) {
      errors.push({
        field: 'target',
        message: 'target must select at least one group, tag or device',
      });
    }
    const stageInputs = body.stages ?? [
      { percent: 1, dwell_s: 3600, max_failure_rate: 0.05 },
      { percent: 10, dwell_s: 3600, max_failure_rate: 0.05 },
      { percent: 100, dwell_s: 0, max_failure_rate: 0.05 },
    ];
    const parsedStages = stageInputs.map((s) => StageInputSchema.safeParse(s));
    if (parsedStages.some((p) => !p.success))
      errors.push({
        field: 'stages',
        message: 'stages must have integer percent 1..100, dwell_s >= 0 and max_failure_rate 0..1',
      });
    for (const issue of validateStages(stageInputs))
      errors.push({
        field: issue.index === null ? 'stages' : `stages[${issue.index}].${issue.field}`,
        message: issue.message,
      });
    if (errors.length > 0) return problem(422, 'Validation failed', undefined, errors);
    const stages: Stage[] = stageInputs.map((s, index) => ({
      index,
      percent: s.percent,
      dwell_s: s.dwell_s,
      max_failure_rate: s.max_failure_rate,
      state: 'pending',
      started_at: null,
      finished_at: null,
      counts: emptyCounts(),
    }));
    const campaign: Campaign = {
      id: uuid(rng),
      name: body.name!,
      firmware: firmware!,
      target: body.target!,
      delta: body.delta ?? false,
      severity: body.severity ?? firmware!.severity,
      stages,
      current_stage: 0,
      state: 'draft',
      halt_reason: null,
      created_by: 'user:demo',
      created_at: nowIso(),
      started_at: null,
      finished_at: null,
      parent_campaign_id: null,
      totals: emptyCounts(),
    };
    db.campaigns.unshift(campaign);
    db.campaignDevices.set(campaign.id, []);
    audit('campaign.create', { type: 'campaign', id: campaign.id }, 'success', {
      name: campaign.name,
    });
    return HttpResponse.json(campaign, { status: 201 });
  }),
  http.get(`${O}/v1/campaigns/:id`, async ({ params }) => {
    await delay(latencyMs);
    const campaign = db.campaigns.find((c) => c.id === params['id']);
    return campaign ? HttpResponse.json(campaign) : problem(404, 'Campaign not found');
  }),
  http.post(`${O}/v1/campaigns/:id/:action`, async ({ params, request }) => {
    await delay(latencyMs);
    const campaign = db.campaigns.find((c) => c.id === params['id']);
    if (!campaign) return problem(404, 'Campaign not found');
    const action = String(params['action']);
    const body = await readJson<{ reason?: string }>(request);
    switch (action) {
      case 'start':
        if (campaign.state !== 'draft')
          return problem(409, 'Conflict', `Cannot start a campaign in state ${campaign.state}.`);
        startCampaign(campaign);
        break;
      case 'pause':
        if (campaign.state !== 'running')
          return problem(409, 'Conflict', 'Only running campaigns can be paused.');
        campaign.state = 'paused';
        break;
      case 'resume':
        if (campaign.state !== 'paused')
          return problem(409, 'Conflict', 'Only paused campaigns can be resumed.');
        campaign.state = 'running';
        break;
      case 'cancel':
        if (!['draft', 'running', 'paused'].includes(campaign.state))
          return problem(409, 'Conflict', `Cannot cancel a campaign in state ${campaign.state}.`);
        campaign.state = 'cancelled';
        campaign.finished_at = nowIso();
        break;
      case 'halt':
        if (!['running', 'paused'].includes(campaign.state))
          return problem(409, 'Conflict', 'Only running or paused campaigns can be halted.');
        if (!body.reason)
          return problem(422, 'Validation failed', undefined, [
            { field: 'reason', message: 'reason is required' },
          ]);
        campaign.state = 'halted';
        campaign.halt_reason = body.reason;
        campaign.finished_at = nowIso();
        for (const stage of campaign.stages)
          if (stage.state === 'running' || stage.state === 'dwelling') stage.state = 'halted';
        break;
      case 'rollback': {
        if (!['running', 'paused', 'halted', 'completed'].includes(campaign.state))
          return problem(
            409,
            'Conflict',
            `Cannot roll back a campaign in state ${campaign.state}.`,
          );
        if (!body.reason)
          return problem(422, 'Validation failed', undefined, [
            { field: 'reason', message: 'reason is required' },
          ]);
        const previous =
          db.firmware
            .filter(
              (f) =>
                f.product === campaign.firmware.product &&
                f.version_code < campaign.firmware.version_code,
            )
            .sort((a, b) => b.version_code - a.version_code)[0] ?? campaign.firmware;
        const rollbackFirmware: Firmware = {
          ...previous,
          id: uuid(rng),
          version_code: campaign.firmware.version_code + 1,
          created_at: nowIso(),
          notes: `Rollback re-sign of ${previous.version} (parent ${campaign.id})`,
        };
        db.firmware.unshift(rollbackFirmware);
        const child: Campaign = {
          id: uuid(rng),
          name: `Rollback: ${campaign.name}`,
          firmware: rollbackFirmware,
          target: campaign.target,
          delta: false,
          severity: 'security',
          stages: [
            {
              index: 0,
              percent: 100,
              dwell_s: 0,
              max_failure_rate: 1,
              state: 'pending',
              started_at: null,
              finished_at: null,
              counts: emptyCounts(),
            },
          ],
          current_stage: 0,
          state: 'draft',
          halt_reason: null,
          created_by: 'user:demo',
          created_at: nowIso(),
          started_at: null,
          finished_at: null,
          parent_campaign_id: campaign.id,
          totals: emptyCounts(),
        };
        startCampaign(child);
        db.campaigns.unshift(child);
        campaign.state = 'rolled_back';
        campaign.halt_reason = body.reason;
        campaign.finished_at = nowIso();
        audit('campaign.rollback', { type: 'campaign', id: campaign.id }, 'success', {
          reason: body.reason,
          child: child.id,
        });
        return HttpResponse.json(child, { status: 201 });
      }
      default:
        return problem(404, 'Not found');
    }
    audit(
      `campaign.${action}`,
      { type: 'campaign', id: campaign.id },
      'success',
      body.reason ? { reason: body.reason } : {},
    );
    return HttpResponse.json(campaign);
  }),
  http.get(`${O}/v1/campaigns/:id/devices`, async ({ params, request }) => {
    await delay(latencyMs);
    const campaign = db.campaigns.find((c) => c.id === params['id']);
    if (!campaign) return problem(404, 'Campaign not found');
    const url = new URL(request.url);
    const state = url.searchParams.get('state');
    let items = db.campaignDevices.get(campaign.id) ?? [];
    if (state) items = items.filter((d) => d.state === state);
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
  http.get(`${O}/v1/campaigns/:id/audit`, async ({ params, request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const items = db.audit.filter(
      (e) => e.target.type === 'campaign' && e.target.id === params['id'],
    );
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
];

// ----------------------------------------------------------------------------------------------
// Anomaly
// ----------------------------------------------------------------------------------------------

const anomalyHandlers = [
  http.get(`${A}/v1/alerts`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const get = (k: string) => url.searchParams.get(k);
    let items = db.alerts;
    if (get('state')) items = items.filter((a) => get('state')!.split(',').includes(a.state));
    if (get('severity'))
      items = items.filter((a) => get('severity')!.split(',').includes(a.severity));
    if (get('rule')) items = items.filter((a) => a.rule === get('rule'));
    if (get('device_id')) items = items.filter((a) => a.device_id === get('device_id'));
    if (get('from')) items = items.filter((a) => a.created_at >= get('from')!);
    if (get('to')) items = items.filter((a) => a.created_at <= get('to')!);
    return HttpResponse.json(paginate(items, get('cursor'), get('limit')));
  }),
  http.get(`${A}/v1/alerts/:id`, async ({ params }) => {
    await delay(latencyMs);
    const alert = db.alerts.find((a) => a.id === params['id']);
    return alert ? HttpResponse.json(alert) : problem(404, 'Alert not found');
  }),
  http.post(`${A}/v1/alerts/:id/ack`, async ({ params, request }) => {
    await delay(latencyMs);
    const alert = db.alerts.find((a) => a.id === params['id']);
    if (!alert) return problem(404, 'Alert not found');
    if (alert.state !== 'open') return problem(409, 'Conflict', `Alert is already ${alert.state}.`);
    const { note } = await readJson<{ note?: string }>(request);
    alert.state = 'acked';
    alert.acked_by = 'user:demo';
    audit('alert.ack', { type: 'alert', id: alert.id }, 'success', { note });
    return HttpResponse.json(alert);
  }),
  http.post(`${A}/v1/alerts/:id/resolve`, async ({ params, request }) => {
    await delay(latencyMs);
    const alert = db.alerts.find((a) => a.id === params['id']);
    if (!alert) return problem(404, 'Alert not found');
    if (alert.state === 'resolved') return problem(409, 'Conflict', 'Alert is already resolved.');
    const { note, false_positive } = await readJson<{ note?: string; false_positive?: boolean }>(
      request,
    );
    alert.state = 'resolved';
    alert.resolved_by = 'user:demo';
    alert.false_positive = Boolean(false_positive);
    const device = findDevice(alert.device_id);
    if (device && device.detail.open_alerts > 0) device.detail.open_alerts -= 1;
    audit('alert.resolve', { type: 'alert', id: alert.id }, 'success', {
      note,
      false_positive: Boolean(false_positive),
    });
    return HttpResponse.json(alert);
  }),
  http.get(`${A}/v1/rules`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.rules);
  }),
  http.put(`${A}/v1/rules/:name`, async ({ params, request }) => {
    await delay(latencyMs);
    const rule = db.rules.find((r) => r.name === params['name']);
    if (!rule) return problem(404, 'Rule not found');
    Object.assign(rule, await readJson(request));
    return HttpResponse.json(rule);
  }),
  http.get(`${A}/v1/devices/:id/baseline`, async ({ params }) => {
    await delay(latencyMs);
    const device = findDevice(String(params['id']));
    if (!device) return problem(404, 'Device not found');
    const r = createRng(hashSeed(`baseline:${device.detail.id}`));
    const hasAlert = db.alerts.some((a) => a.device_id === device.detail.id);
    const now = Date.now();
    const recent: Array<[string, number]> = [];
    for (let i = 47; i >= 0; i -= 1) {
      let score = 0.15 + r() * 0.2;
      if (hasAlert && i < 6) score = 0.55 + r() * 0.4;
      recent.push([iso(now - i * 3_600_000), Number(score.toFixed(3))]);
    }
    return HttpResponse.json({
      device_class: device.detail.product,
      samples: 12_480 + Math.round(r() * 4000),
      trained_at: iso(now - 9 * 3_600_000),
      score_threshold: 0.6,
      feature_means: {
        cpu_pct: 31.2,
        mem_pct: 54.8,
        temp_c: 44.1,
        net_tx_ratio: 1.0,
        auth_failures: 0.1,
        msgs_per_min: 2.0,
      },
      recent_scores: recent,
    });
  }),
  http.get(`${A}/v1/quarantine`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    return HttpResponse.json(
      paginate(db.quarantine, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
  http.get(`${A}/v1/settings`, async () => {
    await delay(latencyMs);
    return HttpResponse.json({
      auto_quarantine: db.tenant.settings.auto_quarantine,
      quarantine_min_severity: 'high',
      siem: {
        ecs_webhook_url: 'https://siem.acme.example/ecs',
        syslog_host: null,
        syslog_port: null,
        enabled: true,
      },
    });
  }),
];

// ----------------------------------------------------------------------------------------------
// Policy
// ----------------------------------------------------------------------------------------------

const policyHandlers = [
  http.get(`${P}/v1/policy`, async () => {
    await delay(latencyMs);
    return HttpResponse.json(db.policy);
  }),
  http.put(`${P}/v1/policy`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson<{ rego?: string; message?: string }>(request);
    if (typeof body.rego !== 'string' || body.rego.trim().length === 0) {
      return problem(422, 'Validation failed', undefined, [
        { field: 'rego', message: 'rego source is required' },
      ]);
    }
    const diagnostics = compilePolicy(body.rego);
    if (diagnostics.length > 0) {
      audit('policy.put', { type: 'policy', id: 'tenant-policy' }, 'failure', {
        diagnostics: diagnostics.length,
      });
      return problem(
        422,
        'Policy rejected',
        'The policy did not compile or failed a built-in invariant test.',
        diagnostics.map((d) => ({ line: d.line, col: d.col, message: d.message })),
      );
    }
    const version = db.policy.version + 1;
    const sha = hex(createRng(hashSeed(body.rego)), 64);
    db.policy = {
      version,
      updated_at: nowIso(),
      updated_by: 'user:demo',
      rego: body.rego,
      sha256_hex: sha,
    };
    db.policyHistory.unshift({
      version,
      updated_at: db.policy.updated_at,
      updated_by: 'user:demo',
      message: body.message ?? null,
      sha256_hex: sha,
    });
    audit('policy.put', { type: 'policy', id: 'tenant-policy' }, 'success', { version });
    return HttpResponse.json({ version, sha256_hex: sha });
  }),
  http.post(`${P}/v1/policy/evaluate`, async ({ request }) => {
    await delay(latencyMs);
    const body = await readJson<{ input?: Record<string, unknown> }>(request);
    const input = body.input;
    if (!input || typeof input['topic'] !== 'string')
      return problem(422, 'Validation failed', undefined, [
        { field: 'input.topic', message: 'topic is required' },
      ]);
    const result = evaluatePolicy({
      clientid: String(input['clientid'] ?? ''),
      username: String(input['username'] ?? ''),
      tenant_id: String(input['tenant_id'] ?? ''),
      device_id: String(input['device_id'] ?? ''),
      kind: String(input['kind'] ?? 'device'),
      topic: String(input['topic']),
      action: String(input['action'] ?? 'publish'),
      qos: Number(input['qos'] ?? 0),
      retain: Boolean(input['retain']),
    });
    return HttpResponse.json({ ...result, evaluated_version: db.policy.version });
  }),
  http.get(`${P}/v1/policy/history`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    return HttpResponse.json(
      paginate(db.policyHistory, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
  http.get(`${P}/v1/revocations`, async ({ request }) => {
    await delay(latencyMs);
    const url = new URL(request.url);
    const items = db.devices
      .flatMap((d) =>
        d.detail.certificates
          .filter((c) => c.revoked_at)
          .map((c) => ({
            serial_hex: c.serial_hex,
            device_id: d.detail.id,
            tenant_id: DEMO_TENANT_ID,
            reason: c.revocation_reason ?? 'unspecified',
            revoked_at: c.revoked_at!,
            applied_at: c.revoked_at,
            kicked: true,
          })),
      )
      .sort((a, b) => (a.revoked_at < b.revoked_at ? 1 : -1));
    return HttpResponse.json(
      paginate(items, url.searchParams.get('cursor'), url.searchParams.get('limit')),
    );
  }),
];

// ----------------------------------------------------------------------------------------------
// WebSocket feed (DESIGN §1.11)
// ----------------------------------------------------------------------------------------------

function frame(type: string, data: unknown) {
  return JSON.stringify({ type, at: nowIso(), data });
}

function sampleFor(deviceId: string) {
  const device = findDevice(deviceId);
  if (!device) return null;
  const r = Math.random;
  const last = device.detail.last_telemetry;
  const sample = {
    ts: nowIso(),
    cpu_pct: Number(Math.max(1, Math.min(99, (last?.cpu_pct ?? 30) + (r() - 0.5) * 8)).toFixed(1)),
    mem_pct: Number(Math.max(5, Math.min(99, (last?.mem_pct ?? 50) + (r() - 0.5) * 3)).toFixed(1)),
    temp_c: Number(((last?.temp_c ?? 45) + (r() - 0.5) * 1.5).toFixed(1)),
    net_rx_bytes: Math.round((last?.net_rx_bytes ?? 1_000_000) + r() * 40_000),
    net_tx_bytes: Math.round((last?.net_tx_bytes ?? 500_000) + r() * 15_000),
    uptime_s: (last?.uptime_s ?? 3600) + 2,
    auth_failures: 0,
    fw_version: device.detail.fw_version,
    ...(device.platform === 'esp32'
      ? {
          rssi: Math.round((last?.rssi ?? -60) + (r() - 0.5) * 4),
          free_heap: Math.round((last?.free_heap ?? 120_000) + (r() - 0.5) * 2_000),
        }
      : { proc_count: last?.proc_count ?? 120 }),
  };
  device.detail.last_telemetry = sample;
  return sample;
}

function wsHandlersFor(url: string) {
  const link = ws.link(url);
  return link.addEventListener('connection', ({ client }) => {
    const topics = new Set<string>(['fleet', 'alerts']);
    const timers: Array<ReturnType<typeof setInterval>> = [];

    client.addEventListener('message', (event) => {
      if (typeof event.data !== 'string') return;
      try {
        const message = JSON.parse(event.data) as { type?: string; topics?: string[] };
        if (message.type === 'ping') client.send(frame('pong', {}));
        if (message.type === 'subscribe') for (const t of message.topics ?? []) topics.add(t);
        if (message.type === 'unsubscribe') for (const t of message.topics ?? []) topics.delete(t);
      } catch {
        // ignore malformed client frames
      }
    });

    // Connect / disconnect churn across the active fleet.
    timers.push(
      setInterval(() => {
        const active = db.devices.filter((d) => d.detail.state === 'active');
        const device = active[Math.floor(Math.random() * active.length)];
        if (!device) return;
        device.detail.connected = !device.detail.connected;
        device.detail.last_seen_at = nowIso();
        if (topics.has('fleet') || topics.has(`device:${device.detail.id}`)) {
          client.send(
            frame(device.detail.connected ? 'device.connected' : 'device.disconnected', {
              device_id: device.detail.id,
              product: device.detail.product,
              connected: device.detail.connected,
              peerhost: '185.12.44.9',
            }),
          );
        }
        timeline(
          device.detail.id,
          device.detail.connected ? 'connect' : 'disconnect',
          device.detail.connected
            ? 'Connected (TLS 1.3, MQTT 5)'
            : 'Disconnected: keep-alive timeout',
        );
      }, 5_000),
    );

    // Sampled telemetry for subscribed devices (1 frame / s / device max).
    timers.push(
      setInterval(() => {
        for (const topic of topics) {
          if (!topic.startsWith('device:')) continue;
          const sample = sampleFor(topic.slice('device:'.length));
          if (sample)
            client.send(
              frame('device.telemetry', { device_id: topic.slice('device:'.length), sample }),
            );
        }
      }, 2_000),
    );

    // Running campaigns make progress.
    timers.push(
      setInterval(() => {
        for (const campaign of db.campaigns.filter((c) => c.state === 'running')) {
          const stage = campaign.stages[campaign.current_stage];
          const devices = db.campaignDevices.get(campaign.id) ?? [];
          const inFlight = devices.filter((d) =>
            ['notified', 'downloading', 'verifying', 'applying'].includes(d.state),
          );
          const next = inFlight[Math.floor(Math.random() * inFlight.length)];
          if (stage && next) {
            const order: CampaignDevice['state'][] = [
              'notified',
              'downloading',
              'verifying',
              'applying',
              'success',
            ];
            const idx = order.indexOf(next.state);
            const before = next.state;
            next.state = order[Math.min(idx + 1, order.length - 1)] ?? 'success';
            next.progress_pct =
              next.state === 'success' ? 100 : Math.min(95, next.progress_pct + 25);
            next.updated_at = nowIso();
            if (next.state === 'success') next.fw_hash_hex = campaign.firmware.sha256_hex;
            const counts = stage.counts as unknown as Record<string, number>;
            if (before in counts && before !== 'notified')
              counts[before] = Math.max(0, (counts[before] ?? 0) - 1);
            if (next.state in counts) counts[next.state] = (counts[next.state] ?? 0) + 1;
            campaign.totals = sumCounts(campaign.stages);
            if (topics.has('fleet') || topics.has(`campaign:${campaign.id}`)) {
              client.send(
                frame('campaign.updated', {
                  id: campaign.id,
                  state: campaign.state,
                  current_stage: campaign.current_stage,
                  totals: campaign.totals,
                }),
              );
            }
          }
        }
      }, 8_000),
    );

    // Occasional new alert.
    timers.push(
      setInterval(() => {
        const active = db.devices.filter((d) => d.detail.state === 'active');
        const device = active[Math.floor(Math.random() * active.length)];
        if (!device) return;
        const alert: Alert = {
          id: uuid(rng),
          tenant_id: DEMO_TENANT_ID,
          device_id: device.detail.id,
          rule: 'isolation_forest',
          severity: 'medium',
          score: Number((0.62 + Math.random() * 0.2).toFixed(2)),
          features: { cpu_pct: 88.1, net_tx_ratio: 2.4, proc_count: 131 },
          explanation:
            'Telemetry vector is an outlier for the device class: sustained CPU above 85% with elevated egress.',
          created_at: nowIso(),
          state: 'open',
          acked_by: null,
          resolved_by: null,
          actions: [{ type: 'notify', at: nowIso(), result: 'SIEM webhook 200' }],
        };
        db.alerts.unshift(alert);
        device.detail.open_alerts += 1;
        timeline(device.detail.id, 'alert', `Alert raised: ${alert.rule} (${alert.severity})`, {
          alert_id: alert.id,
        });
        if (topics.has('alerts'))
          client.send(
            frame('alert.created', {
              id: alert.id,
              device_id: alert.device_id,
              severity: alert.severity,
              rule: alert.rule,
            }),
          );
      }, 45_000),
    );

    client.addEventListener('close', () => {
      for (const timer of timers) clearInterval(timer);
    });
  });
}

export const wsHandlers = [wsHandlersFor('ws://*/v1/ws'), wsHandlersFor('wss://*/v1/ws')];

export const httpHandlers = [
  ...registryHandlers,
  ...otaHandlers,
  ...anomalyHandlers,
  ...policyHandlers,
];

export const handlers = [...httpHandlers, ...wsHandlers];

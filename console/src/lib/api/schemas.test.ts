import { describe, expect, it } from 'vitest';
import { buildFixtures } from '@/mocks/fixtures';
import {
  AlertSchema,
  AuditEventSchema,
  CampaignSchema,
  DeviceDetailSchema,
  DeviceSummarySchema,
  FirmwareSchema,
  PolicyDocumentSchema,
  PolicyEvaluateInputSchema,
  ProblemDetailsSchema,
  SendCommandInputSchema,
  StageInputSchema,
  TelemetrySeriesSchema,
  TwinSchema,
  WsFrameSchema,
  WsTicketSchema,
  pageSchema,
} from './schemas';

const fixtures = buildFixtures(Date.UTC(2026, 10, 1));

describe('contract schemas accept the fixture data', () => {
  it('devices (summary and detail)', () => {
    for (const device of fixtures.devices) {
      expect(DeviceDetailSchema.safeParse(device.detail).success).toBe(true);
      expect(DeviceSummarySchema.safeParse(device.detail).success).toBe(true);
    }
    expect(fixtures.devices).toHaveLength(50);
    const states = new Set(fixtures.devices.map((d) => d.detail.state));
    expect([...states].sort()).toEqual([
      'active',
      'decommissioned',
      'manufactured',
      'provisioned',
      'quarantined',
    ]);
  });

  it('twins, campaigns, firmware, alerts, audit and policy', () => {
    for (const device of fixtures.devices)
      expect(TwinSchema.safeParse(device.twin).success).toBe(true);
    expect(fixtures.campaigns).toHaveLength(3);
    for (const campaign of fixtures.campaigns)
      expect(CampaignSchema.safeParse(campaign).success).toBe(true);
    for (const fw of fixtures.firmware) expect(FirmwareSchema.safeParse(fw).success).toBe(true);
    expect(fixtures.alerts).toHaveLength(12);
    for (const alert of fixtures.alerts) expect(AlertSchema.safeParse(alert).success).toBe(true);
    for (const event of fixtures.audit)
      expect(AuditEventSchema.safeParse(event).success).toBe(true);
    expect(PolicyDocumentSchema.safeParse(fixtures.policy).success).toBe(true);
    expect(fixtures.policy.rego).toContain('package ironmesh.mqtt');
  });
});

describe('schema strictness', () => {
  it('rejects unknown lifecycle states', () => {
    const device = { ...fixtures.devices[0]!.detail, state: 'sleeping' };
    const result = DeviceSummarySchema.safeParse(device);
    expect(result.success).toBe(false);
  });

  it('validates cursor pages', () => {
    const Page = pageSchema(DeviceSummarySchema);
    expect(Page.safeParse({ items: [], next_cursor: null }).success).toBe(true);
    expect(Page.safeParse({ items: [], next_cursor: 5 }).success).toBe(false);
    expect(Page.safeParse({ items: [] }).success).toBe(false);
  });

  it('accepts telemetry points with string or epoch timestamps and null values', () => {
    const result = TelemetrySeriesSchema.safeParse({
      series: [
        {
          metric: 'cpu_pct',
          points: [
            ['2026-11-01T00:00:00Z', 12.5],
            [1762000000, null],
          ],
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('enforces command TTL bounds and name format', () => {
    expect(SendCommandInputSchema.safeParse({ name: 'reboot', args: {}, ttl_s: 29 }).success).toBe(
      false,
    );
    expect(
      SendCommandInputSchema.safeParse({ name: 'Reboot Now', args: {}, ttl_s: 300 }).success,
    ).toBe(false);
    expect(
      SendCommandInputSchema.safeParse({
        name: 'set_log_level',
        args: { level: 'debug' },
        ttl_s: 86400,
      }).success,
    ).toBe(true);
  });

  it('bounds stage inputs', () => {
    expect(
      StageInputSchema.safeParse({ percent: 0, dwell_s: 0, max_failure_rate: 0 }).success,
    ).toBe(false);
    expect(
      StageInputSchema.safeParse({ percent: 10, dwell_s: -1, max_failure_rate: 0 }).success,
    ).toBe(false);
    expect(
      StageInputSchema.safeParse({ percent: 10, dwell_s: 0, max_failure_rate: 1.5 }).success,
    ).toBe(false);
    expect(
      StageInputSchema.safeParse({ percent: 100, dwell_s: 0, max_failure_rate: 0.05 }).success,
    ).toBe(true);
  });

  it('validates policy evaluation input', () => {
    const base = {
      clientid: 'dev-0000000000000001',
      username: 'dev-0000000000000001',
      tenant_id: 't',
      device_id: 'dev-0000000000000001',
      kind: 'device',
      topic: 'im/v1/t/dev-0000000000000001/telemetry',
      action: 'publish',
      qos: 1,
      retain: false,
    };
    expect(PolicyEvaluateInputSchema.safeParse(base).success).toBe(true);
    expect(PolicyEvaluateInputSchema.safeParse({ ...base, qos: 3 }).success).toBe(false);
    expect(PolicyEvaluateInputSchema.safeParse({ ...base, action: 'delete' }).success).toBe(false);
  });

  it('parses problem details and WebSocket frames loosely', () => {
    expect(ProblemDetailsSchema.safeParse({ title: 'x', status: 400, extra: true }).success).toBe(
      true,
    );
    expect(ProblemDetailsSchema.safeParse({ status: 400 }).success).toBe(false);
    expect(
      WsFrameSchema.safeParse({ type: 'device.connected', at: 'now', data: { device_id: 'd' } })
        .success,
    ).toBe(true);
    expect(WsFrameSchema.safeParse({ type: 'device.connected' }).success).toBe(false);
  });
});

describe('WebSocket ticket schema', () => {
  it('accepts a ticket whose url is null (no NEXT_PUBLIC_WS_URL configured)', () => {
    const parsed = WsTicketSchema.safeParse({ ticket: 't-1', expires_in: 60, url: null });
    expect(parsed.success).toBe(true);
  });

  it('accepts a ticket with an explicit url or no url field', () => {
    expect(
      WsTicketSchema.safeParse({ ticket: 't-2', expires_in: 60, url: 'wss://fleet.example/v1/ws' })
        .success,
    ).toBe(true);
    expect(WsTicketSchema.safeParse({ ticket: 't-3', expires_in: 60 }).success).toBe(true);
  });
});

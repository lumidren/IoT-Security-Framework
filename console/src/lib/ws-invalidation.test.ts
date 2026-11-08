import { describe, expect, it } from 'vitest';
import { QueryClient } from '@tanstack/react-query';
import { queryKeys } from '@/lib/api/keys';
import { applyTelemetryFrame } from '@/providers/ws-provider';
import { invalidationsFor } from './ws-invalidation';

describe('invalidationsFor', () => {
  it('maps connectivity frames to fleet, list and device keys', () => {
    const keys = invalidationsFor({
      type: 'device.connected',
      at: 'now',
      data: { device_id: 'dev-1' },
    });
    expect(keys).toContainEqual(queryKeys.fleet.all);
    expect(keys).toContainEqual(queryKeys.devices.lists());
    expect(keys).toContainEqual(queryKeys.devices.detail('dev-1'));
  });

  it('maps state changes to provisioning and quarantine as well', () => {
    const keys = invalidationsFor({
      type: 'device.state_changed',
      at: 'now',
      data: { device_id: 'dev-1', state: 'quarantined' },
    });
    expect(keys).toContainEqual(queryKeys.provisioning.all);
    expect(keys).toContainEqual(queryKeys.quarantine.all);
  });

  it('maps alert, campaign, command, twin, provisioning and audit frames', () => {
    expect(
      invalidationsFor({ type: 'alert.created', at: 'n', data: { id: 'a1', device_id: 'dev-1' } }),
    ).toEqual(
      expect.arrayContaining([
        queryKeys.alerts.lists(),
        queryKeys.alerts.detail('a1'),
        queryKeys.devices.timeline('dev-1'),
      ]),
    );
    expect(invalidationsFor({ type: 'campaign.updated', at: 'n', data: { id: 'c1' } })).toEqual(
      expect.arrayContaining([queryKeys.campaigns.lists(), queryKeys.campaigns.detail('c1')]),
    );
    expect(
      invalidationsFor({
        type: 'command.updated',
        at: 'n',
        data: { device_id: 'dev-1', cmd_id: 'k' },
      }),
    ).toEqual(
      expect.arrayContaining([queryKeys.devices.commands('dev-1'), queryKeys.commands.detail('k')]),
    );
    expect(
      invalidationsFor({ type: 'twin.updated', at: 'n', data: { device_id: 'dev-1' } }),
    ).toEqual([queryKeys.devices.twin('dev-1')]);
    expect(invalidationsFor({ type: 'provisioning.updated', at: 'n', data: {} })).toContainEqual(
      queryKeys.provisioning.all,
    );
    expect(invalidationsFor({ type: 'audit.created', at: 'n', data: {} })).toEqual([
      queryKeys.audit.all,
    ]);
  });

  it('ignores telemetry and unknown frames', () => {
    expect(invalidationsFor({ type: 'device.telemetry', at: 'n', data: {} })).toEqual([]);
    expect(invalidationsFor({ type: 'something.else', at: 'n', data: {} })).toEqual([]);
  });
});

describe('applyTelemetryFrame', () => {
  it('appends samples to cached series and updates the device snapshot', () => {
    const client = new QueryClient();
    const key = queryKeys.devices.telemetry('dev-1', { metrics: ['cpu_pct'] });
    client.setQueryData(key, {
      series: [
        { metric: 'cpu_pct', points: [['2026-01-01T00:00:00Z', 10]] },
        { metric: 'temp_c', points: [] },
      ],
    });
    client.setQueryData(queryKeys.devices.detail('dev-1'), {
      id: 'dev-1',
      connected: false,
      last_telemetry: null,
    });
    applyTelemetryFrame(client, {
      type: 'device.telemetry',
      at: 'now',
      data: { device_id: 'dev-1', sample: { ts: '2026-01-01T00:01:00Z', cpu_pct: 42 } },
    });
    const series = client.getQueryData<{ series: Array<{ metric: string; points: unknown[] }> }>(
      key,
    );
    expect(series?.series[0]?.points).toHaveLength(2);
    expect(series?.series[0]?.points[1]).toEqual(['2026-01-01T00:01:00Z', 42]);
    expect(series?.series[1]?.points).toHaveLength(0);
    const device = client.getQueryData<{ connected: boolean; last_telemetry: { cpu_pct: number } }>(
      queryKeys.devices.detail('dev-1'),
    );
    expect(device?.connected).toBe(true);
    expect(device?.last_telemetry.cpu_pct).toBe(42);
  });

  it('ignores malformed telemetry payloads', () => {
    const client = new QueryClient();
    const key = queryKeys.devices.telemetry('dev-1');
    client.setQueryData(key, { series: [{ metric: 'cpu_pct', points: [] }] });
    applyTelemetryFrame(client, { type: 'device.telemetry', at: 'now', data: { nope: true } });
    expect(
      client.getQueryData<{ series: Array<{ points: unknown[] }> }>(key)?.series[0]?.points,
    ).toHaveLength(0);
  });
});

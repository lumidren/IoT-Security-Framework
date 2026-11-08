import type { DeviceDetail, DeviceSummary, TelemetrySeries } from '@/lib/api/schemas';
import { buildFixtures, type Fixtures } from './fixtures';
import { createRng, hashSeed } from './fixtures/seed';

/** Mutable in-memory state behind the mock handlers. Reset between tests with `resetDb()`. */
export let db: Fixtures = buildFixtures();

export function resetDb(now?: number): Fixtures {
  db = buildFixtures(now);
  return db;
}

export function summaryOf(detail: DeviceDetail): DeviceSummary {
  const {
    id,
    tenant_id,
    product,
    hw_revision,
    state,
    assurance_level,
    se_type,
    groups,
    tags,
    connected,
    last_seen_at,
    fw_version,
    fw_hash_hex,
    cert,
    location,
    open_alerts,
  } = detail;
  return {
    id,
    tenant_id,
    product,
    hw_revision,
    state,
    assurance_level,
    se_type,
    groups,
    tags,
    connected,
    last_seen_at,
    fw_version,
    fw_hash_hex,
    cert,
    location,
    open_alerts,
  };
}

export function findDevice(id: string) {
  return db.devices.find((d) => d.detail.id === id) ?? null;
}

/** Opaque cursor = base64 offset, like the services. */
export function encodeCursor(offset: number): string {
  return typeof btoa === 'function'
    ? btoa(String(offset))
    : Buffer.from(String(offset), 'utf8').toString('base64');
}

export function decodeCursor(cursor: string | null): number {
  if (!cursor) return 0;
  try {
    const raw =
      typeof atob === 'function' ? atob(cursor) : Buffer.from(cursor, 'base64').toString('utf8');
    const n = Number.parseInt(raw, 10);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
}

export function paginate<T>(
  items: T[],
  cursor: string | null,
  limitRaw: string | null,
  defaultLimit = 50,
) {
  const limit = Math.min(Math.max(Number.parseInt(limitRaw ?? '', 10) || defaultLimit, 1), 200);
  const offset = decodeCursor(cursor);
  const page = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? encodeCursor(offset + limit) : null;
  return { items: page, next_cursor: next };
}

const STEP_SECONDS: Record<string, number> = {
  '10s': 10,
  '30s': 30,
  '60s': 60,
  '5m': 300,
  '15m': 900,
  '1h': 3600,
};

/** Smooth, deterministic telemetry series per device and metric. */
export function telemetryFor(
  deviceId: string,
  from: number,
  to: number,
  metrics: string[],
  step: string,
): TelemetrySeries {
  const stepS = STEP_SECONDS[step] ?? Math.max(10, Math.round((to - from) / 1000 / 300));
  const maxPoints = 2000;
  let stepMs = stepS * 1000;
  if ((to - from) / stepMs > maxPoints) stepMs = Math.ceil((to - from) / maxPoints);
  const base = createRng(hashSeed(deviceId));
  const offsets = {
    cpu: 15 + base() * 30,
    mem: 30 + base() * 35,
    temp: 36 + base() * 15,
    rssi: -(50 + base() * 30),
    heap: 90_000 + base() * 60_000,
  };
  return {
    series: metrics.map((metric) => {
      const points: Array<[string, number | null]> = [];
      let rx = 1_000_000 + base() * 500_000;
      let tx = 400_000 + base() * 200_000;
      for (let t = from; t <= to; t += stepMs) {
        const phase = t / 3_600_000;
        const noise =
          createRng(hashSeed(`${deviceId}:${metric}:${Math.floor(t / stepMs)}`))() - 0.5;
        let value: number;
        switch (metric) {
          case 'cpu_pct':
            value = Math.max(
              2,
              Math.min(98, offsets.cpu + 12 * Math.sin(phase * 2.1) + noise * 14),
            );
            break;
          case 'mem_pct':
            value = Math.max(10, Math.min(95, offsets.mem + 6 * Math.sin(phase * 0.7) + noise * 4));
            break;
          case 'temp_c':
            value = offsets.temp + 4 * Math.sin(phase * 0.9) + noise * 2;
            break;
          case 'net_rx_bytes':
            rx += Math.max(0, 20_000 + noise * 30_000) * (stepMs / 60_000);
            value = Math.round(rx);
            break;
          case 'net_tx_bytes':
            tx += Math.max(0, 8_000 + noise * 12_000) * (stepMs / 60_000);
            value = Math.round(tx);
            break;
          case 'rssi':
            value = Math.round(offsets.rssi + 5 * Math.sin(phase * 1.3) + noise * 6);
            break;
          case 'free_heap':
            value = Math.round(offsets.heap - 300 * (phase % 24) + noise * 4_000);
            break;
          default:
            value = noise;
        }
        points.push([new Date(t).toISOString(), Number(value.toFixed(2))]);
      }
      return { metric, points };
    }),
  };
}

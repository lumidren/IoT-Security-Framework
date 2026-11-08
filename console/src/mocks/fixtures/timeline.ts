import type { DeviceConfig, TimelineEvent } from '@/lib/api/schemas';
import { DAY, HOUR, createRng, hashSeed, int, iso, pick, uuid } from './seed';
import type { DeviceFixture } from './devices';

export function buildTimelines(
  now: number,
  devices: DeviceFixture[],
): Map<string, TimelineEvent[]> {
  const out = new Map<string, TimelineEvent[]>();
  for (const device of devices) {
    const d = device.detail;
    const rng = createRng(hashSeed(`timeline:${d.id}`));
    const events: TimelineEvent[] = [];
    const push = (
      at: string,
      kind: TimelineEvent['kind'],
      summary: string,
      data: Record<string, unknown> = {},
    ) => events.push({ id: uuid(rng), at, kind, summary, data });

    push(d.created_at, 'lifecycle', 'Device manufactured; bootstrap certificate issued', {
      state: 'manufactured',
      bootstrap_serial_hex: d.bootstrap_serial_hex,
    });
    if (d.provisioned_at) {
      push(d.provisioned_at, 'enroll', 'EST simpleenroll succeeded (attestation verified)', {
        se_type: d.se_type,
        assurance_level: d.assurance_level,
      });
      push(d.provisioned_at, 'lifecycle', 'State changed manufactured → provisioned', {
        state: 'provisioned',
      });
    }
    if (d.activated_at) {
      push(d.activated_at, 'lifecycle', 'State changed provisioned → active', { state: 'active' });
    }
    if (d.state === 'active' || d.state === 'quarantined' || d.state === 'decommissioned') {
      const sessions = int(rng, 6, 14);
      let t = now - int(rng, 20, 60) * DAY;
      for (let i = 0; i < sessions; i += 1) {
        t += int(rng, 6, 70) * HOUR;
        if (t > now - HOUR) break;
        push(
          iso(t),
          'connect',
          `Connected from ${pick(rng, ['185.12.44.9', '91.198.174.192', '203.0.113.71', '10.44.2.19'])} (TLS 1.3, MQTT 5)`,
          { peerhost: '185.12.44.9' },
        );
        if (rng() < 0.6)
          push(
            iso(t + int(rng, 1, 5) * HOUR),
            'disconnect',
            `Disconnected: ${pick(rng, ['keep-alive timeout', 'client initiated', 'network change'])}`,
          );
        if (rng() < 0.25) {
          push(
            iso(t + 30 * 60_000),
            'command',
            `Command ${pick(rng, ['reboot', 'rotate_logs', 'set_log_level'])} acknowledged`,
            { status: 'acked' },
          );
        }
        if (rng() < 0.2) {
          push(iso(t + 40 * 60_000), 'twin', 'Desired state updated (telemetry_interval_s)', {
            version: d.twin_version,
          });
        }
        if (rng() < 0.15) {
          push(iso(t + 50 * 60_000), 'config', 'Encrypted configuration published (version 3)', {
            version: 3,
          });
        }
      }
      push(
        iso(now - int(rng, 2, 9) * DAY),
        'renew',
        'Operational certificate renewed via simplereenroll',
        {
          serial_hex: d.cert.serial_hex,
        },
      );
      if (d.fw_version) {
        push(
          iso(now - int(rng, 10, 25) * DAY),
          'ota',
          `Firmware ${d.product}/${d.fw_version} applied and marked healthy`,
          {
            version: d.fw_version,
            fw_hash_hex: d.fw_hash_hex,
          },
        );
      }
    }
    if (d.state === 'quarantined' && d.quarantined_at) {
      const at = new Date(d.quarantined_at).getTime();
      push(
        iso(at - 90_000),
        'authz_denied',
        'Policy denied publish to im/v1/<tenant>/dev-0000000000000001/telemetry',
        {
          topic: 'im/v1/<tenant>/dev-0000000000000001/telemetry',
          action: 'publish',
        },
      );
      push(
        iso(at - 20_000),
        'alert',
        `Alert raised: ${d.quarantine_reason ?? 'anomaly detected'}`,
        { severity: 'critical' },
      );
      push(iso(at), 'revoke', 'All certificates revoked (quarantine); session kicked in 3.2 s', {
        reason: 'quarantine',
      });
      push(iso(at), 'lifecycle', 'State changed active → quarantined', {
        state: 'quarantined',
        reason: d.quarantine_reason,
      });
    }
    if (d.state === 'decommissioned' && d.decommissioned_at) {
      push(d.decommissioned_at, 'revoke', 'All certificates revoked (decommissioned)', {
        reason: 'decommissioned',
      });
      push(d.decommissioned_at, 'lifecycle', 'State changed active → decommissioned', {
        state: 'decommissioned',
      });
    }
    events.sort((a, b) => (a.at < b.at ? 1 : -1));
    out.set(d.id, events);
  }
  return out;
}

export function buildConfigs(now: number, devices: DeviceFixture[]): Map<string, DeviceConfig> {
  const out = new Map<string, DeviceConfig>();
  for (const device of devices) {
    const d = device.detail;
    if (d.state === 'manufactured') continue;
    const rng = createRng(hashSeed(`config:${d.id}`));
    out.set(d.id, {
      version: int(rng, 1, 5),
      config: {
        mqtt: { keepalive_s: 60, session_expiry_s: 604800, receive_maximum: 32 },
        telemetry: {
          interval_s: device.twin.reported['telemetry_interval_s'] ?? 60,
          metrics:
            device.platform === 'esp32'
              ? ['cpu_pct', 'mem_pct', 'temp_c', 'rssi', 'free_heap']
              : ['cpu_pct', 'mem_pct', 'temp_c', 'net_rx_bytes', 'net_tx_bytes', 'proc_count'],
        },
        thresholds: { temp_c_max: 70, cpu_pct_max: 95 },
        wifi:
          device.platform === 'esp32'
            ? { ssid: 'acme-iot', psk_ref: 'vault:wifi/acme-iot' }
            : undefined,
      },
      delivered_at: iso(now - int(rng, 1, 10) * DAY),
      acked_at: d.state === 'active' ? iso(now - int(rng, 1, 10) * DAY + 60_000) : null,
    });
  }
  return out;
}

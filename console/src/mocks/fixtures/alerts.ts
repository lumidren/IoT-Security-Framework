import type { Alert, AlertRule, QuarantineEntry, Rule, Severity } from '@/lib/api/schemas';
import { DEMO_TENANT_ID } from '@/lib/env';
import { HOUR, createRng, int, iso, pick, uuid } from './seed';
import type { DeviceFixture } from './devices';

interface AlertTemplate {
  rule: AlertRule;
  severity: Severity;
  explanation: string;
  features: Record<string, unknown>;
  score: number;
}

const TEMPLATES: AlertTemplate[] = [
  {
    rule: 'impossible_travel',
    severity: 'critical',
    score: 0.97,
    explanation:
      'Two TLS sessions for the same certificate originated 1 840 km apart within 6 minutes, implying a speed of 18 400 km/h. The private key is probably cloned.',
    features: {
      distance_km: 1840,
      minutes_between: 6,
      implied_speed_kmh: 18400,
      peer_hosts: ['185.12.44.9', '203.0.113.71'],
    },
  },
  {
    rule: 'fw_hash_mismatch',
    severity: 'critical',
    score: 0.99,
    explanation:
      'Reported firmware hash is not in the OTA service known-hash list for this product. The image was not signed by the tenant signing keys.',
    features: {
      reported_hash: 'f00dbabe' + 'a'.repeat(56),
      known_hashes: 7,
      product: 'gateway-rpi',
    },
  },
  {
    rule: 'auth_burst',
    severity: 'high',
    score: 0.91,
    explanation:
      '46 failed CONNECT attempts in 60 seconds using an expired certificate, far above the 5/min baseline.',
    features: { failures_60s: 46, baseline_per_min: 1.2, reason: 'certificate_expired' },
  },
  {
    rule: 'topic_violation',
    severity: 'high',
    score: 0.88,
    explanation:
      'Device attempted to subscribe to another device’s shadow/desired topic; the policy service denied it 12 times.',
    features: {
      denied_count: 12,
      topic: 'im/v1/<tenant>/dev-0000000000000001/shadow/desired',
      action: 'subscribe',
    },
  },
  {
    rule: 'beaconing',
    severity: 'medium',
    score: 0.74,
    explanation:
      'Highly periodic outbound traffic (every 300 s ± 1 s) to a host outside the broker allow-list.',
    features: { period_s: 300, jitter_s: 1.1, destination: '198.51.100.23', bytes_per_beacon: 512 },
  },
  {
    rule: 'isolation_forest',
    severity: 'medium',
    score: 0.68,
    explanation:
      'Telemetry vector is an outlier for the device class: CPU 92% and 3× normal egress with unchanged process count.',
    features: { cpu_pct: 92.4, net_tx_ratio: 3.1, proc_count: 118, anomaly_score: 0.68 },
  },
  {
    rule: 'isolation_forest',
    severity: 'low',
    score: 0.55,
    explanation:
      'Free heap dropped below 40 kB for 20 minutes while RSSI stayed stable; possible memory leak in the new firmware.',
    features: { free_heap: 38120, duration_min: 20, rssi: -62 },
  },
  {
    rule: 'auth_burst',
    severity: 'low',
    score: 0.52,
    explanation:
      '7 failed CONNECTs in 60 seconds shortly after an operational certificate renewal.',
    features: { failures_60s: 7, baseline_per_min: 1.2, reason: 'clientid_mismatch' },
  },
];

export const RULES: Rule[] = [
  {
    name: 'impossible_travel',
    enabled: true,
    severity: 'critical',
    params: { max_speed_kmh: 900, min_distance_km: 50 },
    description: 'Flags certificate reuse from geographically impossible locations.',
    dry_run: false,
  },
  {
    name: 'auth_burst',
    enabled: true,
    severity: 'high',
    params: { window_s: 60, threshold: 20 },
    description: 'Bursts of failed CONNECT attempts for one identity.',
    dry_run: false,
  },
  {
    name: 'topic_violation',
    enabled: true,
    severity: 'high',
    params: { denied_threshold: 5, window_s: 300 },
    description: 'Repeated authorization denials for topics outside the device scheme.',
    dry_run: false,
  },
  {
    name: 'fw_hash_mismatch',
    enabled: true,
    severity: 'critical',
    params: {},
    description: 'Reported firmware hash not in the signed known-hash list.',
    dry_run: false,
  },
  {
    name: 'beaconing',
    enabled: true,
    severity: 'medium',
    params: { min_period_s: 60, max_jitter_pct: 2 },
    description: 'Periodic traffic patterns typical of command-and-control.',
    dry_run: true,
  },
  {
    name: 'isolation_forest',
    enabled: true,
    severity: 'medium',
    params: { contamination: 0.02, retrain_hours: 24 },
    description: 'Unsupervised outlier detection over telemetry vectors per device class.',
    dry_run: false,
  },
];

export function buildAlerts(
  now: number,
  devices: DeviceFixture[],
): { alerts: Alert[]; quarantine: QuarantineEntry[] } {
  const rng = createRng(0x5eed5eed);
  const quarantined = devices.filter((d) => d.detail.state === 'quarantined');
  const active = devices.filter((d) => d.detail.state === 'active');
  const alerts: Alert[] = [];
  const quarantine: QuarantineEntry[] = [];

  // Quarantined devices: 3 automatic (critical/high alerts) and 1 manual.
  quarantined.forEach((device, index) => {
    const quarantinedAt = device.detail.quarantined_at ?? iso(now - HOUR);
    if (index < 3) {
      const template = TEMPLATES[index]!;
      const alert: Alert = {
        id: uuid(rng),
        tenant_id: DEMO_TENANT_ID,
        device_id: device.detail.id,
        rule: template.rule,
        severity: template.severity,
        score: template.score,
        features: template.features,
        explanation: template.explanation,
        created_at: iso(new Date(quarantinedAt).getTime() - 20_000),
        state: index === 0 ? 'open' : 'acked',
        acked_by: index === 0 ? null : 'user:ops-lead',
        resolved_by: null,
        actions: [
          {
            type: 'quarantine',
            at: quarantinedAt,
            result: 'revoked 1 certificate, kicked session in 3.2 s',
          },
          { type: 'notify', at: quarantinedAt, result: 'SIEM webhook 200' },
        ],
      };
      alerts.push(alert);
      quarantine.push({
        device_id: device.detail.id,
        quarantined_at: quarantinedAt,
        reason: device.detail.quarantine_reason ?? template.explanation,
        alert_id: alert.id,
        by: 'auto',
      });
    } else {
      quarantine.push({
        device_id: device.detail.id,
        quarantined_at: quarantinedAt,
        reason: device.detail.quarantine_reason ?? 'Manual quarantine',
        alert_id: null,
        by: 'user:field-tech-7',
      });
    }
  });

  // Remaining alerts on active devices across states.
  const states: Alert['state'][] = [
    'open',
    'open',
    'open',
    'acked',
    'resolved',
    'open',
    'acked',
    'resolved',
    'open',
  ];
  let i = 0;
  while (alerts.length < 12 && i < states.length) {
    const template = TEMPLATES[(i + 3) % TEMPLATES.length]!;
    const device = pick(rng, active);
    const state = states[i]!;
    alerts.push({
      id: uuid(rng),
      tenant_id: DEMO_TENANT_ID,
      device_id: device.detail.id,
      rule: template.rule,
      severity: template.severity,
      score: template.score - rng() * 0.05,
      features: template.features,
      explanation: template.explanation,
      created_at: iso(now - int(rng, 1, 120) * HOUR),
      state,
      acked_by: state === 'open' ? null : 'user:ops-lead',
      resolved_by: state === 'resolved' ? 'user:ops-lead' : null,
      false_positive: state === 'resolved' ? i % 2 === 0 : undefined,
      actions: [
        {
          type: template.severity === 'low' ? 'none' : 'notify',
          at: iso(now - int(rng, 1, 120) * HOUR),
          result: template.severity === 'low' ? null : 'SIEM webhook 200',
        },
      ],
    });
    i += 1;
  }

  alerts.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  return { alerts, quarantine };
}

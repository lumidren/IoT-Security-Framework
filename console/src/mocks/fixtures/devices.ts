import type {
  Certificate,
  DeviceDetail,
  DeviceState,
  Group,
  ProvisioningItem,
  SeType,
  Twin,
} from '@/lib/api/schemas';
import { DEMO_TENANT_ID } from '@/lib/env';
import { DAY, HOUR, createRng, deviceId, hex, int, iso, pick, type Rng } from './seed';

export interface ProductSpec {
  product: string;
  hwRevisions: string[];
  seTypes: SeType[];
  firmware: string[];
  platform: 'linux' | 'esp32';
}

export const PRODUCTS: ProductSpec[] = [
  {
    product: 'gateway-rpi',
    hwRevisions: ['rev-b', 'rev-c'],
    seTypes: ['tpm2', 'tpm2', 'software'],
    firmware: ['2.4.1', '2.4.1', '2.4.0', '2.3.7'],
    platform: 'linux',
  },
  {
    product: 'sensor-esp32',
    hwRevisions: ['v3', 'v4'],
    seTypes: ['atecc608', 'atecc608', 'atecc608', 'software'],
    firmware: ['1.8.2', '1.8.2', '1.8.0'],
    platform: 'esp32',
  },
  {
    product: 'edge-nuc',
    hwRevisions: ['gen11'],
    seTypes: ['optee', 'tpm2'],
    firmware: ['3.1.0', '3.0.4'],
    platform: 'linux',
  },
];

export const FW_HASHES: Record<string, string> = {
  'gateway-rpi/2.4.1': '5d41402abc4b2a76b9719d911017c592e7b8f1a2c3d4e5f60718293a4b5c6d7e',
  'gateway-rpi/2.4.0': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  'gateway-rpi/2.3.7': 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2',
  'sensor-esp32/1.8.2': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
  'sensor-esp32/1.8.0': 'b1ee4a1cfa6a4b0e36e1e87b1d9f48e1e1b4a2a0c0e2a8d1b44d6f1a3c8e9f10',
  'edge-nuc/3.1.0': 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
  'edge-nuc/3.0.4': '2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3',
};

const SITES = [
  { tag: 'ber', lat: 52.52, lon: 13.405 },
  { tag: 'ams', lat: 52.37, lon: 4.9 },
  { tag: 'par', lat: 48.857, lon: 2.352 },
  { tag: 'nyc', lat: 40.713, lon: -74.006 },
  { tag: 'sfo', lat: 37.775, lon: -122.419 },
  { tag: 'tor', lat: 43.653, lon: -79.383 },
];

export const GROUP_DEFS: Array<Omit<Group, 'member_count' | 'created_at'>> = [
  {
    slug: 'eu-west-gateways',
    name: 'EU West gateways',
    description: 'Production gateways in Berlin, Amsterdam and Paris',
    hardware_only: false,
  },
  {
    slug: 'us-east-gateways',
    name: 'US East gateways',
    description: 'Production gateways in New York and Toronto',
    hardware_only: false,
  },
  {
    slug: 'prod-sensors',
    name: 'Production sensors',
    description: 'Hardware-attested ESP32 sensors on production lines',
    hardware_only: true,
  },
  {
    slug: 'lab-sensors',
    name: 'Lab sensors',
    description: 'Bench and lab sensors (software keys allowed)',
    hardware_only: false,
  },
  {
    slug: 'edge-pilot',
    name: 'Edge pilot',
    description: 'Edge compute pilot deployment',
    hardware_only: true,
  },
];

/** Target distribution of lifecycle states across the 50 fixture devices. */
const STATE_PLAN: DeviceState[] = [
  ...Array<DeviceState>(30).fill('active'),
  ...Array<DeviceState>(6).fill('provisioned'),
  ...Array<DeviceState>(7).fill('manufactured'),
  ...Array<DeviceState>(4).fill('quarantined'),
  ...Array<DeviceState>(3).fill('decommissioned'),
];

export interface DeviceFixture {
  detail: DeviceDetail;
  twin: Twin;
  provisioning: ProvisioningItem | null;
  platform: 'linux' | 'esp32';
}

function certFor(
  rng: Rng,
  state: DeviceState,
  index: number,
  now: number,
): {
  cert: DeviceDetail['cert'];
  certificates: Certificate[];
} {
  const serial = hex(rng, 32);
  const issuer = 'CN=IronMesh Device CA,O=IronMesh';
  if (state === 'manufactured') {
    return { cert: { serial_hex: null, not_after: null, status: 'none' }, certificates: [] };
  }
  // Spread expiry: a couple inside 24 h, a few inside 7 d, the rest later.
  let hoursLeft: number;
  if (index % 17 === 3) hoursLeft = int(rng, 2, 20);
  else if (index % 7 === 2) hoursLeft = int(rng, 30, 6 * 24);
  else hoursLeft = int(rng, 8 * 24, 14 * 24);
  const notAfter = now + hoursLeft * HOUR;
  const notBefore = notAfter - 14 * DAY;
  const previous: Certificate = {
    serial_hex: hex(rng, 32),
    not_before: iso(notBefore - 7 * DAY),
    not_after: iso(notBefore + 7 * DAY),
    revoked_at: null,
    revocation_reason: null,
    issuer,
  };
  if (state === 'quarantined' || state === 'decommissioned') {
    const revokedAt = now - int(rng, 1, 72) * HOUR;
    return {
      cert: { serial_hex: serial, not_after: iso(notAfter), status: 'revoked' },
      certificates: [
        {
          serial_hex: serial,
          not_before: iso(notBefore),
          not_after: iso(notAfter),
          revoked_at: iso(revokedAt),
          revocation_reason: state === 'quarantined' ? 'quarantine' : 'decommissioned',
          issuer,
        },
        previous,
      ],
    };
  }
  const status = hoursLeft <= 7 * 24 ? 'expiring' : 'valid';
  return {
    cert: { serial_hex: serial, not_after: iso(notAfter), status },
    certificates: [
      {
        serial_hex: serial,
        not_before: iso(notBefore),
        not_after: iso(notAfter),
        revoked_at: null,
        revocation_reason: null,
        issuer,
      },
      previous,
    ],
  };
}

const QUARANTINE_REASONS = [
  'Impossible travel: 1 840 km in 6 minutes between two TLS sessions',
  'Firmware hash mismatch against OTA known-hash list',
  'Auth burst: 46 failed CONNECTs in 60 s from the device certificate',
  'Manual quarantine: field technician reported tampered enclosure',
];

export function buildDevices(now: number): { devices: DeviceFixture[]; groups: Group[] } {
  const rng = createRng(0x1a2b3c4d);
  const devices: DeviceFixture[] = [];
  const memberCounts = new Map<string, number>(GROUP_DEFS.map((g) => [g.slug, 0]));

  STATE_PLAN.forEach((state, index) => {
    const spec = PRODUCTS[index % PRODUCTS.length] ?? PRODUCTS[0]!;
    const id = deviceId(rng);
    const site = pick(rng, SITES);
    const seType = pick(rng, spec.seTypes);
    const assurance =
      state === 'manufactured' ? null : seType === 'software' ? 'software' : 'hardware';
    const fwVersion = state === 'manufactured' ? null : pick(rng, spec.firmware);
    const fwHash = fwVersion ? (FW_HASHES[`${spec.product}/${fwVersion}`] ?? hex(rng, 64)) : null;
    const createdAt = now - int(rng, 40, 400) * DAY;
    const connected = state === 'active' ? rng() < 0.82 : false;
    const lastSeen =
      state === 'manufactured'
        ? null
        : connected
          ? iso(now - int(rng, 5, 120) * 1000)
          : iso(now - int(rng, 1, 96) * HOUR);
    const env = spec.product === 'sensor-esp32' && index % 5 === 0 ? 'lab' : 'prod';

    const groups: string[] = [];
    if (state !== 'manufactured' && state !== 'decommissioned') {
      if (spec.product === 'gateway-rpi') {
        groups.push(
          ['nyc', 'sfo', 'tor'].includes(site.tag) ? 'us-east-gateways' : 'eu-west-gateways',
        );
      } else if (spec.product === 'sensor-esp32') {
        if (assurance === 'hardware' && env === 'prod') groups.push('prod-sensors');
        else groups.push('lab-sensors');
      } else if (assurance === 'hardware') {
        groups.push('edge-pilot');
      }
    }
    for (const g of groups) memberCounts.set(g, (memberCounts.get(g) ?? 0) + 1);

    const { cert, certificates } = certFor(rng, state, index, now);
    const openAlerts = state === 'quarantined' ? int(rng, 1, 2) : rng() < 0.12 ? 1 : 0;
    const quarantinedAt = state === 'quarantined' ? iso(now - int(rng, 1, 72) * HOUR) : null;
    const failedProvisioning = state === 'manufactured' && index % 3 === 1;

    const lastTelemetry =
      state === 'active'
        ? {
            ts: lastSeen ?? iso(now),
            cpu_pct: Number((15 + rng() * 40).toFixed(1)),
            mem_pct: Number((30 + rng() * 40).toFixed(1)),
            temp_c: Number((35 + rng() * 20).toFixed(1)),
            net_rx_bytes: int(rng, 10_000, 2_000_000),
            net_tx_bytes: int(rng, 5_000, 800_000),
            uptime_s: int(rng, 3600, 40 * 86400),
            auth_failures: 0,
            fw_version: fwVersion,
            ...(spec.platform === 'esp32'
              ? { rssi: -int(rng, 45, 85), free_heap: int(rng, 60_000, 180_000) }
              : { proc_count: int(rng, 80, 240) }),
          }
        : null;

    const detail: DeviceDetail = {
      id,
      tenant_id: DEMO_TENANT_ID,
      product: spec.product,
      hw_revision: pick(rng, spec.hwRevisions),
      state,
      assurance_level: assurance,
      se_type: seType,
      groups,
      tags: { site: site.tag, env, line: pick(rng, ['a', 'b', 'c']) },
      connected,
      last_seen_at: lastSeen,
      fw_version: fwVersion,
      fw_hash_hex: fwHash,
      cert,
      location:
        state === 'manufactured'
          ? null
          : { lat: site.lat + (rng() - 0.5) * 0.4, lon: site.lon + (rng() - 0.5) * 0.4 },
      open_alerts: openAlerts,
      bootstrap_serial_hex: hex(rng, 32),
      created_at: iso(createdAt),
      provisioned_at: state === 'manufactured' ? null : iso(createdAt + 2 * DAY),
      activated_at:
        state === 'manufactured' || state === 'provisioned'
          ? null
          : iso(createdAt + 2 * DAY + HOUR),
      quarantined_at: quarantinedAt,
      quarantine_reason:
        state === 'quarantined' ? QUARANTINE_REASONS[index % QUARANTINE_REASONS.length]! : null,
      decommissioned_at: state === 'decommissioned' ? iso(now - int(rng, 2, 30) * DAY) : null,
      twin_version: int(rng, 1, 12),
      last_telemetry: lastTelemetry,
      certificates,
    };

    const desired = {
      telemetry_interval_s: pick(rng, [30, 60, 120]),
      log_level: pick(rng, ['info', 'warn', 'debug']),
      features: { ota: true, remote_shell: false, metrics_export: rng() < 0.5 },
    };
    const reportedIntervalMatches = rng() < 0.7;
    const reported = {
      telemetry_interval_s: reportedIntervalMatches ? desired.telemetry_interval_s : 60,
      log_level: desired.log_level,
      features: { ...desired.features },
      fw_version: fwVersion,
    };
    const delta: Record<string, unknown> = reportedIntervalMatches
      ? {}
      : { telemetry_interval_s: desired.telemetry_interval_s };

    const twin: Twin = {
      device_id: id,
      version: detail.twin_version,
      desired,
      reported,
      delta,
      desired_updated_at: iso(now - int(rng, 1, 20) * DAY),
      reported_updated_at: state === 'active' ? iso(now - int(rng, 1, 600) * 1000) : null,
    };

    let provisioning: ProvisioningItem | null = null;
    if (state === 'manufactured' || state === 'provisioned') {
      provisioning = {
        device_id: id,
        product: spec.product,
        se_type: seType,
        state: failedProvisioning ? 'failed' : state,
        bootstrap_serial_hex: detail.bootstrap_serial_hex,
        created_at: detail.created_at,
        last_attempt_at:
          state === 'manufactured' && !failedProvisioning
            ? null
            : iso(now - int(rng, 1, 48) * HOUR),
        last_error: failedProvisioning
          ? pick(rng, [
              'attestation: TPM quote PCR7 does not match the approved policy',
              'attestation: nonce expired (replayed enrollment request)',
              'se_type software rejected: tenant requires hardware assurance',
            ])
          : null,
        attempts: failedProvisioning ? int(rng, 2, 6) : state === 'provisioned' ? 1 : 0,
      };
    }

    devices.push({ detail, twin, provisioning, platform: spec.platform });
  });

  const groups: Group[] = GROUP_DEFS.map((g) => ({
    ...g,
    member_count: memberCounts.get(g.slug) ?? 0,
    created_at: iso(now - 200 * DAY),
  }));

  return { devices, groups };
}

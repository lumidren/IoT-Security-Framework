import type {
  Campaign,
  CampaignDevice,
  Firmware,
  SigningKey,
  Stage,
  StageCounts,
} from '@/lib/api/schemas';
import { DAY, HOUR, createRng, int, iso, pick, uuid, type Rng } from './seed';
import { FW_HASHES, type DeviceFixture } from './devices';

export function emptyCounts(): StageCounts {
  return {
    targeted: 0,
    notified: 0,
    downloading: 0,
    verifying: 0,
    applying: 0,
    success: 0,
    failed: 0,
    rolled_back: 0,
    rejected: 0,
  };
}

const FIRMWARE_DEFS: Array<
  Pick<Firmware, 'product' | 'version' | 'version_code' | 'severity' | 'notes'>
> = [
  {
    product: 'gateway-rpi',
    version: '2.3.7',
    version_code: 2307,
    severity: 'normal',
    notes: 'Maintenance release: MQTT keep-alive tuning.',
  },
  {
    product: 'gateway-rpi',
    version: '2.4.0',
    version_code: 2400,
    severity: 'normal',
    notes: 'Adds delta OTA support and TPM-backed renewal.',
  },
  {
    product: 'gateway-rpi',
    version: '2.4.1',
    version_code: 2401,
    severity: 'security',
    notes: 'Fixes CVE-2026-1182 in the TLS stack (TLS 1.3 only).',
  },
  {
    product: 'sensor-esp32',
    version: '1.8.0',
    version_code: 1800,
    severity: 'normal',
    notes: 'Ring-buffer replay fixes.',
  },
  {
    product: 'sensor-esp32',
    version: '1.8.2',
    version_code: 1802,
    severity: 'normal',
    notes: 'Improves RSSI telemetry and heap reporting.',
  },
  {
    product: 'edge-nuc',
    version: '3.0.4',
    version_code: 3004,
    severity: 'normal',
    notes: 'OP-TEE attestation evidence v2.',
  },
  {
    product: 'edge-nuc',
    version: '3.1.0',
    version_code: 3100,
    severity: 'security',
    notes: 'Rotates the bundle verification key; mandatory before 2027-01-01.',
  },
];

export function buildFirmware(now: number): { firmware: Firmware[]; signingKeys: SigningKey[] } {
  const rng = createRng(0x0f1e2d3c);
  const firmware = FIRMWARE_DEFS.map((def, index) => ({
    id: uuid(rng),
    product: def.product,
    version: def.version,
    version_code: def.version_code,
    sha256_hex: FW_HASHES[`${def.product}/${def.version}`] ?? '',
    size: int(rng, 1_800_000, 48_000_000),
    created_at: iso(now - (FIRMWARE_DEFS.length - index) * 9 * DAY),
    created_by: pick(rng, ['user:ops-lead', 'user:release-bot']),
    signed_manifest_b64: 'omdwYXlsb2FkWQEA' + 'A'.repeat(40),
    signing_key_id: 'ed25519-2026-01',
    pq_signed: index >= 2,
    notes: def.notes,
    severity: def.severity,
  }));
  const signingKeys: SigningKey[] = [
    {
      key_id: 'ed25519-2026-01',
      algorithm: 'Ed25519',
      public_key_b64: 'MCowBQYDK2VwAyEAq3f8ZxkT1yHq1rBx0D0M1Q3h2X4Yv1p2a0JrJx0wXyA=',
      active: true,
      created_at: iso(now - 300 * DAY),
    },
    {
      key_id: 'mldsa65-2026-01',
      algorithm: 'ML-DSA-65',
      public_key_b64: 'MIIHtDANBgsrBgEEAQKCCwcGBQOCB6EA' + 'B'.repeat(40),
      active: true,
      created_at: iso(now - 120 * DAY),
    },
  ];
  return { firmware, signingKeys };
}

function stage(
  index: number,
  percent: number,
  dwell: number,
  state: Stage['state'],
  counts: StageCounts,
  startedAt: string | null,
  finishedAt: string | null,
): Stage {
  return {
    index,
    percent,
    dwell_s: dwell,
    max_failure_rate: 0.05,
    state,
    started_at: startedAt,
    finished_at: finishedAt,
    counts,
  };
}

function sumCounts(stages: Stage[]): StageCounts {
  const total = emptyCounts();
  for (const s of stages) {
    for (const key of Object.keys(total) as Array<keyof StageCounts>) total[key] += s.counts[key];
  }
  return total;
}

export function buildCampaigns(
  now: number,
  firmware: Firmware[],
  devices: DeviceFixture[],
): { campaigns: Campaign[]; campaignDevices: Map<string, CampaignDevice[]> } {
  const rng = createRng(0xabcdef01);
  const campaignDevices = new Map<string, CampaignDevice[]>();
  const fw = (product: string, version: string) => {
    const f = firmware.find((x) => x.product === product && x.version === version);
    if (!f) throw new Error(`fixture firmware ${product}/${version} missing`);
    return f;
  };

  // 1. Running security rollout of gateway-rpi 2.4.1, currently in stage 2 (10%).
  const gatewayTargets = devices.filter(
    (d) => d.detail.product === 'gateway-rpi' && d.detail.state === 'active',
  );
  const running = makeRunning(rng, now, fw('gateway-rpi', '2.4.1'), gatewayTargets);
  campaignDevices.set(running.campaign.id, running.devices);

  // 2. Completed sensor rollout.
  const sensorTargets = devices.filter(
    (d) => d.detail.product === 'sensor-esp32' && d.detail.state === 'active',
  );
  const completed = makeCompleted(rng, now, fw('sensor-esp32', '1.8.2'), sensorTargets);
  campaignDevices.set(completed.campaign.id, completed.devices);

  // 3. Draft security campaign for the edge pilot.
  const draftId = uuid(rng);
  const draftStages = [
    stage(0, 1, 3600, 'pending', emptyCounts(), null, null),
    stage(1, 25, 7200, 'pending', emptyCounts(), null, null),
    stage(2, 100, 0, 'pending', emptyCounts(), null, null),
  ];
  const draft: Campaign = {
    id: draftId,
    name: 'edge-nuc 3.1.0 bundle key rotation',
    firmware: fw('edge-nuc', '3.1.0'),
    target: { groups: ['edge-pilot'], device_ids: [], tags: {} },
    delta: false,
    severity: 'security',
    stages: draftStages,
    current_stage: 0,
    state: 'draft',
    halt_reason: null,
    created_by: 'user:ops-lead',
    created_at: iso(now - 3 * HOUR),
    started_at: null,
    finished_at: null,
    parent_campaign_id: null,
    totals: sumCounts(draftStages),
  };
  campaignDevices.set(draftId, []);

  return { campaigns: [running.campaign, completed.campaign, draft], campaignDevices };
}

function makeRunning(rng: Rng, now: number, firmware: Firmware, targets: DeviceFixture[]) {
  const id = uuid(rng);
  const startedAt = now - 26 * HOUR;
  const total = Math.max(targets.length, 10);
  const stage1Count = Math.max(1, Math.round(total * 0.01));
  const stage2Count = Math.max(2, Math.round(total * 0.1));
  const devicesOut: CampaignDevice[] = [];
  let cursor = 0;
  const s1 = emptyCounts();
  s1.targeted = stage1Count;
  s1.notified = stage1Count;
  s1.success = stage1Count;
  for (let i = 0; i < stage1Count && cursor < targets.length; i += 1, cursor += 1) {
    const d = targets[cursor]!;
    devicesOut.push({
      device_id: d.detail.id,
      state: 'success',
      progress_pct: 100,
      error: null,
      notified_at: iso(startedAt + 60_000),
      updated_at: iso(startedAt + 25 * 60_000),
      fw_hash_hex: firmware.sha256_hex,
    });
  }
  const s2 = emptyCounts();
  s2.targeted = stage2Count;
  for (let i = 0; i < stage2Count && cursor < targets.length; i += 1, cursor += 1) {
    const d = targets[cursor]!;
    const roll = rng();
    const state: CampaignDevice['state'] =
      roll < 0.5
        ? 'success'
        : roll < 0.7
          ? 'applying'
          : roll < 0.85
            ? 'downloading'
            : roll < 0.95
              ? 'notified'
              : 'failed';
    s2.notified += 1;
    if (state === 'success') s2.success += 1;
    else if (state === 'applying') s2.applying += 1;
    else if (state === 'downloading') s2.downloading += 1;
    else if (state === 'failed') s2.failed += 1;
    devicesOut.push({
      device_id: d.detail.id,
      state,
      progress_pct:
        state === 'success'
          ? 100
          : state === 'applying'
            ? 90
            : state === 'downloading'
              ? int(rng, 10, 80)
              : state === 'failed'
                ? 42
                : 0,
      error: state === 'failed' ? 'verify: image sha256 mismatch after download (retrying)' : null,
      notified_at: iso(now - 70 * 60_000),
      updated_at: iso(now - int(rng, 1, 40) * 60_000),
      fw_hash_hex: state === 'success' ? firmware.sha256_hex : null,
    });
  }
  const s3 = emptyCounts();
  s3.targeted = Math.max(total - stage1Count - stage2Count, 0);
  for (; cursor < targets.length; cursor += 1) {
    const d = targets[cursor]!;
    devicesOut.push({
      device_id: d.detail.id,
      state: 'pending',
      progress_pct: 0,
      error: null,
      notified_at: null,
      updated_at: iso(startedAt),
      fw_hash_hex: null,
    });
  }
  const stages = [
    stage(0, 1, 3600, 'passed', s1, iso(startedAt), iso(startedAt + 2 * HOUR)),
    stage(1, 10, 3600, 'running', s2, iso(now - 75 * 60_000), null),
    stage(2, 100, 0, 'pending', s3, null, null),
  ];
  const campaign: Campaign = {
    id,
    name: 'gateway-rpi 2.4.1 security rollout',
    firmware,
    target: {
      groups: ['eu-west-gateways', 'us-east-gateways'],
      device_ids: [],
      tags: { env: 'prod' },
    },
    delta: true,
    severity: 'security',
    stages,
    current_stage: 1,
    state: 'running',
    halt_reason: null,
    created_by: 'user:ops-lead',
    created_at: iso(startedAt - HOUR),
    started_at: iso(startedAt),
    finished_at: null,
    parent_campaign_id: null,
    totals: sumCounts(stages),
  };
  return { campaign, devices: devicesOut };
}

function makeCompleted(rng: Rng, now: number, firmware: Firmware, targets: DeviceFixture[]) {
  const id = uuid(rng);
  const startedAt = now - 9 * DAY;
  const finishedAt = startedAt + 30 * HOUR;
  const total = targets.length;
  const counts = [Math.max(1, Math.round(total * 0.01)), Math.max(1, Math.round(total * 0.1)), 0];
  counts[2] = Math.max(total - counts[0]! - counts[1]!, 0);
  const devicesOut: CampaignDevice[] = targets.map((d, index) => {
    const failed = index === targets.length - 1 && targets.length > 3;
    return {
      device_id: d.detail.id,
      state: failed ? 'rolled_back' : 'success',
      progress_pct: 100,
      error: failed
        ? 'health check: ota_mark_healthy() not called within 120 s; bootloader reverted'
        : null,
      notified_at: iso(startedAt + HOUR),
      updated_at: iso(startedAt + int(rng, 2, 28) * HOUR),
      fw_hash_hex: failed ? null : firmware.sha256_hex,
    };
  });
  const stages = counts.map((targeted, index) => {
    const c = emptyCounts();
    c.targeted = targeted;
    c.notified = targeted;
    c.success = targeted;
    if (index === 2 && targets.length > 3) {
      c.success -= 1;
      c.rolled_back = 1;
    }
    return stage(
      index,
      [1, 10, 100][index]!,
      [3600, 3600, 0][index]!,
      'passed',
      c,
      iso(startedAt + index * 10 * HOUR),
      iso(startedAt + (index + 1) * 10 * HOUR),
    );
  });
  const campaign: Campaign = {
    id,
    name: 'sensor-esp32 1.8.2 telemetry improvements',
    firmware,
    target: { groups: ['prod-sensors', 'lab-sensors'], device_ids: [], tags: {} },
    delta: false,
    severity: 'normal',
    stages,
    current_stage: 2,
    state: 'completed',
    halt_reason: null,
    created_by: 'user:release-bot',
    created_at: iso(startedAt - 2 * HOUR),
    started_at: iso(startedAt),
    finished_at: iso(finishedAt),
    parent_campaign_id: null,
    totals: sumCounts(stages),
  };
  return { campaign, devices: devicesOut };
}

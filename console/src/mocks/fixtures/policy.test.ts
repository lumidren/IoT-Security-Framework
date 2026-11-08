import { describe, expect, it } from 'vitest';
import { DEMO_TENANT_ID } from '@/lib/env';
import { POLICY_REGO, compilePolicy, evaluatePolicy } from './policy';

const device = 'dev-8f3a1c2b9d4e5f60';
const base = {
  clientid: device,
  username: device,
  tenant_id: DEMO_TENANT_ID,
  device_id: device,
  kind: 'device',
  topic: `im/v1/${DEMO_TENANT_ID}/${device}/telemetry`,
  action: 'publish',
  qos: 1,
  retain: false,
};

describe('mock policy evaluation mirrors DESIGN_CONTRACT §4', () => {
  it('allows a device to publish telemetry on its own topic', () => {
    expect(evaluatePolicy(base).result).toBe('allow');
  });
  it('denies QoS 2, retained device publishes, wildcards and foreign topics', () => {
    expect(evaluatePolicy({ ...base, qos: 2 }).result).toBe('deny');
    expect(evaluatePolicy({ ...base, retain: true }).result).toBe('deny');
    expect(
      evaluatePolicy({ ...base, topic: `im/v1/${DEMO_TENANT_ID}/+/telemetry`, action: 'subscribe' })
        .result,
    ).toBe('deny');
    expect(
      evaluatePolicy({ ...base, topic: `im/v1/${DEMO_TENANT_ID}/dev-0000000000000001/telemetry` })
        .result,
    ).toBe('deny');
  });
  it('lets the bridge use only its shared subscription and the registry publish retained config', () => {
    expect(
      evaluatePolicy({
        ...base,
        clientid: 'svc-bridge',
        kind: 'service',
        topic: '$share/bridge/im/v1/#',
        action: 'subscribe',
      }).result,
    ).toBe('allow');
    expect(
      evaluatePolicy({
        ...base,
        clientid: 'svc-bridge',
        kind: 'service',
        topic: base.topic,
        action: 'publish',
      }).result,
    ).toBe('deny');
    expect(
      evaluatePolicy({
        ...base,
        clientid: 'svc-registry',
        kind: 'service',
        topic: `im/v1/${DEMO_TENANT_ID}/${device}/config`,
        retain: true,
      }).result,
    ).toBe('allow');
    expect(
      evaluatePolicy({
        ...base,
        clientid: 'svc-registry',
        kind: 'service',
        topic: `im/v1/${DEMO_TENANT_ID}/${device}/cmd/req`,
        retain: true,
      }).result,
    ).toBe('deny');
  });
});

describe('mock policy compiler', () => {
  it('accepts the shipped policy', () => {
    expect(compilePolicy(POLICY_REGO)).toEqual([]);
  });
  it('reports missing package, unbalanced braces and lost default deny with positions', () => {
    const diagnostics = compilePolicy('allow if {\n  true\n');
    expect(diagnostics.map((d) => d.message)).toEqual(
      expect.arrayContaining([
        expect.stringContaining('package ironmesh.mqtt'),
        expect.stringContaining('unclosed'),
        expect.stringContaining('test_default_deny'),
      ]),
    );
    expect(diagnostics.every((d) => d.line >= 1 && d.col >= 1)).toBe(true);
  });
});

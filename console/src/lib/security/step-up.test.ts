import { describe, expect, it } from 'vitest';
import {
  DEFAULT_STEP_UP_MAX_AGE_S,
  STEP_UP_CODE,
  isAuthFresh,
  isStepUpProblem,
  normaliseUpstreamPath,
  stepUpAction,
  stepUpMaxAgeSeconds,
  stepUpProblemBody,
  type StepUpAction,
} from './step-up';

const ID = '0b6c6a43-2a61-4b8e-a0a1-7d3b1f0e9c11';

describe('stepUpAction (route classifier)', () => {
  it.each<[string, string, string, StepUpAction]>([
    ['registry', 'POST', `/v1/devices/${ID}/quarantine`, 'device.quarantine'],
    ['registry', 'POST', `/v1/devices/${ID}/release`, 'device.release'],
    ['registry', 'POST', `/v1/devices/${ID}/decommission`, 'device.decommission'],
    ['registry', 'PUT', `/v1/devices/${ID}/config`, 'device.config.write'],
    ['registry', 'POST', '/v1/api-keys', 'apikey.create'],
    ['registry', 'DELETE', `/v1/api-keys/${ID}`, 'apikey.revoke'],
    ['registry', 'PATCH', '/v1/tenants/me/settings', 'tenant.settings'],
    ['registry', 'PUT', `/v1/users/${ID}/role`, 'user.role'],
    ['policy', 'PUT', '/v1/policy', 'policy.save'],
    ['ota', 'POST', `/v1/campaigns/${ID}/start`, 'campaign.start'],
    ['ota', 'POST', `/v1/campaigns/${ID}/halt`, 'campaign.halt'],
    ['ota', 'POST', `/v1/campaigns/${ID}/rollback`, 'campaign.rollback'],
  ])('%s %s %s needs step-up (%s)', (service, method, path, action) => {
    expect(stepUpAction(service, method, path)).toBe(action);
  });

  it.each<[string, string, string]>([
    ['registry', 'GET', `/v1/devices/${ID}/config`],
    ['registry', 'GET', '/v1/api-keys'],
    ['registry', 'PATCH', `/v1/devices/${ID}`],
    ['registry', 'POST', `/v1/devices/${ID}/commands`],
    ['registry', 'PATCH', `/v1/devices/${ID}/twin/desired`],
    ['policy', 'POST', '/v1/policy/evaluate'],
    ['ota', 'POST', `/v1/campaigns/${ID}/pause`],
    ['ota', 'POST', `/v1/campaigns/${ID}/resume`],
    ['ota', 'POST', '/v1/campaigns'],
    ['anomaly', 'POST', `/v1/alerts/${ID}/ack`],
    // The same path on another service is not the registry's quarantine route.
    ['ota', 'POST', `/v1/devices/${ID}/quarantine`],
  ])('%s %s %s does not need step-up', (service, method, path) => {
    expect(stepUpAction(service, method, path)).toBeNull();
  });

  it('cannot be bypassed with encoded slashes, dot segments, case or extra slashes', () => {
    expect(stepUpAction('registry', 'POST', `/v1/devices/${ID}%2Fquarantine`)).toBe(
      'device.quarantine',
    );
    expect(stepUpAction('registry', 'POST', `/v1/devices/${ID}/x/../quarantine`)).toBe(
      'device.quarantine',
    );
    expect(stepUpAction('registry', 'POST', `/V1/Devices/${ID}/QUARANTINE/`)).toBe(
      'device.quarantine',
    );
    expect(stepUpAction('registry', 'post', `//v1//devices/${ID}/./quarantine`)).toBe(
      'device.quarantine',
    );
    expect(stepUpAction('policy', 'PUT', '/v1/policy/')).toBe('policy.save');
  });

  it('accepts pre-normalised segments without decoding twice', () => {
    expect(stepUpAction('registry', 'POST', ['v1', 'devices', ID, 'quarantine'])).toBe(
      'device.quarantine',
    );
    expect(normaliseUpstreamPath('/a/b/%2e%2e/c')).toEqual(['a', 'c']);
  });
});

describe('isAuthFresh (age check)', () => {
  const now = Date.UTC(2026, 10, 9, 12, 0, 0);
  const nowS = now / 1000;

  it('is fresh within the window and stale after it', () => {
    expect(isAuthFresh(nowS - 10, 300, now)).toBe(true);
    expect(isAuthFresh(nowS - 300, 300, now)).toBe(true);
    expect(isAuthFresh(nowS - 301, 300, now)).toBe(false);
    expect(isAuthFresh(nowS - 3600, 300, now)).toBe(false);
  });

  it('treats a missing auth_time as stale (sessions issued before step-up existed)', () => {
    expect(isAuthFresh(undefined, 300, now)).toBe(false);
    expect(isAuthFresh(null, 300, now)).toBe(false);
    expect(isAuthFresh(Number.NaN, 300, now)).toBe(false);
  });

  it('tolerates small clock skew but not an auth_time far in the future', () => {
    expect(isAuthFresh(nowS + 30, 300, now)).toBe(true);
    expect(isAuthFresh(nowS + 3600, 300, now)).toBe(false);
  });
});

describe('stepUpMaxAgeSeconds', () => {
  it('defaults to 300 s and parses CONSOLE_STEP_UP_MAX_AGE', () => {
    expect(stepUpMaxAgeSeconds(undefined)).toBe(DEFAULT_STEP_UP_MAX_AGE_S);
    expect(stepUpMaxAgeSeconds('')).toBe(300);
    expect(stepUpMaxAgeSeconds('600')).toBe(600);
    expect(stepUpMaxAgeSeconds(' 900 ')).toBe(900);
  });

  it('ignores invalid values and clamps very small ones', () => {
    expect(stepUpMaxAgeSeconds('abc')).toBe(300);
    expect(stepUpMaxAgeSeconds('-5')).toBe(300);
    expect(stepUpMaxAgeSeconds('0')).toBe(300);
    expect(stepUpMaxAgeSeconds('1.5')).toBe(300);
    expect(stepUpMaxAgeSeconds('5')).toBe(30);
  });
});

describe('step-up problem', () => {
  it('is an RFC 9457 401 problem the client recognises', () => {
    const body = stepUpProblemBody('campaign.rollback', 300);
    expect(body).toMatchObject({ status: 401, code: STEP_UP_CODE, action: 'campaign.rollback' });
    expect(isStepUpProblem(body)).toBe(true);
    expect(isStepUpProblem({ type: 'about:blank', title: 'Unauthorized', status: 401 })).toBe(
      false,
    );
    expect(isStepUpProblem({ ...body, status: 403 })).toBe(false);
    expect(isStepUpProblem(null)).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';
import {
  can,
  isRole,
  proxyAllows,
  requiredRole,
  roleAtLeast,
  type Permission,
  type Role,
} from './rbac';

const ROLES: Role[] = ['owner', 'admin', 'operator', 'viewer', 'factory'];

describe('rbac.can', () => {
  it.each<[Permission, Role[]]>([
    ['device.quarantine', ['owner', 'admin', 'operator']],
    ['device.release', ['owner', 'admin']],
    ['device.decommission', ['owner', 'admin']],
    ['device.config.read', ['owner', 'admin']],
    ['twin.write', ['owner', 'admin', 'operator']],
    ['campaign.rollback', ['owner', 'admin']],
    ['firmware.upload', ['owner', 'admin']],
    ['policy.read', ['owner', 'admin']],
    ['policy.write', ['owner']],
    ['policy.evaluate', ['owner', 'admin', 'operator']],
    ['users.role', ['owner']],
    ['apikeys.manage', ['owner', 'admin']],
    ['audit.export', ['owner', 'admin']],
    ['audit.read', ['owner', 'admin', 'operator', 'viewer', 'factory']],
    ['device.create', ['owner', 'admin', 'factory']],
  ])('%s is granted exactly to %j', (permission, allowed) => {
    for (const role of ROLES) {
      expect(can(role, permission), `${role} / ${permission}`).toBe(allowed.includes(role));
    }
  });

  it('denies unknown or missing roles', () => {
    expect(can(undefined, 'device.quarantine')).toBe(false);
    expect(can(null, 'audit.read')).toBe(false);
    expect(can('root' as Role, 'audit.read')).toBe(false);
  });

  it('factory does not inherit operator powers', () => {
    expect(can('factory', 'device.quarantine')).toBe(false);
    expect(can('factory', 'twin.write')).toBe(false);
  });

  it('exposes the minimum role for UI hints', () => {
    expect(requiredRole('policy.write')).toBe('owner');
    expect(requiredRole('device.quarantine')).toBe('operator');
  });
});

describe('roleAtLeast / isRole', () => {
  it('orders roles', () => {
    expect(roleAtLeast('admin', 'operator')).toBe(true);
    expect(roleAtLeast('operator', 'admin')).toBe(false);
    expect(roleAtLeast('viewer', 'viewer')).toBe(true);
    expect(roleAtLeast(undefined, 'viewer')).toBe(false);
  });

  it('recognises valid role strings', () => {
    expect(isRole('owner')).toBe(true);
    expect(isRole('superuser')).toBe(false);
    expect(isRole(3)).toBe(false);
  });
});

describe('proxyAllows (server-side viewer guard)', () => {
  it('lets every known role read', () => {
    for (const role of ROLES) expect(proxyAllows(role, 'GET')).toBe(true);
  });

  it('refuses mutations for viewers only', () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(proxyAllows('viewer', method)).toBe(false);
      expect(proxyAllows('operator', method)).toBe(true);
      expect(proxyAllows('factory', method)).toBe(true);
    }
  });

  it('refuses unknown roles entirely', () => {
    expect(proxyAllows(undefined, 'GET')).toBe(false);
  });
});

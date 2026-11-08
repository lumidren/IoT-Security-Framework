import type { Role } from '@/lib/api/schemas';

export type { Role };

/** Ordered tenant roles; `factory` is a side role that only manufactures devices. */
export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  factory: 0,
  operator: 1,
  admin: 2,
  owner: 3,
};

export const ROLE_LABEL: Record<Role, string> = {
  owner: 'Owner',
  admin: 'Admin',
  operator: 'Operator',
  viewer: 'Viewer',
  factory: 'Factory',
};

export type Permission =
  | 'device.create'
  | 'device.edit'
  | 'device.quarantine'
  | 'device.release'
  | 'device.decommission'
  | 'device.command'
  | 'device.config.read'
  | 'device.config.write'
  | 'twin.write'
  | 'group.write'
  | 'group.delete'
  | 'provisioning.review'
  | 'firmware.upload'
  | 'campaign.create'
  | 'campaign.control'
  | 'campaign.rollback'
  | 'policy.read'
  | 'policy.write'
  | 'policy.evaluate'
  | 'alert.ack'
  | 'alert.resolve'
  | 'rules.write'
  | 'audit.read'
  | 'audit.export'
  | 'users.read'
  | 'users.role'
  | 'apikeys.manage'
  | 'tenant.settings';

interface PermissionRule {
  /** Minimum ordered role. */
  min: Role;
  /** Additional roles granted regardless of rank (for the `factory` side role). */
  also?: Role[];
}

const PERMISSIONS: Record<Permission, PermissionRule> = {
  'device.create': { min: 'admin', also: ['factory'] },
  'device.edit': { min: 'operator' },
  'device.quarantine': { min: 'operator' },
  'device.release': { min: 'admin' },
  'device.decommission': { min: 'admin' },
  'device.command': { min: 'operator' },
  'device.config.read': { min: 'admin' },
  'device.config.write': { min: 'admin' },
  'twin.write': { min: 'operator' },
  'group.write': { min: 'operator' },
  'group.delete': { min: 'admin' },
  'provisioning.review': { min: 'operator' },
  'firmware.upload': { min: 'admin' },
  'campaign.create': { min: 'operator' },
  'campaign.control': { min: 'operator' },
  'campaign.rollback': { min: 'admin' },
  'policy.read': { min: 'admin' },
  'policy.write': { min: 'owner' },
  'policy.evaluate': { min: 'operator' },
  'alert.ack': { min: 'operator' },
  'alert.resolve': { min: 'operator' },
  'rules.write': { min: 'admin' },
  'audit.read': { min: 'viewer' },
  'audit.export': { min: 'admin' },
  'users.read': { min: 'admin' },
  'users.role': { min: 'owner' },
  'apikeys.manage': { min: 'admin' },
  'tenant.settings': { min: 'admin' },
};

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && value in ROLE_RANK;
}

export function roleAtLeast(role: Role | null | undefined, min: Role): boolean {
  if (!role) return false;
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

/** Whether `role` may perform `permission`. Unknown or missing roles never can. */
export function can(role: Role | null | undefined, permission: Permission): boolean {
  if (!isRole(role)) return false;
  const rule = PERMISSIONS[permission];
  if (rule.also?.includes(role)) return true;
  // `factory` never inherits ordered permissions, even those granted to `viewer`.
  if (role === 'factory') return rule.min === 'viewer' && permission === 'audit.read';
  return roleAtLeast(role, rule.min);
}

/** Minimum role label for UI hints such as "Requires admin". */
export function requiredRole(permission: Permission): Role {
  return PERMISSIONS[permission].min;
}

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function isMutationMethod(method: string): boolean {
  return MUTATION_METHODS.has(method.toUpperCase());
}

/** Server-side guard used by the proxy: viewers may never issue mutating requests. */
export function proxyAllows(role: Role | null | undefined, method: string): boolean {
  if (!isRole(role)) return false;
  if (!isMutationMethod(method)) return true;
  return role !== 'viewer';
}

/**
 * Step-up re-authentication for destructive actions (THREAT_MODEL T-51 / T-65). The proxy refuses
 * the routes below with a 401 `step_up_required` problem when the session's `auth_time` is older
 * than `CONSOLE_STEP_UP_MAX_AGE` seconds; the UI then re-authenticates and retries.
 *
 * Shared by the server (proxy route, Auth.js callbacks), the browser (API client) and the demo
 * mock worker, so it must stay free of server-only imports.
 */

export const STEP_UP_CODE = 'step_up_required';
export const STEP_UP_PROBLEM_TYPE = 'urn:ironmesh:problem:step_up_required';
export const DEFAULT_STEP_UP_MAX_AGE_S = 300;
/** Lower bound so a misconfiguration cannot cause an endless re-authentication loop. */
export const MIN_STEP_UP_MAX_AGE_S = 30;
/** Accepted clock skew for an `auth_time` slightly in the future. */
const FUTURE_SKEW_S = 60;

export type StepUpAction =
  | 'device.quarantine'
  | 'device.release'
  | 'device.decommission'
  | 'device.config.write'
  | 'policy.save'
  | 'apikey.create'
  | 'apikey.revoke'
  | 'tenant.settings'
  | 'user.role'
  | 'campaign.start'
  | 'campaign.halt'
  | 'campaign.rollback';

export const STEP_UP_ACTION_LABEL: Record<StepUpAction, string> = {
  'device.quarantine': 'quarantine a device',
  'device.release': 'release a device from quarantine',
  'device.decommission': 'decommission a device',
  'device.config.write': 'change device configuration',
  'policy.save': 'save the MQTT policy',
  'apikey.create': 'create an API key',
  'apikey.revoke': 'revoke an API key',
  'tenant.settings': 'change tenant security settings',
  'user.role': 'change a user role',
  'campaign.start': 'start an OTA campaign',
  'campaign.halt': 'halt an OTA campaign',
  'campaign.rollback': 'roll back an OTA campaign',
};

type Matcher = {
  action: StepUpAction;
  service: string;
  methods: readonly string[];
  /** Segment pattern; `*` matches exactly one non-empty segment. */
  pattern: readonly string[];
};

const WRITE = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

const MATCHERS: readonly Matcher[] = [
  {
    action: 'device.quarantine',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'devices', '*', 'quarantine'],
  },
  {
    action: 'device.release',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'devices', '*', 'release'],
  },
  {
    action: 'device.decommission',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'devices', '*', 'decommission'],
  },
  {
    action: 'device.config.write',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'devices', '*', 'config'],
  },
  {
    action: 'apikey.create',
    service: 'registry',
    methods: ['POST', 'PUT'],
    pattern: ['v1', 'api-keys'],
  },
  {
    action: 'apikey.revoke',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'api-keys', '*'],
  },
  {
    action: 'tenant.settings',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'tenants', '*', 'settings'],
  },
  {
    action: 'user.role',
    service: 'registry',
    methods: WRITE,
    pattern: ['v1', 'users', '*', 'role'],
  },
  { action: 'policy.save', service: 'policy', methods: WRITE, pattern: ['v1', 'policy'] },
  {
    action: 'campaign.start',
    service: 'ota',
    methods: WRITE,
    pattern: ['v1', 'campaigns', '*', 'start'],
  },
  {
    action: 'campaign.halt',
    service: 'ota',
    methods: WRITE,
    pattern: ['v1', 'campaigns', '*', 'halt'],
  },
  {
    action: 'campaign.rollback',
    service: 'ota',
    methods: WRITE,
    pattern: ['v1', 'campaigns', '*', 'rollback'],
  },
];

function safeDecode(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/**
 * Normalises an upstream path the way the upstream router will see it: percent-decoded (Starlette
 * decodes `%2F` before routing), split on `/` and `\`, empty and `.` segments dropped, `..`
 * resolved, lower-cased. Classifying the normalised form means encoded slashes or dot segments
 * cannot smuggle a destructive route past the classifier.
 */
export function normaliseUpstreamPath(path: string): string[] {
  const out: string[] = [];
  for (const piece of safeDecode(path).split(/[/\\]+/)) {
    const segment = piece.trim().toLowerCase();
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      out.pop();
      continue;
    }
    out.push(segment);
  }
  return out;
}

function matches(pattern: readonly string[], segments: readonly string[]): boolean {
  if (pattern.length !== segments.length) return false;
  return pattern.every((p, i) => p === '*' || p === segments[i]);
}

/**
 * The destructive action a proxied request performs, or `null` when no step-up is needed. `path`
 * is either the raw upstream path (normalised here) or segments already produced by
 * `normaliseUpstreamPath` (not decoded a second time).
 */
export function stepUpAction(
  service: string,
  method: string,
  path: string | readonly string[],
): StepUpAction | null {
  const upper = method.toUpperCase();
  if (!WRITE.includes(upper as (typeof WRITE)[number])) return null;
  const segments =
    typeof path === 'string' ? normaliseUpstreamPath(path) : path.map((s) => s.toLowerCase());
  const svc = service.toLowerCase();
  for (const m of MATCHERS) {
    if (m.service === svc && m.methods.includes(upper) && matches(m.pattern, segments)) {
      return m.action;
    }
  }
  return null;
}

/** Parses `CONSOLE_STEP_UP_MAX_AGE` (seconds). Invalid values fall back to the default. */
export function stepUpMaxAgeSeconds(raw: string | undefined | null): number {
  if (raw === undefined || raw === null || raw.trim() === '') return DEFAULT_STEP_UP_MAX_AGE_S;
  const value = Number(raw.trim());
  if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0) {
    return DEFAULT_STEP_UP_MAX_AGE_S;
  }
  return Math.max(MIN_STEP_UP_MAX_AGE_S, value);
}

/**
 * Whether the user authenticated recently enough. `authTime` is epoch seconds (OIDC `auth_time`);
 * a missing value (sessions issued before step-up existed) is never fresh.
 */
export function isAuthFresh(
  authTime: number | null | undefined,
  maxAgeSeconds: number,
  nowMs: number = Date.now(),
): boolean {
  if (typeof authTime !== 'number' || !Number.isFinite(authTime)) return false;
  const ageSeconds = nowMs / 1000 - authTime;
  return ageSeconds >= -FUTURE_SKEW_S && ageSeconds <= maxAgeSeconds;
}

/** Recognises the proxy's step-up problem (by `code` extension member or problem `type`). */
export function isStepUpProblem(problem: unknown): boolean {
  if (!problem || typeof problem !== 'object') return false;
  const p = problem as { status?: unknown; code?: unknown; type?: unknown };
  if (p.status !== undefined && p.status !== 401) return false;
  return p.code === STEP_UP_CODE || p.type === STEP_UP_PROBLEM_TYPE;
}

/** RFC 9457 body of the step-up problem (also used by the demo mock worker). */
export function stepUpProblemBody(action: StepUpAction, maxAgeSeconds: number, instance?: string) {
  return {
    type: STEP_UP_PROBLEM_TYPE,
    title: 'Re-authentication required',
    status: 401,
    detail: `Confirm your identity to ${STEP_UP_ACTION_LABEL[action]}: this action needs a sign-in from the last ${maxAgeSeconds} seconds.`,
    code: STEP_UP_CODE,
    action,
    max_age: maxAgeSeconds,
    ...(instance ? { instance } : {}),
  };
}

/** RFC 9470 challenge sent alongside the problem body. */
export function stepUpChallenge(maxAgeSeconds: number): string {
  return `Bearer error="insufficient_user_authentication", error_description="A more recent authentication is required", max_age=${maxAgeSeconds}`;
}

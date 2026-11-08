/** Query key factory. Keep prefixes stable: WebSocket invalidation relies on them. */
export const queryKeys = {
  tenant: ['tenant'] as const,
  fleet: {
    all: ['fleet'] as const,
    summary: () => ['fleet', 'summary'] as const,
    health: (window: string) => ['fleet', 'health', window] as const,
  },
  devices: {
    all: ['devices'] as const,
    lists: () => ['devices', 'list'] as const,
    list: (filters: Record<string, unknown>) => ['devices', 'list', filters] as const,
    detail: (id: string) => ['devices', 'detail', id] as const,
    timeline: (id: string, filters: Record<string, unknown> = {}) =>
      ['devices', 'detail', id, 'timeline', filters] as const,
    telemetry: (id: string, filters: Record<string, unknown> = {}) =>
      ['devices', 'detail', id, 'telemetry', filters] as const,
    twin: (id: string) => ['devices', 'detail', id, 'twin'] as const,
    commands: (id: string, filters: Record<string, unknown> = {}) =>
      ['devices', 'detail', id, 'commands', filters] as const,
    config: (id: string) => ['devices', 'detail', id, 'config'] as const,
    certificates: (id: string) => ['devices', 'detail', id, 'certificates'] as const,
    baseline: (id: string) => ['devices', 'detail', id, 'baseline'] as const,
  },
  commands: {
    detail: (cmdId: string) => ['commands', cmdId] as const,
  },
  groups: {
    all: ['groups'] as const,
  },
  provisioning: {
    all: ['provisioning'] as const,
    list: (filters: Record<string, unknown>) => ['provisioning', 'list', filters] as const,
  },
  audit: {
    all: ['audit'] as const,
    list: (filters: Record<string, unknown>) => ['audit', 'list', filters] as const,
  },
  users: ['users'] as const,
  apiKeys: ['api-keys'] as const,
  firmware: {
    all: ['firmware'] as const,
    list: (filters: Record<string, unknown>) => ['firmware', 'list', filters] as const,
    detail: (id: string) => ['firmware', 'detail', id] as const,
  },
  signingKeys: ['signing-keys'] as const,
  campaigns: {
    all: ['campaigns'] as const,
    lists: () => ['campaigns', 'list'] as const,
    list: (filters: Record<string, unknown>) => ['campaigns', 'list', filters] as const,
    detail: (id: string) => ['campaigns', 'detail', id] as const,
    devices: (id: string, filters: Record<string, unknown> = {}) =>
      ['campaigns', 'detail', id, 'devices', filters] as const,
    audit: (id: string) => ['campaigns', 'detail', id, 'audit'] as const,
  },
  alerts: {
    all: ['alerts'] as const,
    lists: () => ['alerts', 'list'] as const,
    list: (filters: Record<string, unknown>) => ['alerts', 'list', filters] as const,
    detail: (id: string) => ['alerts', 'detail', id] as const,
  },
  rules: ['rules'] as const,
  quarantine: {
    all: ['quarantine'] as const,
    list: (filters: Record<string, unknown>) => ['quarantine', 'list', filters] as const,
  },
  anomalySettings: ['anomaly-settings'] as const,
  policy: {
    all: ['policy'] as const,
    current: () => ['policy', 'current'] as const,
    history: () => ['policy', 'history'] as const,
  },
  revocations: ['revocations'] as const,
};

import 'server-only';
import type { Service } from '@/lib/api/client';

const DEFAULTS: Record<Service, string> = {
  registry: 'http://localhost:8000',
  ota: 'http://localhost:8001',
  anomaly: 'http://localhost:8002',
  policy: 'http://localhost:8081',
};

/**
 * Upstream URL variables. The Helm chart (deploy/helm/ironmesh) injects `CONSOLE_<SERVICE>_URL`;
 * the bare `<SERVICE>_URL` names remain supported for compose / local development.
 */
const ENV_NAMES: Record<Service, [primary: string, fallback: string]> = {
  registry: ['CONSOLE_REGISTRY_URL', 'REGISTRY_URL'],
  ota: ['CONSOLE_OTA_URL', 'OTA_URL'],
  anomaly: ['CONSOLE_ANOMALY_URL', 'ANOMALY_URL'],
  policy: ['CONSOLE_POLICY_URL', 'POLICY_URL'],
};

export function isService(value: string): value is Service {
  return value in DEFAULTS;
}

/** Upstream base URL for a service, without a trailing slash. */
export function serviceBaseUrl(service: Service): string {
  const [primary, fallback] = ENV_NAMES[service];
  const raw = process.env[primary] || process.env[fallback] || DEFAULTS[service];
  return raw.replace(/\/+$/, '');
}

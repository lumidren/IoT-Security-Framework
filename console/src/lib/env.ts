/** Browser-safe configuration. `NEXT_PUBLIC_*` values are inlined at build time. */
export const isMockMode = process.env.NEXT_PUBLIC_MOCK_API === 'true';

export const publicEnv = {
  wsUrl: process.env.NEXT_PUBLIC_WS_URL ?? '',
  mapStyleUrl: process.env.NEXT_PUBLIC_MAP_STYLE_URL ?? '',
  /** Public console URL as injected by the Helm chart (also the Auth.js fallback URL). */
  appUrl: process.env.NEXT_PUBLIC_APP_URL ?? '',
  /** Deployment environment label shown in the header, e.g. "staging" (Helm: NEXT_PUBLIC_ENVIRONMENT). */
  environment: process.env.NEXT_PUBLIC_ENVIRONMENT ?? '',
} as const;

/** The tenant used by demo mode fixtures and the demo sign-in provider. */
export const DEMO_TENANT_ID = '7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11';
export const DEMO_TENANT_NAME = 'Acme Robotics (demo)';

/**
 * Resolves the WebSocket URL the browser should connect to. Falls back to the current origin
 * (`/v1/ws`) which matches the recommended reverse-proxy layout.
 */
export function resolveWsUrl(): string {
  if (publicEnv.wsUrl) return publicEnv.wsUrl;
  if (publicEnv.appUrl) {
    try {
      const url = new URL(publicEnv.appUrl);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      url.pathname = '/v1/ws';
      url.search = '';
      return url.toString();
    } catch {
      // fall through to the current origin
    }
  }
  if (typeof window === 'undefined') return '';
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/v1/ws`;
}

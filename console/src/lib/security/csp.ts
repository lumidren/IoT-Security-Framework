/**
 * Content-Security-Policy builder. The policy is generated per request in `src/middleware.ts` so
 * every response carries a fresh script nonce; Next.js reads the nonce from the request's
 * `content-security-policy` header and stamps it on its own inline and chunk scripts.
 *
 * Kept free of `next/*` imports so it runs in the Edge middleware and in unit tests alike.
 */

export interface CspSources {
  /** Map tile origins (img-src / connect-src), from `MAP_TILE_ORIGINS`. */
  tileOrigins: string[];
  /** Origin of `NEXT_PUBLIC_MAP_STYLE_URL`, when set. */
  mapOrigin: string | null;
  /** Origin of `NEXT_PUBLIC_WS_URL`, when set. */
  wsOrigin: string | null;
}

export interface CspOptions extends CspSources {
  nonce: string;
  /** Development adds `'unsafe-eval'` (React Refresh) and `ws:` (HMR socket). */
  isDev: boolean;
}

export const DEFAULT_TILE_ORIGINS = 'https://tile.openstreetmap.org';

export function originOf(url: string | undefined | null): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.origin === 'null' ? null : parsed.origin;
  } catch {
    return null;
  }
}

/** Reads the CSP source lists from the environment (server-side, evaluated per request). */
export function cspSourcesFromEnv(env: Record<string, string | undefined>): CspSources {
  const tileOrigins = (env['MAP_TILE_ORIGINS'] ?? DEFAULT_TILE_ORIGINS)
    .split(',')
    .map((s) => originOf(s.trim()))
    .filter((v): v is string => Boolean(v));
  return {
    tileOrigins,
    mapOrigin: originOf(env['NEXT_PUBLIC_MAP_STYLE_URL']),
    wsOrigin: originOf(env['NEXT_PUBLIC_WS_URL']),
  };
}

/** 128-bit random nonce, base64-encoded (Web Crypto: works in Edge, Node and the browser). */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

const NONCE_PATTERN = /^[A-Za-z0-9+/=_-]{16,}$/;

function sourceList(values: (string | null | false | undefined)[]): string {
  return [...new Set(values.filter((v): v is string => Boolean(v)))].join(' ');
}

/**
 * Builds the policy. Scripts: only those carrying the per-request nonce, plus whatever they load
 * (`'strict-dynamic'`, which makes CSP3 browsers ignore `'self'`; `'self'` stays as the CSP2
 * fallback). Styles keep `'unsafe-inline'`: Radix UI and next-themes set `style` attributes and
 * CodeMirror / Sonner inject `<style>` elements at runtime, which nonces cannot cover (a nonce in
 * style-src would also disable `'unsafe-inline'` for attributes).
 */
export function buildCsp(options: CspOptions): string {
  if (!NONCE_PATTERN.test(options.nonce)) {
    throw new Error('CSP nonce must be at least 16 base64 characters.');
  }
  const scriptSrc = sourceList([
    "'self'",
    `'nonce-${options.nonce}'`,
    "'strict-dynamic'",
    options.isDev && "'unsafe-eval'",
  ]);
  const connectSrc = sourceList([
    "'self'",
    ...options.tileOrigins,
    options.mapOrigin,
    options.wsOrigin,
    options.isDev && 'ws:',
  ]);
  const imgSrc = sourceList([
    "'self'",
    'data:',
    'blob:',
    ...options.tileOrigins,
    options.mapOrigin,
  ]);

  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src ${imgSrc}`,
    "font-src 'self'",
    `connect-src ${connectSrc}`,
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join('; ');
}

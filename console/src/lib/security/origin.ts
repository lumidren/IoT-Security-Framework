/**
 * CSRF defence for the console's own API routes (`/api/proxy/*`, `/api/ws/ticket`): every
 * state-changing request must come from a page served by the console itself. Browsers always send
 * `Origin` on POST / PUT / PATCH / DELETE; `Referer` is the fallback for the rare client that
 * omits it. A request with neither (or with `Origin: null`) is refused.
 *
 * Framework-free so it can be unit tested without a Next.js runtime.
 */

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

type Env = Record<string, string | undefined>;

export type OriginCheck = { ok: true } | { ok: false; reason: string };

function normaliseOrigin(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.origin.toLowerCase();
  } catch {
    return null;
  }
}

function firstValue(header: string | null): string | null {
  if (!header) return null;
  const first = header.split(',')[0]?.trim();
  return first && first.length > 0 ? first : null;
}

/**
 * The console's own origin(s). `AUTH_URL` and `NEXT_PUBLIC_APP_URL` win when configured (both are
 * accepted, since either may name the public URL); otherwise the origin is derived from the
 * request's `Host` (and `X-Forwarded-Host` / `X-Forwarded-Proto` when `AUTH_TRUST_HOST=true`).
 */
export function expectedOrigins(env: Env, headers: Headers, requestUrl: string): string[] {
  const configured = [env['AUTH_URL'], env['NEXT_PUBLIC_APP_URL']]
    .map(normaliseOrigin)
    .filter((v): v is string => Boolean(v));
  if (configured.length > 0) return [...new Set(configured)];

  const trustProxy = env['AUTH_TRUST_HOST'] === 'true';
  let protocol = 'http:';
  try {
    protocol = new URL(requestUrl).protocol;
  } catch {
    // keep http:
  }
  const forwardedProto = trustProxy ? firstValue(headers.get('x-forwarded-proto')) : null;
  if (forwardedProto === 'https' || forwardedProto === 'http') protocol = `${forwardedProto}:`;

  const hosts = [
    trustProxy ? firstValue(headers.get('x-forwarded-host')) : null,
    headers.get('host'),
  ];
  if (hosts.every((h) => !h)) {
    try {
      hosts.push(new URL(requestUrl).host);
    } catch {
      // no usable host
    }
  }
  return [
    ...new Set(
      hosts
        .filter((h): h is string => Boolean(h))
        .map((host) => normaliseOrigin(`${protocol}//${host}`))
        .filter((v): v is string => Boolean(v)),
    ),
  ];
}

/** Origin of the request initiator: `Origin`, else the origin of `Referer`. */
export function requestInitiatorOrigin(headers: Headers): string | null {
  const origin = headers.get('origin');
  if (origin !== null) {
    // `Origin: null` (sandboxed frames, privacy redirects) is never trusted.
    return origin.trim() === 'null' ? null : normaliseOrigin(origin);
  }
  return normaliseOrigin(headers.get('referer'));
}

export function isMutatingMethod(method: string): boolean {
  return MUTATING.has(method.toUpperCase());
}

/** Allows safe methods; for mutations requires the initiator origin to be the console's own. */
export function checkSameOrigin(
  method: string,
  headers: Headers,
  requestUrl: string,
  env: Env,
): OriginCheck {
  if (!isMutatingMethod(method)) return { ok: true };
  const initiator = requestInitiatorOrigin(headers);
  if (!initiator) {
    return { ok: false, reason: 'The request carries no usable Origin or Referer header.' };
  }
  const allowed = expectedOrigins(env, headers, requestUrl);
  if (allowed.includes(initiator)) return { ok: true };
  return { ok: false, reason: `Origin ${initiator} is not allowed to call this console.` };
}

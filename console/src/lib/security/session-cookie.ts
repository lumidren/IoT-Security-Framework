/**
 * Auth.js session cookie settings, shared by `src/auth.ts` (which writes the cookie) and
 * `src/lib/server/token.ts` (which decrypts it for the proxy: the cookie name is also the JWE salt,
 * so both sides must agree).
 *
 * - `SameSite=Strict`: the cookie is never attached to cross-site requests, top-level navigations
 *   included. `src/middleware.ts` bounces cross-site navigations through `/auth/continue` so links
 *   from mail or chat and the OIDC callback redirect still land signed in.
 * - Served over https: `Secure` and the `__Host-` prefix (no `Domain`, `Path=/`), so a sibling
 *   subdomain cannot plant or shadow the cookie.
 */

type Env = Record<string, string | undefined>;

export interface SessionCookieSettings {
  name: string;
  secure: boolean;
}

export const SESSION_COOKIE_BASENAME = 'authjs.session-token';

/**
 * https is decided from the configured public URL (`AUTH_URL`, else `NEXT_PUBLIC_APP_URL`). With no
 * URL configured, production builds assume TLS (except the demo build, which is served on
 * http://localhost) and development does not.
 */
export function usesSecureCookies(env: Env): boolean {
  const url = env['AUTH_URL'] || env['NEXT_PUBLIC_APP_URL'];
  if (url) {
    try {
      return new URL(url).protocol === 'https:';
    } catch {
      // fall through to the environment default
    }
  }
  return env['NODE_ENV'] === 'production' && env['NEXT_PUBLIC_MOCK_API'] !== 'true';
}

export function sessionCookieSettings(env: Env): SessionCookieSettings {
  const secure = usesSecureCookies(env);
  return { name: `${secure ? '__Host-' : ''}${SESSION_COOKIE_BASENAME}`, secure };
}

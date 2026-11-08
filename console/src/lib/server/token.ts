import 'server-only';
import type { NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';

export interface SessionTokenInfo {
  accessToken: string | null;
  /** Epoch milliseconds, when the IdP reported `expires_at`. */
  accessTokenExpires: number | null;
  provider: string | null;
}

/**
 * Reads the encrypted Auth.js session cookie server-side. The OIDC access token never leaves the
 * server: it is attached to upstream requests by the proxy only.
 */
export async function readSessionToken(req: NextRequest): Promise<SessionTokenInfo | null> {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return null;
  const secure =
    req.nextUrl.protocol === 'https:' || req.headers.get('x-forwarded-proto') === 'https';
  const cookieName = secure ? '__Secure-authjs.session-token' : 'authjs.session-token';
  const token = await getToken({ req, secret, salt: cookieName, cookieName, secureCookie: secure });
  if (!token) return null;
  return {
    accessToken: typeof token.accessToken === 'string' ? token.accessToken : null,
    accessTokenExpires:
      typeof token.accessTokenExpires === 'number' ? token.accessTokenExpires : null,
    provider: typeof token.provider === 'string' ? token.provider : null,
  };
}

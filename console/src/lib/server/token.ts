import 'server-only';
import type { NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { sessionCookie } from '@/auth';

export interface SessionTokenInfo {
  accessToken: string | null;
  /** Epoch milliseconds, when the IdP reported `expires_at`. */
  accessTokenExpires: number | null;
  provider: string | null;
  /** Epoch seconds of the last authentication (step-up checks). */
  authTime: number | null;
}

/**
 * Reads the encrypted Auth.js session cookie server-side. The OIDC access token never leaves the
 * server: it is attached to upstream requests by the proxy only. The cookie name (also the JWE
 * salt) comes from the Auth.js config so a `__Host-` cookie is read back correctly.
 */
export async function readSessionToken(req: NextRequest): Promise<SessionTokenInfo | null> {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return null;
  const cookieName = sessionCookie.name;
  const token = await getToken({
    req,
    secret,
    salt: cookieName,
    cookieName,
    secureCookie: sessionCookie.secure,
  });
  if (!token) return null;
  return {
    accessToken: typeof token.accessToken === 'string' ? token.accessToken : null,
    accessTokenExpires:
      typeof token.accessTokenExpires === 'number' ? token.accessTokenExpires : null,
    provider: typeof token.provider === 'string' ? token.provider : null,
    authTime: typeof token.authTime === 'number' ? token.authTime : null,
  };
}

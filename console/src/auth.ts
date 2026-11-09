import NextAuth, { type NextAuthConfig } from 'next-auth';
import type { Provider } from 'next-auth/providers';
import Credentials from 'next-auth/providers/credentials';
import { DEMO_TENANT_ID, DEMO_TENANT_NAME, isMockMode } from '@/lib/env';
import { ROLE_RANK, isRole, type Role } from '@/lib/rbac';
import { sessionCookieSettings } from '@/lib/security/session-cookie';
import { stepUpMaxAgeSeconds } from '@/lib/security/step-up';

const roleClaim = process.env.AUTH_ROLE_CLAIM ?? 'role';
const tenantClaim = process.env.AUTH_TENANT_CLAIM ?? 'tenant_id';
const tenantNameClaim = process.env.AUTH_TENANT_NAME_CLAIM ?? 'tenant_name';

/**
 * OIDC settings. The Helm chart injects `CONSOLE_OIDC_*` and `NEXT_PUBLIC_APP_URL`; the
 * `AUTH_OIDC_*` / `AUTH_URL` names from .env.example keep working as fallbacks.
 */
function firstEnv(...names: string[]): string | undefined {
  for (const name of names) {
    const value = process.env[name];
    if (value && value.length > 0) return value;
  }
  return undefined;
}

if (!process.env.AUTH_URL && process.env.NEXT_PUBLIC_APP_URL) {
  process.env.AUTH_URL = process.env.NEXT_PUBLIC_APP_URL;
}

/**
 * Session cookie: SameSite=Strict, plus Secure and the `__Host-` prefix when the console is served
 * over https (see src/lib/security/session-cookie.ts). Exported so the proxy decrypts the same
 * cookie name (it doubles as the JWE salt).
 */
export const sessionCookie = sessionCookieSettings({
  AUTH_URL: process.env.AUTH_URL,
  NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
  NODE_ENV: process.env.NODE_ENV,
  NEXT_PUBLIC_MOCK_API: process.env.NEXT_PUBLIC_MOCK_API,
});

/** `CONSOLE_STEP_UP_MAX_AGE`: how recent a sign-in destructive actions require (seconds). */
export function stepUpMaxAge(): number {
  return stepUpMaxAgeSeconds(process.env.CONSOLE_STEP_UP_MAX_AGE);
}

/** OIDC `auth_time` (epoch seconds) when the IdP sent it. */
function authTimeClaim(claims: Claims): number | undefined {
  const value = claims['auth_time'];
  if (typeof value === 'number' && Number.isFinite(value)) return Math.floor(value);
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

type Claims = Record<string, unknown>;

function highestRole(candidates: unknown[]): Role | null {
  let best: Role | null = null;
  for (const candidate of candidates) {
    if (isRole(candidate) && (best === null || ROLE_RANK[candidate] > ROLE_RANK[best])) {
      best = candidate;
    }
  }
  return best;
}

/** Reads the tenant role from the configured claim; supports a string, a list and Keycloak's realm_access. */
export function roleFromClaims(claims: Claims): Role {
  const raw = claims[roleClaim];
  const direct = highestRole(Array.isArray(raw) ? raw : [raw]);
  if (direct) return direct;
  const realm = claims['realm_access'];
  if (realm && typeof realm === 'object') {
    const roles = (realm as { roles?: unknown }).roles;
    if (Array.isArray(roles)) {
      const fromRealm = highestRole(roles);
      if (fromRealm) return fromRealm;
    }
  }
  return 'viewer';
}

function stringClaim(claims: Claims, key: string): string | undefined {
  const value = claims[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

const providers: Provider[] = [];

const oidcIssuer = firstEnv('CONSOLE_OIDC_ISSUER', 'AUTH_OIDC_ISSUER', 'NEXT_PUBLIC_OIDC_ISSUER');
const oidcClientId = firstEnv(
  'CONSOLE_OIDC_CLIENT_ID',
  'AUTH_OIDC_CLIENT_ID',
  'NEXT_PUBLIC_OIDC_CLIENT_ID',
);
const oidcClientSecret = firstEnv('CONSOLE_OIDC_CLIENT_SECRET', 'AUTH_OIDC_CLIENT_SECRET');
export const oidcConfigured = Boolean(oidcIssuer && oidcClientId);

if (oidcIssuer && oidcClientId) {
  providers.push({
    id: 'oidc',
    name: 'Single sign-on',
    type: 'oidc',
    issuer: oidcIssuer,
    clientId: oidcClientId,
    clientSecret: oidcClientSecret,
    // Step-up re-authentication adds `prompt=login&max_age=0` per sign-in (see StepUpProvider).
    authorization: { params: { scope: 'openid profile email' } },
    checks: ['pkce', 'state'],
    profile(profile) {
      const claims = profile as Claims;
      return {
        id: stringClaim(claims, 'sub') ?? '',
        name: stringClaim(claims, 'name') ?? stringClaim(claims, 'preferred_username') ?? null,
        email: stringClaim(claims, 'email') ?? null,
        image: stringClaim(claims, 'picture') ?? null,
        role: roleFromClaims(claims),
        tenantId: stringClaim(claims, tenantClaim) ?? '',
        tenantName: stringClaim(claims, tenantNameClaim),
      };
    },
  });
}

if (isMockMode) {
  providers.push(
    Credentials({
      id: 'demo',
      name: 'Demo sign-in',
      credentials: {
        role: { label: 'Role', type: 'text' },
      },
      authorize(credentials) {
        const role = credentials?.role;
        if (!isRole(role)) return null;
        return {
          id: `demo-${role}`,
          name: `Demo ${role}`,
          email: `${role}@demo.ironmesh.local`,
          role,
          tenantId: DEMO_TENANT_ID,
          tenantName: DEMO_TENANT_NAME,
        };
      },
    }),
  );
}

export const authConfig = {
  providers,
  session: { strategy: 'jwt', maxAge: 8 * 60 * 60 },
  pages: { signIn: '/signin', error: '/signin' },
  trustHost: process.env.AUTH_TRUST_HOST === 'true' || isMockMode,
  useSecureCookies: sessionCookie.secure,
  cookies: {
    sessionToken: {
      name: sessionCookie.name,
      options: {
        httpOnly: true,
        sameSite: 'strict',
        path: '/',
        secure: sessionCookie.secure,
      },
    },
  },
  callbacks: {
    jwt({ token, user, account, profile }) {
      if (account) {
        token.accessToken = account.access_token;
        token.accessTokenExpires = account.expires_at ? account.expires_at * 1000 : undefined;
        token.provider = account.provider;
        // `account` is only present on an actual sign-in. Prefer the IdP's `auth_time` (when the
        // user really authenticated, which may predate this sign-in under IdP SSO); the demo
        // provider and IdPs that omit the claim get the sign-in time.
        const claimed = profile ? authTimeClaim(profile as Claims) : undefined;
        token.authTime = claimed ?? Math.floor(Date.now() / 1000);
      }
      if (user) {
        token.role = user.role ?? 'viewer';
        token.tenantId = user.tenantId ?? '';
        token.tenantName = user.tenantName;
      }
      if (profile) {
        const claims = profile as Claims;
        token.role = roleFromClaims(claims);
        token.tenantId = stringClaim(claims, tenantClaim) ?? token.tenantId ?? '';
        token.tenantName = stringClaim(claims, tenantNameClaim) ?? token.tenantName;
      }
      return token;
    },
    session({ session, token }) {
      session.user.role = isRole(token.role) ? token.role : 'viewer';
      session.user.tenantId = typeof token.tenantId === 'string' ? token.tenantId : '';
      session.user.tenantName = typeof token.tenantName === 'string' ? token.tenantName : undefined;
      session.user.provider = typeof token.provider === 'string' ? token.provider : undefined;
      session.user.authTime = typeof token.authTime === 'number' ? token.authTime : undefined;
      if (typeof token.sub === 'string') session.user.id = token.sub;
      session.stepUpMaxAge = stepUpMaxAge();
      return session;
    },
  },
} satisfies NextAuthConfig;

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);

import type { DefaultSession } from 'next-auth';
import type { Role } from '@/lib/rbac';

declare module 'next-auth' {
  interface User {
    role?: Role;
    tenantId?: string;
    tenantName?: string;
  }

  interface Session {
    user: {
      id?: string;
      role: Role;
      tenantId: string;
      tenantName?: string;
      provider?: string;
      /** When the user last authenticated at the IdP (epoch seconds, OIDC `auth_time`). */
      authTime?: number;
    } & DefaultSession['user'];
    /** `CONSOLE_STEP_UP_MAX_AGE` in seconds (read by the demo mock worker's step-up emulation). */
    stepUpMaxAge?: number;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    role?: Role;
    tenantId?: string;
    tenantName?: string;
    provider?: string;
    accessToken?: string;
    accessTokenExpires?: number;
    /** Epoch seconds of the last real authentication (OIDC `auth_time`, else sign-in time). */
    authTime?: number;
  }
}

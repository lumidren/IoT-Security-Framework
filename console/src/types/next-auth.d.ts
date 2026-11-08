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
    } & DefaultSession['user'];
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
  }
}

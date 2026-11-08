import type { Session } from 'next-auth';
import type { Role } from '@/lib/rbac';

/** The subset of the session handed to client components (no tokens). */
export interface ConsoleUser {
  id: string;
  name: string;
  email: string;
  image: string | null;
  role: Role;
  tenantId: string;
  tenantName: string | null;
  provider: string | null;
}

/** Server-safe mapping from an Auth.js session to the console user model. */
export function userFromSession(session: Session): ConsoleUser {
  const user = session.user;
  return {
    id: user.id ?? user.email ?? 'unknown',
    name: user.name ?? user.email ?? 'Signed-in user',
    email: user.email ?? '',
    image: user.image ?? null,
    role: user.role,
    tenantId: user.tenantId,
    tenantName: user.tenantName ?? null,
    provider: user.provider ?? null,
  };
}

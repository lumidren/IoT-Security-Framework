'use client';

import * as React from 'react';
import { can, type Permission, type Role } from '@/lib/rbac';
import type { ConsoleUser } from '@/lib/session-user';

export type { ConsoleUser };

const SessionContext = React.createContext<ConsoleUser | null>(null);

export function SessionProvider({
  user,
  children,
}: {
  user: ConsoleUser;
  children: React.ReactNode;
}) {
  return <SessionContext.Provider value={user}>{children}</SessionContext.Provider>;
}

export function useCurrentUser(): ConsoleUser {
  const user = React.useContext(SessionContext);
  if (!user) {
    throw new Error('useCurrentUser must be used inside the authenticated console layout.');
  }
  return user;
}

export function useRole(): Role {
  return useCurrentUser().role;
}

/** `can(role, permission)` bound to the current session. */
export function usePermission(permission: Permission): boolean {
  const role = useRole();
  return can(role, permission);
}

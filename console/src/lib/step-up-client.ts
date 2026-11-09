'use client';

import { signIn } from 'next-auth/react';
import type { Role } from '@/lib/rbac';

/** Same-origin channel the step-up pop-up uses to report back (COOP severs `window.opener`). */
export const REAUTH_CHANNEL = 'ironmesh-reauth';
export const REAUTH_COMPLETE_PATH = '/auth/reauth/complete';
export const REAUTH_POPUP_PATH = '/auth/reauth';

export interface ReauthMessage {
  type: 'reauth-complete';
}

export function isReauthMessage(data: unknown): data is ReauthMessage {
  return Boolean(data) && (data as { type?: unknown }).type === 'reauth-complete';
}

/**
 * Forces a fresh login at the IdP: `prompt=login` makes it re-prompt even with an SSO session and
 * `max_age=0` makes it return a current `auth_time`. Navigates the current window.
 */
export function startOidcStepUp(redirectTo: string): Promise<unknown> {
  return signIn('oidc', { redirectTo }, { prompt: 'login', max_age: '0' });
}

/** Demo provider: re-run the demo sign-in (new session, new `auth_time`) without navigating. */
export async function reauthenticateDemo(role: Role): Promise<boolean> {
  const result = await signIn('demo', { role, redirect: false });
  return Boolean(result && result.ok && !result.error);
}

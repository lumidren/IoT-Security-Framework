'use client';

import * as React from 'react';
import { Loader2Icon, ShieldAlertIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { setStepUpHandler } from '@/lib/api/client';
import type { ProblemDetails } from '@/lib/api/schemas';
import {
  REAUTH_CHANNEL,
  REAUTH_POPUP_PATH,
  isReauthMessage,
  reauthenticateDemo,
  startOidcStepUp,
} from '@/lib/step-up-client';
import { useCurrentUser } from '@/providers/session-context';

type Phase = 'prompt' | 'working' | 'waiting-popup' | 'error';

interface PendingStepUp {
  problem: ProblemDetails;
  resolve: (ok: boolean) => void;
}

function currentPath(): string {
  return `${window.location.pathname}${window.location.search}`;
}

/**
 * Handles the proxy's 401 `step_up_required` problem for destructive actions: asks the operator to
 * confirm their identity, re-authenticates, then lets `apiFetch` retry the request once.
 *
 * - Demo provider: re-runs the demo sign-in in place (new session, fresh `auth_time`).
 * - OIDC: opens `/auth/reauth` in a pop-up, which calls
 *   `signIn('oidc', …, { prompt: 'login', max_age: '0' })`; the pop-up reports back on a
 *   BroadcastChannel (COOP `same-origin` severs `window.opener` once it visits the IdP). If the
 *   pop-up is blocked, the whole tab goes through the same forced login and the action is not
 *   retried automatically.
 *
 * Concurrent step-up failures share one prompt.
 */
export function StepUpProvider({ children }: { children: React.ReactNode }) {
  const user = useCurrentUser();
  const [pending, setPending] = React.useState<PendingStepUp | null>(null);
  const [phase, setPhase] = React.useState<Phase>('prompt');
  const [error, setError] = React.useState<string | null>(null);
  const pendingRef = React.useRef<PendingStepUp | null>(null);
  const sharedRef = React.useRef<Promise<boolean> | null>(null);
  const channelRef = React.useRef<BroadcastChannel | null>(null);

  const closeChannel = React.useCallback(() => {
    channelRef.current?.close();
    channelRef.current = null;
  }, []);

  const settle = React.useCallback(
    (ok: boolean) => {
      closeChannel();
      const entry = pendingRef.current;
      pendingRef.current = null;
      setPending(null);
      setPhase('prompt');
      setError(null);
      entry?.resolve(ok);
    },
    [closeChannel],
  );

  React.useEffect(() => {
    const unregister = setStepUpHandler((problem) => {
      if (sharedRef.current) return sharedRef.current;
      const promise = new Promise<boolean>((resolve) => {
        const entry: PendingStepUp = { problem, resolve };
        pendingRef.current = entry;
        setPending(entry);
        setPhase('prompt');
        setError(null);
      }).finally(() => {
        sharedRef.current = null;
      });
      sharedRef.current = promise;
      return promise;
    });
    return () => {
      unregister();
      closeChannel();
      pendingRef.current?.resolve(false);
      pendingRef.current = null;
    };
  }, [closeChannel]);

  /** After re-authenticating, the console must still be signed in as the same operator. */
  const confirmSameUser = React.useCallback(async (): Promise<boolean> => {
    try {
      const response = await fetch('/api/auth/session', {
        credentials: 'same-origin',
        cache: 'no-store',
      });
      const session = (await response.json()) as {
        user?: { id?: string; email?: string };
      } | null;
      const id = session?.user?.id ?? session?.user?.email;
      if (!id) return false;
      if (id !== user.id) {
        // A different account signed in: the page's session context is stale.
        window.location.reload();
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }, [user.id]);

  const fail = (message: string) => {
    setPhase('error');
    setError(message);
  };

  const reauthenticate = async () => {
    setError(null);
    if (user.provider === 'demo') {
      setPhase('working');
      try {
        const ok = (await reauthenticateDemo(user.role)) && (await confirmSameUser());
        if (ok) settle(true);
        else fail('Re-authentication failed. Try again.');
      } catch {
        fail('Re-authentication failed. Try again.');
      }
      return;
    }

    closeChannel();
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel(REAUTH_CHANNEL);
      channel.onmessage = (event: MessageEvent) => {
        if (!isReauthMessage(event.data)) return;
        closeChannel();
        setPhase('working');
        void confirmSameUser().then((ok) => {
          if (ok) settle(true);
          else fail('The new sign-in could not be confirmed. Try again.');
        });
      };
      channelRef.current = channel;
    }
    const popup =
      channelRef.current &&
      window.open(REAUTH_POPUP_PATH, 'ironmesh-reauth', 'popup=yes,width=520,height=700');
    if (!popup) {
      // Pop-up blocked: re-authenticate in this tab; the operator repeats the action afterwards.
      settle(false);
      await startOidcStepUp(currentPath());
      return;
    }
    setPhase('waiting-popup');
  };

  const open = pending !== null;
  const busy = phase === 'working';
  const maxAge = pending?.problem['max_age'];
  const windowLabel =
    typeof maxAge === 'number' && maxAge > 0
      ? maxAge >= 120
        ? `${Math.round(maxAge / 60)} minutes`
        : `${maxAge} seconds`
      : 'few minutes';

  return (
    <>
      {children}
      <Dialog open={open} onOpenChange={(next) => !next && !busy && settle(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlertIcon className="size-5 text-warning" aria-hidden="true" />
              Confirm it&apos;s you
            </DialogTitle>
            <DialogDescription>
              {pending?.problem.detail ??
                'This action needs a recent sign-in before it can be performed.'}
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2 text-sm">
            <p className="text-muted-foreground">
              Destructive actions require a sign-in from the last {windowLabel}.{' '}
              {user.provider === 'demo'
                ? 'The demo sign-in is repeated for your current role.'
                : 'Your identity provider asks for your credentials again in a pop-up window.'}
            </p>
            {phase === 'waiting-popup' && (
              <p role="status" className="flex items-center gap-2">
                <Loader2Icon className="size-4 animate-spin" aria-hidden="true" />
                Complete the sign-in in the pop-up window…
              </p>
            )}
            {error && (
              <p role="alert" className="text-destructive">
                {error}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => settle(false)} disabled={busy}>
              Cancel
            </Button>
            <Button type="button" onClick={() => void reauthenticate()} disabled={busy}>
              {busy && <Loader2Icon className="animate-spin" aria-hidden="true" />}
              {phase === 'waiting-popup' ? 'Open the pop-up again' : 'Re-authenticate'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

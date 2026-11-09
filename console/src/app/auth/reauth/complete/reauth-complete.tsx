'use client';

import * as React from 'react';
import { REAUTH_CHANNEL, type ReauthMessage } from '@/lib/step-up-client';

/** Tells the console tab that re-authentication finished, then closes the pop-up. */
export function ReauthComplete() {
  React.useEffect(() => {
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel(REAUTH_CHANNEL);
      const message: ReauthMessage = { type: 'reauth-complete' };
      channel.postMessage(message);
      channel.close();
    }
    window.close();
  }, []);
  return (
    <p className="text-sm text-muted-foreground" role="status">
      Identity confirmed. You can close this window and return to the console.
    </p>
  );
}

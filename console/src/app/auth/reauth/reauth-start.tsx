'use client';

import * as React from 'react';
import { REAUTH_COMPLETE_PATH, startOidcStepUp } from '@/lib/step-up-client';

export function ReauthStart() {
  const [failed, setFailed] = React.useState(false);
  React.useEffect(() => {
    startOidcStepUp(REAUTH_COMPLETE_PATH).catch(() => setFailed(true));
  }, []);
  return (
    <p className="text-sm text-muted-foreground" role="status">
      {failed
        ? 'Could not reach the identity provider. Close this window and try again.'
        : 'Redirecting to your identity provider…'}
    </p>
  );
}

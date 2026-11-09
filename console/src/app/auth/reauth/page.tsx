import type { Metadata } from 'next';
import { ReauthStart } from './reauth-start';

export const metadata: Metadata = { title: 'Confirm your identity', robots: { index: false } };

/** Opened in a pop-up by StepUpProvider: starts a forced OIDC login (prompt=login, max_age=0). */
export default function ReauthPage() {
  return (
    <main id="main-content" className="flex min-h-dvh items-center justify-center p-4">
      <ReauthStart />
    </main>
  );
}

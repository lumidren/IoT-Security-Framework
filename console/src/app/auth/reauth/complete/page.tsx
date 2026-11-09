import type { Metadata } from 'next';
import { ReauthComplete } from './reauth-complete';

export const metadata: Metadata = { title: 'Identity confirmed', robots: { index: false } };

/** Landing page of the step-up pop-up after the IdP round trip. */
export default function ReauthCompletePage() {
  return (
    <main id="main-content" className="flex min-h-dvh items-center justify-center p-4">
      <ReauthComplete />
    </main>
  );
}

'use client';

import * as React from 'react';
import { isMockMode } from '@/lib/env';

type MockState = 'disabled' | 'starting' | 'ready' | 'failed';

const MockContext = React.createContext<MockState>('disabled');

/**
 * Starts the Mock Service Worker before any data fetch when `NEXT_PUBLIC_MOCK_API=true`. In normal
 * builds the dynamic import is never evaluated, so MSW stays out of the production bundle.
 */
export function MockProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = React.useState<MockState>(isMockMode ? 'starting' : 'disabled');

  React.useEffect(() => {
    if (!isMockMode) return;
    let cancelled = false;
    import('@/mocks/browser')
      .then(({ startMockWorker }) => startMockWorker())
      .then(() => {
        if (!cancelled) setState('ready');
      })
      .catch((error: unknown) => {
        console.error('Mock Service Worker failed to start', error);
        if (!cancelled) setState('failed');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (state === 'starting') {
    return (
      <div
        className="flex min-h-dvh items-center justify-center p-6"
        role="status"
        aria-live="polite"
      >
        <p className="text-sm text-muted-foreground">Starting demo mode…</p>
      </div>
    );
  }

  return <MockContext.Provider value={state}>{children}</MockContext.Provider>;
}

export function useMockState(): MockState {
  return React.useContext(MockContext);
}

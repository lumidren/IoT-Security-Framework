import { setupWorker } from 'msw/browser';
import { handlers, setMockLatency, setStepUpEmulation } from './handlers';

export const worker = setupWorker(...handlers);

let started: Promise<void> | null = null;

/** Starts the service worker once; requests the worker cannot match pass through to the server. */
export function startMockWorker(): Promise<void> {
  if (!started) {
    setMockLatency(60);
    setStepUpEmulation(true);
    started = worker
      .start({
        onUnhandledRequest: 'bypass',
        quiet: true,
        serviceWorker: { url: '/mockServiceWorker.js' },
      })
      .then(() => undefined);
  }
  return started;
}

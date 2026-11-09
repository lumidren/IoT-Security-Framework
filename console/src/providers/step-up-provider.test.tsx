import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HttpResponse, http } from 'msw';
import { signIn } from 'next-auth/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useQuarantineDevice } from '@/lib/api/hooks';
import { stepUpProblemBody } from '@/lib/security/step-up';
import { REAUTH_CHANNEL } from '@/lib/step-up-client';
import { db } from '@/mocks/db';
import { server } from '@/mocks/server';
import { setupMockServer } from '@/test/msw';
import { renderWithProviders } from '@/test/render';
import { StepUpProvider } from './step-up-provider';

vi.mock('next-auth/react', () => ({ signIn: vi.fn() }));

setupMockServer();

function QuarantineButton({ id }: { id: string }) {
  const quarantine = useQuarantineDevice();
  return (
    <div>
      <button type="button" onClick={() => quarantine.mutate({ id, reason: 'compromised' })}>
        Quarantine device
      </button>
      {quarantine.isSuccess && <p>Device is now {quarantine.data.state}</p>}
      {quarantine.isError && <p role="alert">{quarantine.error.message}</p>}
    </div>
  );
}

let quarantineCalls = 0;

/** First quarantine call is refused like the proxy would; later calls reach the fixture handler. */
function stepUpOnce() {
  quarantineCalls = 0;
  server.use(
    http.post('*/api/proxy/registry/v1/devices/:id/quarantine', () => {
      quarantineCalls += 1;
      if (quarantineCalls === 1) {
        return HttpResponse.json(stepUpProblemBody('device.quarantine', 300), {
          status: 401,
          headers: { 'content-type': 'application/problem+json' },
        });
      }
      return undefined;
    }),
    http.get('*/api/auth/session', () =>
      HttpResponse.json({ user: { id: 'test-operator' }, stepUpMaxAge: 300 }),
    ),
  );
}

function activeDeviceId(): string {
  const device = db.devices.find((d) => d.detail.state === 'active');
  if (!device) throw new Error('fixture has no active device');
  return device.detail.id;
}

function renderHarness(provider: string) {
  return renderWithProviders(
    <StepUpProvider>
      <QuarantineButton id={activeDeviceId()} />
    </StepUpProvider>,
    { user: { provider } },
  );
}

beforeEach(() => {
  vi.mocked(signIn).mockReset();
});

describe('StepUpProvider', () => {
  it('re-runs the demo sign-in on step_up_required and retries the action', async () => {
    vi.mocked(signIn).mockResolvedValue({
      ok: true,
      status: 200,
      error: undefined,
      code: undefined,
      url: 'http://localhost:3000/',
    });
    stepUpOnce();
    const user = userEvent.setup();
    renderHarness('demo');

    await user.click(screen.getByRole('button', { name: 'Quarantine device' }));
    const dialog = await screen.findByRole('dialog', { name: /Confirm it.s you/ });
    expect(dialog).toHaveTextContent(/quarantine a device/);
    expect(quarantineCalls).toBe(1);

    await user.click(screen.getByRole('button', { name: 'Re-authenticate' }));
    expect(signIn).toHaveBeenCalledWith('demo', { role: 'operator', redirect: false });
    expect(await screen.findByText('Device is now quarantined')).toBeInTheDocument();
    expect(quarantineCalls).toBe(2);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('surfaces the step-up problem when the operator cancels', async () => {
    stepUpOnce();
    const user = userEvent.setup();
    renderHarness('demo');

    await user.click(screen.getByRole('button', { name: 'Quarantine device' }));
    await screen.findByRole('dialog');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/Re-authentication required/);
    expect(signIn).not.toHaveBeenCalled();
    expect(quarantineCalls).toBe(1);
  });

  it('OIDC: re-authenticates in a pop-up and retries when it reports back', async () => {
    stepUpOnce();
    const open = vi.spyOn(window, 'open').mockReturnValue({} as Window);
    const user = userEvent.setup();
    renderHarness('oidc');

    await user.click(screen.getByRole('button', { name: 'Quarantine device' }));
    await screen.findByRole('dialog');
    await user.click(screen.getByRole('button', { name: 'Re-authenticate' }));

    expect(open).toHaveBeenCalledWith('/auth/reauth', 'ironmesh-reauth', expect.any(String));
    expect(await screen.findByText(/Complete the sign-in in the pop-up/)).toBeInTheDocument();

    // What /auth/reauth/complete does once the IdP round trip (prompt=login, max_age=0) is done.
    const popupSide = new BroadcastChannel(REAUTH_CHANNEL);
    popupSide.postMessage({ type: 'reauth-complete' });
    popupSide.close();

    expect(await screen.findByText('Device is now quarantined')).toBeInTheDocument();
    expect(quarantineCalls).toBe(2);
  });

  it('OIDC: falls back to a forced login in this tab when the pop-up is blocked', async () => {
    stepUpOnce();
    vi.spyOn(window, 'open').mockReturnValue(null);
    vi.mocked(signIn).mockResolvedValue(undefined as never);
    const user = userEvent.setup();
    renderHarness('oidc');

    await user.click(screen.getByRole('button', { name: 'Quarantine device' }));
    await screen.findByRole('dialog');
    await user.click(screen.getByRole('button', { name: 'Re-authenticate' }));

    await waitFor(() =>
      expect(signIn).toHaveBeenCalledWith(
        'oidc',
        { redirectTo: expect.stringMatching(/^\//) },
        { prompt: 'login', max_age: '0' },
      ),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(/Re-authentication required/);
    expect(quarantineCalls).toBe(1);
  });
});

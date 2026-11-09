// @vitest-environment node
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('server-only', () => ({}));

const authMock = vi.fn();
const readSessionTokenMock = vi.fn();

vi.mock('@/auth', () => ({
  auth: () => authMock(),
  stepUpMaxAge: () => 300,
}));
vi.mock('@/lib/server/token', () => ({
  readSessionToken: () => readSessionTokenMock(),
}));

const { POST, GET, DELETE } = await import('./route');

const APP = 'https://console.example.com';
const DEVICE = '0b6c6a43-2a61-4b8e-a0a1-7d3b1f0e9c11';
const nowS = () => Math.floor(Date.now() / 1000);

function request(
  method: string,
  service: string,
  path: string[],
  headers: Record<string, string> = { origin: APP },
) {
  const url = `${APP}/api/proxy/${service}/${path.map(encodeURIComponent).join('/')}`;
  const req = new NextRequest(url, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: method === 'GET' ? undefined : JSON.stringify({ reason: 'test' }),
  });
  return [req, { params: Promise.resolve({ service, path }) }] as const;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.stubEnv('AUTH_URL', APP);
  vi.stubEnv('NEXT_PUBLIC_APP_URL', APP);
  vi.stubEnv('CONSOLE_REGISTRY_URL', 'http://registry:8000');
  vi.stubEnv('CONSOLE_OTA_URL', 'http://ota:8001');
  authMock.mockResolvedValue({ user: { role: 'admin', tenantId: 't1' } });
  readSessionTokenMock.mockResolvedValue({
    accessToken: 'access-token',
    accessTokenExpires: null,
    provider: 'oidc',
    authTime: nowS() - 10,
  });
  fetchMock = vi.fn(async () =>
    Response.json({ ok: true }, { status: 200, headers: { 'content-type': 'application/json' } }),
  );
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function problemOf(res: Response) {
  expect(res.headers.get('content-type')).toContain('application/problem+json');
  return (await res.json()) as Record<string, unknown>;
}

describe('proxy CSRF origin check', () => {
  it('forwards a same-origin mutation', async () => {
    const res = await POST(...request('POST', 'registry', ['v1', 'devices', DEVICE, 'commands']));
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [target, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(String(target)).toBe(`http://registry:8000/v1/devices/${DEVICE}/commands`);
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer access-token');
  });

  it('accepts the Referer origin when Origin is absent', async () => {
    const res = await POST(
      ...request('POST', 'registry', ['v1', 'devices', DEVICE, 'commands'], {
        referer: `${APP}/devices/${DEVICE}`,
      }),
    );
    expect(res.status).toBe(200);
  });

  it.each([
    ['a foreign Origin', { origin: 'https://evil.example' }],
    ['Origin: null', { origin: 'null' }],
    ['a foreign Referer', { referer: 'https://evil.example/x' }],
    ['no Origin or Referer', {}],
  ])('rejects %s with a 403 problem before authenticating', async (_label, headers) => {
    const res = await POST(
      ...request('POST', 'registry', ['v1', 'devices', DEVICE, 'commands'], headers),
    );
    expect(res.status).toBe(403);
    expect(await problemOf(res)).toMatchObject({ title: 'Cross-origin request blocked' });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(authMock).not.toHaveBeenCalled();
  });

  it('applies to DELETE too', async () => {
    const res = await DELETE(
      ...request('DELETE', 'registry', ['v1', 'api-keys', DEVICE], {
        origin: 'https://evil.example',
      }),
    );
    expect(res.status).toBe(403);
  });

  it('does not require an Origin on reads', async () => {
    const res = await GET(...request('GET', 'registry', ['v1', 'devices'], {}));
    expect(res.status).toBe(200);
  });
});

describe('proxy step-up', () => {
  it('refuses a destructive action with a stale auth_time (401 step_up_required)', async () => {
    readSessionTokenMock.mockResolvedValue({
      accessToken: 'access-token',
      accessTokenExpires: null,
      provider: 'oidc',
      authTime: nowS() - 3600,
    });
    const res = await POST(...request('POST', 'registry', ['v1', 'devices', DEVICE, 'quarantine']));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('insufficient_user_authentication');
    expect(await problemOf(res)).toMatchObject({
      status: 401,
      code: 'step_up_required',
      action: 'device.quarantine',
      max_age: 300,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses when the session has no auth_time at all', async () => {
    readSessionTokenMock.mockResolvedValue({
      accessToken: 'access-token',
      accessTokenExpires: null,
      provider: 'oidc',
      authTime: null,
    });
    const res = await POST(...request('POST', 'ota', ['v1', 'campaigns', DEVICE, 'rollback']));
    expect(res.status).toBe(401);
    expect(await problemOf(res)).toMatchObject({ action: 'campaign.rollback' });
  });

  it('lets a destructive action through after a recent authentication', async () => {
    const res = await POST(...request('POST', 'registry', ['v1', 'devices', DEVICE, 'quarantine']));
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('does not ask for step-up on ordinary mutations', async () => {
    readSessionTokenMock.mockResolvedValue({
      accessToken: 'access-token',
      accessTokenExpires: null,
      provider: 'oidc',
      authTime: nowS() - 3600,
    });
    const res = await POST(...request('POST', 'ota', ['v1', 'campaigns', DEVICE, 'pause']));
    expect(res.status).toBe(200);
  });

  it('classifies the path the upstream will route (encoded slash, dot segments)', async () => {
    readSessionTokenMock.mockResolvedValue({
      accessToken: 'access-token',
      accessTokenExpires: null,
      provider: 'oidc',
      authTime: nowS() - 3600,
    });
    const encoded = await POST(
      ...request('POST', 'registry', ['v1', 'devices', `${DEVICE}/quarantine`]),
    );
    expect(encoded.status).toBe(401);
    const dotted = await POST(
      ...request('POST', 'registry', ['v1', 'devices', DEVICE, 'x', '..', 'decommission']),
    );
    expect(dotted.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('still blocks /internal even when reached through dot segments', async () => {
    const res = await GET(...request('GET', 'registry', ['v1', '..', 'internal', 'x'], {}));
    expect(res.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

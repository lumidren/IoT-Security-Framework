// @vitest-environment node
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('server-only', () => ({}));

const authMock = vi.fn();
vi.mock('@/auth', () => ({ auth: () => authMock() }));
vi.mock('@/lib/server/token', () => ({
  readSessionToken: async () => ({
    accessToken: 'access-token',
    accessTokenExpires: null,
    provider: 'oidc',
    authTime: null,
  }),
}));

const { POST } = await import('./route');

const APP = 'https://console.example.com';

function ticketRequest(headers: Record<string, string>) {
  return new NextRequest(`${APP}/api/ws/ticket`, { method: 'POST', headers });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.stubEnv('NEXT_PUBLIC_APP_URL', APP);
  vi.stubEnv('AUTH_URL', APP);
  authMock.mockResolvedValue({ user: { role: 'viewer', tenantId: 't1' } });
  fetchMock = vi.fn(async () =>
    Response.json({ ticket: 'tkt_123', expires_in: 60 }, { status: 201 }),
  );
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('POST /api/ws/ticket origin check', () => {
  it('mints a ticket for a same-origin request', async () => {
    const res = await POST(ticketRequest({ origin: APP }));
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    ['a foreign Origin', { origin: 'https://evil.example' }],
    ['Origin: null', { origin: 'null' }],
    ['neither Origin nor Referer', {}],
  ])('refuses %s with 403', async (_label, headers) => {
    const res = await POST(ticketRequest(headers));
    expect(res.status).toBe(403);
    expect(res.headers.get('content-type')).toContain('application/problem+json');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(authMock).not.toHaveBeenCalled();
  });
});

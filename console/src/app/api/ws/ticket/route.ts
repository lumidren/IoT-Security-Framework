import { type NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { WsTicketSchema } from '@/lib/api/schemas';
import { checkSameOrigin } from '@/lib/security/origin';
import { originCheckEnv, serviceBaseUrl } from '@/lib/server/env';
import { problemResponse } from '@/lib/server/problem';
import { readSessionToken } from '@/lib/server/token';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Mints a one-time WebSocket ticket from the registry (`POST /v1/ws/ticket`). The browser then
 * connects directly to `NEXT_PUBLIC_WS_URL?ticket=...`; the deployment's reverse proxy must expose
 * the registry's `/v1/ws` endpoint on that URL (see README).
 */
export async function POST(req: NextRequest): Promise<NextResponse> {
  // CSRF: a ticket is a bearer credential for the live feed; only console pages may mint one.
  const origin = checkSameOrigin(req.method, req.headers, req.url, originCheckEnv());
  if (!origin.ok) return problemResponse(403, 'Cross-origin request blocked', origin.reason);

  const session = await auth();
  if (!session?.user) return problemResponse(401, 'Authentication required');
  const tokenInfo = await readSessionToken(req);
  if (!tokenInfo?.accessToken) {
    return problemResponse(401, 'Session has no access token', 'Sign in again to continue.');
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${serviceBaseUrl('registry')}/v1/ws/ticket`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${tokenInfo.accessToken}`,
        accept: 'application/json',
      },
      cache: 'no-store',
      signal: req.signal,
    });
  } catch {
    return problemResponse(502, 'Upstream unavailable', 'The registry could not be reached.');
  }

  if (!upstream.ok) {
    return new NextResponse(upstream.body, {
      status: upstream.status,
      headers: {
        'content-type': upstream.headers.get('content-type') ?? 'application/problem+json',
        'cache-control': 'no-store',
      },
    });
  }

  const parsed = WsTicketSchema.safeParse(await upstream.json().catch(() => null));
  if (!parsed.success) {
    return problemResponse(502, 'Unexpected response', 'The registry returned an invalid ticket.');
  }
  return NextResponse.json(
    { ...parsed.data, url: process.env.NEXT_PUBLIC_WS_URL ?? null },
    { headers: { 'cache-control': 'no-store' } },
  );
}

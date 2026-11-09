import { type NextRequest, NextResponse } from 'next/server';
import { auth, stepUpMaxAge } from '@/auth';
import { proxyAllows } from '@/lib/rbac';
import { checkSameOrigin } from '@/lib/security/origin';
import {
  isAuthFresh,
  normaliseUpstreamPath,
  stepUpAction,
  stepUpChallenge,
  stepUpProblemBody,
} from '@/lib/security/step-up';
import { isService, originCheckEnv, serviceBaseUrl } from '@/lib/server/env';
import { problemResponse } from '@/lib/server/problem';
import { readSessionToken } from '@/lib/server/token';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Request headers copied to the upstream call (everything else, cookies included, is dropped). */
const FORWARDED_REQUEST_HEADERS = [
  'accept',
  'accept-language',
  'content-type',
  'idempotency-key',
  'x-ironmesh-tenant',
  'if-match',
  'if-none-match',
  'x-request-id',
  'traceparent',
  'tracestate',
];

/** Response headers passed back to the browser untouched. */
const FORWARDED_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'cache-control',
  'etag',
  'location',
  'idempotency-replayed',
  'x-request-id',
  'retry-after',
  'link',
];

type RouteContext = { params: Promise<{ service: string; path: string[] }> };

async function proxy(req: NextRequest, context: RouteContext): Promise<NextResponse> {
  const { service, path } = await context.params;
  if (!isService(service)) {
    return problemResponse(404, 'Unknown service', `No upstream is configured for "${service}".`);
  }
  const instance = `/api/proxy/${service}/${path.join('/')}`;

  // The upstream path exactly as the service will route it (dot segments resolved, %2F decoded),
  // so neither the /internal block nor the step-up classifier can be sidestepped by encoding.
  const base = new URL(serviceBaseUrl(service));
  const basePath = base.pathname.replace(/\/+$/, '');
  const target = new URL(
    `${base.origin}${basePath}/${path.map((segment) => encodeURIComponent(segment)).join('/')}`,
  );
  target.search = req.nextUrl.search;
  if (basePath && !target.pathname.startsWith(`${basePath}/`)) {
    return problemResponse(404, 'Not found');
  }
  const upstreamPath = normaliseUpstreamPath(target.pathname.slice(basePath.length));
  if (upstreamPath.length === 0 || upstreamPath[0] === 'internal') {
    return problemResponse(404, 'Not found');
  }

  // CSRF: mutations must originate from the console's own pages.
  const origin = checkSameOrigin(req.method, req.headers, req.url, originCheckEnv());
  if (!origin.ok) {
    return problemResponse(403, 'Cross-origin request blocked', origin.reason, { instance });
  }

  const session = await auth();
  if (!session?.user) {
    return problemResponse(401, 'Authentication required');
  }
  if (!proxyAllows(session.user.role, req.method)) {
    return problemResponse(
      403,
      'Forbidden',
      `Role "${session.user.role}" may not perform ${req.method} requests.`,
    );
  }

  const tokenInfo = await readSessionToken(req);
  if (!tokenInfo?.accessToken) {
    return problemResponse(
      401,
      'Session has no access token',
      'Sign in again through the identity provider.',
    );
  }
  if (tokenInfo.accessTokenExpires && tokenInfo.accessTokenExpires <= Date.now()) {
    return problemResponse(401, 'Access token expired', 'Sign in again to continue.');
  }

  // Step-up: destructive actions need a recent authentication (THREAT_MODEL T-51, T-65).
  const action = stepUpAction(service, req.method, upstreamPath);
  if (action) {
    const maxAge = stepUpMaxAge();
    if (!isAuthFresh(tokenInfo.authTime, maxAge)) {
      const response = NextResponse.json(stepUpProblemBody(action, maxAge, instance), {
        status: 401,
        headers: {
          'content-type': 'application/problem+json',
          'cache-control': 'no-store',
          'www-authenticate': stepUpChallenge(maxAge),
        },
      });
      return response;
    }
  }

  const headers = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = req.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set('authorization', `Bearer ${tokenInfo.accessToken}`);
  if (!headers.has('accept')) headers.set('accept', 'application/json');

  const hasBody = !['GET', 'HEAD'].includes(req.method);
  const init: RequestInit & { duplex?: 'half' } = {
    method: req.method,
    headers,
    body: hasBody ? req.body : undefined,
    duplex: hasBody ? 'half' : undefined,
    redirect: 'manual',
    cache: 'no-store',
    signal: req.signal,
  };

  let upstream: Response;
  try {
    upstream = await fetch(target, init);
  } catch (error) {
    return problemResponse(
      502,
      'Upstream unavailable',
      `The ${service} service could not be reached.`,
      { instance },
    );
  }

  const responseHeaders = new Headers({ 'cache-control': 'no-store' });
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) responseHeaders.set(name, value);
  }
  return new NextResponse(upstream.body, { status: upstream.status, headers: responseHeaders });
}

export { proxy as GET, proxy as POST, proxy as PUT, proxy as PATCH, proxy as DELETE };

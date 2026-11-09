import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { buildCsp, cspSourcesFromEnv, generateNonce } from '@/lib/security/csp';

/** `/auth/*` holds the post-redirect interstitial and the step-up pop-up pages. */
const PUBLIC_PATHS = ['/signin', '/forbidden', '/auth'];

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/**
 * Per-request CSP. Members are spelled out so the build-time inlined `NEXT_PUBLIC_*` values are
 * used; `MAP_TILE_ORIGINS` is read at request time.
 */
function contentSecurityPolicy(nonce: string): string {
  return buildCsp({
    nonce,
    isDev: process.env.NODE_ENV !== 'production',
    ...cspSourcesFromEnv({
      MAP_TILE_ORIGINS: process.env.MAP_TILE_ORIGINS,
      NEXT_PUBLIC_MAP_STYLE_URL: process.env.NEXT_PUBLIC_MAP_STYLE_URL,
      NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL,
    }),
  });
}

export default auth((req) => {
  const { pathname, search } = req.nextUrl;
  const signedIn = Boolean(req.auth?.user);

  // Next.js reads the nonce from the request's CSP header and applies it to its own scripts;
  // `x-nonce` is for our server components (next-themes' inline theme script).
  const nonce = generateNonce();
  const csp = contentSecurityPolicy(nonce);
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('content-security-policy', csp);

  const withCsp = (response: NextResponse): NextResponse => {
    response.headers.set('content-security-policy', csp);
    return response;
  };
  const next = () => withCsp(NextResponse.next({ request: { headers: requestHeaders } }));

  if (isPublic(pathname)) {
    if (signedIn && pathname === '/signin') {
      return withCsp(NextResponse.redirect(new URL('/', req.nextUrl)));
    }
    return next();
  }

  if (!signedIn) {
    if (pathname.startsWith('/api/')) {
      return withCsp(
        NextResponse.json(
          { type: 'about:blank', title: 'Authentication required', status: 401 },
          { status: 401, headers: { 'content-type': 'application/problem+json' } },
        ),
      );
    }
    // The session cookie is SameSite=Strict, so a navigation that arrives from another site (a
    // link in mail or chat, the OIDC callback redirect chain) never carries it. Re-issue it as a
    // same-origin navigation through /auth/continue before concluding the user is signed out.
    const fetchSite = req.headers.get('sec-fetch-site');
    const fetchMode = req.headers.get('sec-fetch-mode');
    if (req.method === 'GET' && fetchSite === 'cross-site' && fetchMode === 'navigate') {
      const url = new URL('/auth/continue', req.nextUrl);
      url.searchParams.set('to', `${pathname}${search}`);
      return withCsp(NextResponse.redirect(url));
    }
    const url = new URL('/signin', req.nextUrl);
    url.searchParams.set('callbackUrl', `${pathname}${search}`);
    return withCsp(NextResponse.redirect(url));
  }
  return next();
});

export const config = {
  matcher: [
    '/((?!api/auth|api/health|_next/static|_next/image|favicon.ico|icon.svg|mockServiceWorker.js|maplibre/|robots.txt|manifest.webmanifest|.*\\.(?:png|svg|ico|webp|woff2?)$).*)',
  ],
};

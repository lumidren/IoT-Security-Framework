import { NextResponse } from 'next/server';
import { auth } from '@/auth';

const PUBLIC_PATHS = ['/signin', '/forbidden'];

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

export default auth((req) => {
  const { pathname, search } = req.nextUrl;
  const signedIn = Boolean(req.auth?.user);

  if (isPublic(pathname)) {
    if (signedIn && pathname === '/signin') {
      return NextResponse.redirect(new URL('/', req.nextUrl));
    }
    return NextResponse.next();
  }

  if (!signedIn) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json(
        { type: 'about:blank', title: 'Authentication required', status: 401 },
        { status: 401, headers: { 'content-type': 'application/problem+json' } },
      );
    }
    const url = new URL('/signin', req.nextUrl);
    url.searchParams.set('callbackUrl', `${pathname}${search}`);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
});

export const config = {
  matcher: [
    '/((?!api/auth|api/health|_next/static|_next/image|favicon.ico|icon.svg|mockServiceWorker.js|maplibre/|robots.txt|manifest.webmanifest|.*\\.(?:png|svg|ico|webp|woff2?)$).*)',
  ],
};

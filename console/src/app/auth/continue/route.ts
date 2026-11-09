import { type NextRequest } from 'next/server';
import { safeRedirectPath } from '@/lib/safe-redirect';

export const dynamic = 'force-dynamic';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Interstitial for navigations that arrive from another site. The session cookie is
 * SameSite=Strict, so the browser withholds it on such navigations (and on the OIDC callback
 * redirect chain). A meta refresh issued by this console page is a same-origin navigation, which
 * carries the cookie again. `src/middleware.ts` sends cross-site navigations without a cookie here.
 *
 * Plain HTML without script (works under the nonce CSP and before the demo mock worker starts).
 */
export function GET(req: NextRequest): Response {
  const target = safeRedirectPath(req.nextUrl.searchParams.get('to'));
  // Quote the URL in the refresh value; a `'` in the path is percent-encoded so it cannot end it.
  const refreshUrl = escapeHtml(target.replace(/'/g, '%27'));
  const href = escapeHtml(target);
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<meta http-equiv="refresh" content="0;url='${refreshUrl}'">
<title>Continuing · IronMesh Console</title>
</head>
<body>
<main><p>Continuing to the console… <a href="${href}">Continue</a></p></main>
</body>
</html>
`;
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

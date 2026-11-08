import { NextResponse } from 'next/server';
import type { ProblemDetails } from '@/lib/api/schemas';

/** RFC 9457 response produced by the console itself (auth, proxy and ticket failures). */
export function problemResponse(
  status: number,
  title: string,
  detail?: string,
  extra: Partial<ProblemDetails> = {},
): NextResponse {
  const body: ProblemDetails = {
    type: 'about:blank',
    title,
    status,
    ...(detail ? { detail } : {}),
    ...extra,
  };
  return NextResponse.json(body, {
    status,
    headers: { 'content-type': 'application/problem+json', 'cache-control': 'no-store' },
  });
}

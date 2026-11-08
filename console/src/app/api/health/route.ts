import { NextResponse } from 'next/server';
import { isMockMode } from '@/lib/env';

export const dynamic = 'force-dynamic';

/** Liveness probe used by the Dockerfile HEALTHCHECK and the e2e web server wait. */
export function GET(): NextResponse {
  return NextResponse.json(
    { status: 'ok', mock: isMockMode },
    { headers: { 'cache-control': 'no-store' } },
  );
}

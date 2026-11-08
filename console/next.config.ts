import path from 'node:path';
import type { NextConfig } from 'next';

/**
 * Origins the browser is allowed to reach besides the console itself: map tiles / style and the
 * WebSocket endpoint. Everything else (registry, OTA, anomaly, policy) goes through the server-side
 * proxy under /api/proxy, so it never appears in the CSP.
 */
function originOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

const isDev = process.env.NODE_ENV !== 'production';
const mapOrigin = originOf(process.env.NEXT_PUBLIC_MAP_STYLE_URL);
const wsOrigin = originOf(process.env.NEXT_PUBLIC_WS_URL);
const tileHosts = (process.env.MAP_TILE_ORIGINS ?? 'https://tile.openstreetmap.org')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const connectSrc = ["'self'", ...tileHosts, mapOrigin, wsOrigin, isDev ? 'ws:' : null]
  .filter((v): v is string => Boolean(v))
  .join(' ');
const imgSrc = ["'self'", 'data:', 'blob:', ...tileHosts, mapOrigin]
  .filter((v): v is string => Boolean(v))
  .join(' ');

const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  `img-src ${imgSrc}`,
  "font-src 'self'",
  `connect-src ${connectSrc}`,
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join('; ');

const securityHeaders = [
  { key: 'Content-Security-Policy', value: csp },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  ...(isDev
    ? []
    : [{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' }]),
];

const nextConfig: NextConfig = {
  output: 'standalone',
  // The console is its own npm workspace; keep file tracing rooted here (standalone server.js at
  // .next/standalone/server.js) even when other lockfiles exist higher up.
  outputFileTracingRoot: path.join(__dirname),
  // Lets the mock-mode build (`npm run build:mock`) live next to the production build.
  distDir: process.env.NEXT_DIST_DIR ?? '.next',
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: {
    optimizePackageImports: ['lucide-react', 'recharts', 'radix-ui'],
  },
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};

export default nextConfig;

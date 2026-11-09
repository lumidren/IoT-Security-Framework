import { describe, expect, it } from 'vitest';
import { buildCsp, cspSourcesFromEnv, generateNonce, originOf } from './csp';

const NONCE = 'r4nd0mN0nceValue1234==';

function directives(csp: string): Map<string, string[]> {
  return new Map(
    csp.split(';').map((part) => {
      const [name = '', ...values] = part.trim().split(/\s+/);
      return [name, values] as const;
    }),
  );
}

const sources = {
  tileOrigins: ['https://tile.openstreetmap.org'],
  mapOrigin: null,
  wsOrigin: 'wss://console.example.com',
};

describe('buildCsp', () => {
  it('allows scripts only by nonce + strict-dynamic in production (no unsafe-inline / eval)', () => {
    const csp = buildCsp({ nonce: NONCE, isDev: false, ...sources });
    expect(directives(csp).get('script-src')).toEqual([
      "'self'",
      `'nonce-${NONCE}'`,
      "'strict-dynamic'",
    ]);
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
    expect(csp).not.toContain("'unsafe-eval'");
  });

  it("adds 'unsafe-eval' and the HMR socket only in development", () => {
    const d = directives(buildCsp({ nonce: NONCE, isDev: true, ...sources }));
    expect(d.get('script-src')).toContain("'unsafe-eval'");
    expect(d.get('connect-src')).toContain('ws:');
  });

  it('keeps the hardening directives', () => {
    const d = directives(buildCsp({ nonce: NONCE, isDev: false, ...sources }));
    expect(d.get('frame-ancestors')).toEqual(["'none'"]);
    expect(d.get('base-uri')).toEqual(["'self'"]);
    expect(d.get('form-action')).toEqual(["'self'"]);
    expect(d.get('object-src')).toEqual(["'none'"]);
    expect(d.get('default-src')).toEqual(["'self'"]);
    expect(d.get('worker-src')).toEqual(["'self'", 'blob:']);
    // Styles keep 'unsafe-inline' (Radix style attributes, CodeMirror / Sonner style elements).
    expect(d.get('style-src')).toEqual(["'self'", "'unsafe-inline'"]);
  });

  it('allows map tiles, the map style origin and the WebSocket origin', () => {
    const d = directives(
      buildCsp({
        nonce: NONCE,
        isDev: false,
        tileOrigins: ['https://a.tiles.example', 'https://b.tiles.example'],
        mapOrigin: 'https://styles.example',
        wsOrigin: 'wss://ws.example',
      }),
    );
    expect(d.get('connect-src')).toEqual([
      "'self'",
      'https://a.tiles.example',
      'https://b.tiles.example',
      'https://styles.example',
      'wss://ws.example',
    ]);
    expect(d.get('img-src')).toEqual([
      "'self'",
      'data:',
      'blob:',
      'https://a.tiles.example',
      'https://b.tiles.example',
      'https://styles.example',
    ]);
  });

  it('rejects a missing or malformed nonce', () => {
    expect(() => buildCsp({ nonce: '', isDev: false, ...sources })).toThrow();
    expect(() => buildCsp({ nonce: "abc' 'unsafe-inline", isDev: false, ...sources })).toThrow();
  });
});

describe('generateNonce', () => {
  it('returns 128-bit base64 values that differ per call', () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
    expect(atob(a)).toHaveLength(16);
    expect(() => buildCsp({ nonce: a, isDev: false, ...sources })).not.toThrow();
  });
});

describe('cspSourcesFromEnv / originOf', () => {
  it('derives origins and drops invalid entries', () => {
    expect(
      cspSourcesFromEnv({
        MAP_TILE_ORIGINS: 'https://t1.example/path, not a url ,https://t2.example',
        NEXT_PUBLIC_MAP_STYLE_URL: 'https://styles.example/style.json',
        NEXT_PUBLIC_WS_URL: 'wss://console.example.com/v1/ws',
      }),
    ).toEqual({
      tileOrigins: ['https://t1.example', 'https://t2.example'],
      mapOrigin: 'https://styles.example',
      wsOrigin: 'wss://console.example.com',
    });
  });

  it('defaults to the OpenStreetMap tile server', () => {
    expect(cspSourcesFromEnv({}).tileOrigins).toEqual(['https://tile.openstreetmap.org']);
    expect(originOf('')).toBeNull();
    expect(originOf('javascript:alert(1)')).toBeNull();
  });
});

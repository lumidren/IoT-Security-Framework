import { describe, expect, it } from 'vitest';
import { checkSameOrigin, expectedOrigins, requestInitiatorOrigin } from './origin';

const CONFIGURED = { NEXT_PUBLIC_APP_URL: 'https://console.example.com' };
const REQUEST_URL = 'https://console.example.com/api/proxy/registry/v1/devices/d1/quarantine';

function h(init: Record<string, string>): Headers {
  return new Headers(init);
}

describe('checkSameOrigin', () => {
  it('lets safe methods through without an Origin', () => {
    expect(checkSameOrigin('GET', h({}), REQUEST_URL, CONFIGURED)).toEqual({ ok: true });
    expect(
      checkSameOrigin('HEAD', h({ origin: 'https://evil.example' }), REQUEST_URL, CONFIGURED).ok,
    ).toBe(true);
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('allows a same-origin %s', (method) => {
    expect(
      checkSameOrigin(
        method,
        h({ origin: 'https://console.example.com' }),
        REQUEST_URL,
        CONFIGURED,
      ),
    ).toEqual({ ok: true });
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('blocks a cross-origin %s', (method) => {
    const result = checkSameOrigin(
      method,
      h({ origin: 'https://evil.example' }),
      REQUEST_URL,
      CONFIGURED,
    );
    expect(result.ok).toBe(false);
  });

  it('blocks look-alike origins (scheme, port, subdomain, suffix)', () => {
    for (const origin of [
      'http://console.example.com',
      'https://console.example.com:8443',
      'https://evil.console.example.com',
      'https://console.example.com.evil.example',
    ]) {
      expect(checkSameOrigin('POST', h({ origin }), REQUEST_URL, CONFIGURED).ok).toBe(false);
    }
  });

  it('blocks `Origin: null` and requests with neither Origin nor Referer', () => {
    expect(checkSameOrigin('POST', h({ origin: 'null' }), REQUEST_URL, CONFIGURED).ok).toBe(false);
    expect(checkSameOrigin('DELETE', h({}), REQUEST_URL, CONFIGURED).ok).toBe(false);
  });

  it('falls back to the Referer origin when Origin is absent', () => {
    expect(
      checkSameOrigin(
        'POST',
        h({ referer: 'https://console.example.com/devices/d1' }),
        REQUEST_URL,
        CONFIGURED,
      ).ok,
    ).toBe(true);
    expect(
      checkSameOrigin('POST', h({ referer: 'https://evil.example/page' }), REQUEST_URL, CONFIGURED)
        .ok,
    ).toBe(false);
  });

  it('prefers Origin over Referer', () => {
    expect(
      checkSameOrigin(
        'POST',
        h({ origin: 'https://evil.example', referer: 'https://console.example.com/' }),
        REQUEST_URL,
        CONFIGURED,
      ).ok,
    ).toBe(false);
  });

  it('accepts AUTH_URL as well as NEXT_PUBLIC_APP_URL', () => {
    const env = { AUTH_URL: 'http://127.0.0.1:3100', NEXT_PUBLIC_APP_URL: 'http://localhost:3100' };
    expect(
      checkSameOrigin('POST', h({ origin: 'http://127.0.0.1:3100' }), REQUEST_URL, env).ok,
    ).toBe(true);
    expect(
      checkSameOrigin('POST', h({ origin: 'http://localhost:3100' }), REQUEST_URL, env).ok,
    ).toBe(true);
  });

  it('ignores a spoofed Host when the public URL is configured', () => {
    expect(
      checkSameOrigin(
        'POST',
        h({ origin: 'https://evil.example', host: 'evil.example' }),
        'https://evil.example/api/proxy/x',
        CONFIGURED,
      ).ok,
    ).toBe(false);
  });
});

describe('expectedOrigins without a configured URL', () => {
  it('uses the request Host and URL scheme', () => {
    expect(
      expectedOrigins({}, h({ host: 'localhost:3100' }), 'http://localhost:3100/api/x'),
    ).toEqual(['http://localhost:3100']);
    expect(
      checkSameOrigin(
        'POST',
        h({ host: 'localhost:3100', origin: 'http://localhost:3100' }),
        'http://localhost:3100/api/x',
        {},
      ).ok,
    ).toBe(true);
    expect(
      checkSameOrigin(
        'POST',
        h({ host: 'localhost:3100', origin: 'http://evil.example' }),
        'http://localhost:3100/api/x',
        {},
      ).ok,
    ).toBe(false);
  });

  it('honours X-Forwarded-Host/Proto only with AUTH_TRUST_HOST=true', () => {
    const headers = h({
      host: 'console:3000',
      'x-forwarded-host': 'console.example.com',
      'x-forwarded-proto': 'https',
    });
    expect(expectedOrigins({ AUTH_TRUST_HOST: 'true' }, headers, 'http://console:3000/x')).toEqual([
      'https://console.example.com',
      'https://console:3000',
    ]);
    expect(expectedOrigins({}, headers, 'http://console:3000/x')).toEqual(['http://console:3000']);
  });
});

describe('requestInitiatorOrigin', () => {
  it('normalises case and ignores non-http schemes', () => {
    expect(requestInitiatorOrigin(h({ origin: 'HTTPS://Console.Example.com' }))).toBe(
      'https://console.example.com',
    );
    expect(requestInitiatorOrigin(h({ origin: 'file://' }))).toBeNull();
  });
});

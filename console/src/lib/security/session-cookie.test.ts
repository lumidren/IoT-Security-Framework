import { describe, expect, it } from 'vitest';
import { safeRedirectPath } from '@/lib/safe-redirect';
import { sessionCookieSettings } from './session-cookie';

describe('sessionCookieSettings', () => {
  it('uses Secure and the __Host- prefix when the console is served over https', () => {
    expect(sessionCookieSettings({ AUTH_URL: 'https://console.example.com' })).toEqual({
      name: '__Host-authjs.session-token',
      secure: true,
    });
    expect(
      sessionCookieSettings({ NEXT_PUBLIC_APP_URL: 'https://console.example.com' }).secure,
    ).toBe(true);
  });

  it('drops the prefix for plain-http local URLs (demo build on localhost)', () => {
    expect(sessionCookieSettings({ AUTH_URL: 'http://127.0.0.1:3100' })).toEqual({
      name: 'authjs.session-token',
      secure: false,
    });
  });

  it('lets AUTH_URL win over NEXT_PUBLIC_APP_URL', () => {
    expect(
      sessionCookieSettings({
        AUTH_URL: 'http://localhost:3100',
        NEXT_PUBLIC_APP_URL: 'https://console.example.com',
      }).secure,
    ).toBe(false);
  });

  it('assumes TLS in production without a configured URL, except in the demo build', () => {
    expect(sessionCookieSettings({ NODE_ENV: 'production' }).secure).toBe(true);
    expect(
      sessionCookieSettings({ NODE_ENV: 'production', NEXT_PUBLIC_MOCK_API: 'true' }).secure,
    ).toBe(false);
    expect(sessionCookieSettings({ NODE_ENV: 'development' }).secure).toBe(false);
  });
});

describe('safeRedirectPath', () => {
  it('keeps same-origin relative paths only', () => {
    expect(safeRedirectPath('/devices?state=active')).toBe('/devices?state=active');
    expect(safeRedirectPath(undefined)).toBe('/');
    expect(safeRedirectPath('https://evil.example')).toBe('/');
    expect(safeRedirectPath('//evil.example')).toBe('/');
    expect(safeRedirectPath('/\\evil.example')).toBe('/');
    expect(safeRedirectPath('/ok\nSet-Cookie: x')).toBe('/');
  });
});

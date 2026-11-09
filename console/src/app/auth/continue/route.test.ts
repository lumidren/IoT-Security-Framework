// @vitest-environment node
import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import { GET } from './route';

async function render(to: string) {
  const res = GET(
    new NextRequest(`https://console.example.com/auth/continue?to=${encodeURIComponent(to)}`),
  );
  return { res, html: await res.text() };
}

describe('GET /auth/continue', () => {
  it('re-navigates to the requested console path with a script-free meta refresh', async () => {
    const { res, html } = await render('/devices?state=active&group=a');
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(html).toContain(
      `<meta http-equiv="refresh" content="0;url='/devices?state=active&amp;group=a'">`,
    );
    expect(html).not.toContain('<script');
  });

  it.each(['https://evil.example/', '//evil.example', '/\\evil.example', 'javascript:alert(1)'])(
    'refuses the off-site target %s',
    async (to) => {
      const { html } = await render(to);
      expect(html).toContain(`content="0;url='/'"`);
    },
  );

  it('cannot break out of the attribute or the quoted URL', async () => {
    const { html } = await render(`/x'"><script>alert(1)</script>`);
    expect(html).not.toContain('<script>');
    expect(html).toContain(`url='/x%27&quot;&gt;&lt;script&gt;`);
  });
});

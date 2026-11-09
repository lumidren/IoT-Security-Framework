#!/usr/bin/env node
/**
 * Captures the README screenshots of the console running in demo (mock) mode.
 *
 * Drives an installed Chromium-family browser (Chrome or Edge, set CHROME_PATH) headless over the
 * DevTools protocol using Node's built-in WebSocket, so no extra packages or browser downloads are
 * needed. Expects `npm run start:mock` to be serving on BASE_URL with the same AUTH_SECRET.
 *
 *   AUTH_SECRET=... CHROME_PATH="C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
 *     node scripts/screenshots.mjs
 */
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { encode } from 'next-auth/jwt';

const here = dirname(fileURLToPath(import.meta.url));
const BASE_URL = process.env.BASE_URL ?? 'http://localhost:3100';
const OUT_DIR = process.env.OUT_DIR ?? join(here, '..', '..', 'docs', 'images');
const CHROME_PATH =
  process.env.CHROME_PATH ?? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const WIDTH = 1440;
const HEIGHT = 900;
const SCALE = Number(process.env.SCALE ?? 2);
const PORT = 9333;

function authSecret() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  const envFile = readFileSync(join(here, '..', '.env.local'), 'utf8');
  const match = /^AUTH_SECRET=(.+)$/m.exec(envFile);
  if (!match?.[1]) throw new Error('AUTH_SECRET not set and not found in .env.local');
  return match[1].trim();
}

async function sessionToken(role) {
  const cookieName = 'authjs.session-token';
  const now = Math.floor(Date.now() / 1000);
  return encode({
    secret: authSecret(),
    salt: cookieName,
    maxAge: 3600,
    token: {
      sub: `demo-${role}`,
      name: `Demo ${role}`,
      email: `${role}@demo.ironmesh.local`,
      role,
      tenantId: '7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11',
      tenantName: 'Acme Robotics (demo)',
      provider: 'demo',
      iat: now,
      exp: now + 3600,
    },
  });
}

/** Minimal DevTools protocol client over the global WebSocket. */
class Cdp {
  #ws;
  #id = 0;
  #pending = new Map();

  constructor(ws) {
    this.#ws = ws;
    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(String(event.data));
      if (msg.id && this.#pending.has(msg.id)) {
        const { resolve, reject } = this.#pending.get(msg.id);
        this.#pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message} (${msg.error.code})`));
        else resolve(msg.result);
      }
    });
  }

  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', reject, { once: true });
    });
    return new Cdp(ws);
  }

  send(method, params = {}) {
    const id = ++this.#id;
    this.#ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.#pending.set(id, { resolve, reject }));
  }

  close() {
    this.#ws.close();
  }
}

async function pageTarget() {
  for (let i = 0; i < 50; i += 1) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = targets.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      // browser still starting
    }
    await sleep(200);
  }
  throw new Error('browser did not expose a page target');
}

async function evaluate(cdp, expression) {
  const { result } = await cdp.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  return result.value;
}

async function settle(cdp, ms) {
  await sleep(ms);
  // Wait until no request has been in flight for a moment (map tiles, charts).
  await evaluate(
    cdp,
    `new Promise((resolve) => {
      let last = performance.getEntriesByType('resource').length;
      let quiet = 0;
      const timer = setInterval(() => {
        const now = performance.getEntriesByType('resource').length;
        quiet = now === last ? quiet + 1 : 0;
        last = now;
        if (quiet >= 4) { clearInterval(timer); resolve(true); }
      }, 250);
      setTimeout(() => { clearInterval(timer); resolve(false); }, 15000);
    })`,
  );
}

async function capture(cdp, name, { path, theme = 'dark', before, scrollTo, settleMs = 3500 }) {
  await cdp.send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-color-scheme', value: theme }],
  });
  await cdp.send('Page.navigate', { url: `${BASE_URL}${path}` });
  await settle(cdp, settleMs);
  await evaluate(
    cdp,
    `(() => { const r = document.documentElement; r.classList.remove('light','dark'); r.classList.add('${theme}'); r.style.colorScheme='${theme}'; try { localStorage.setItem('theme','${theme}'); } catch {} return true; })()`,
  );
  if (before) {
    await evaluate(cdp, before);
    await settle(cdp, 1500);
  }
  if (scrollTo) {
    await evaluate(
      cdp,
      `(() => { const el = document.querySelector(${JSON.stringify(scrollTo)}); if (el) el.scrollIntoView({ block: 'center' }); return !!el; })()`,
    );
    await sleep(1500);
  }
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
  const file = join(OUT_DIR, `${name}.png`);
  writeFileSync(file, Buffer.from(data, 'base64'));
  console.log(`saved ${file}`);
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  const profile = mkdtempSync(join(tmpdir(), 'ironmesh-shots-'));
  const browser = spawn(
    CHROME_PATH,
    [
      '--headless=new',
      `--remote-debugging-port=${PORT}`,
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--hide-scrollbars',
      '--force-color-profile=srgb',
      `--window-size=${WIDTH},${HEIGHT}`,
      'about:blank',
    ],
    { stdio: 'ignore' },
  );
  try {
    const cdp = await Cdp.connect(await pageTarget());
    await cdp.send('Page.enable');
    await cdp.send('Network.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: WIDTH,
      height: HEIGHT,
      deviceScaleFactor: SCALE,
      mobile: false,
    });
    const host = new URL(BASE_URL).hostname;
    await cdp.send('Network.setCookie', {
      name: 'authjs.session-token',
      value: await sessionToken('owner'),
      domain: host,
      path: '/',
      httpOnly: true,
    });

    // The demo WebSocket emits a connect/disconnect event every 5 s; wait for a few.
    await capture(cdp, 'console-overview', { path: '/', settleMs: 18000 });
    await capture(cdp, 'console-overview-light', { path: '/', theme: 'light', settleMs: 6000 });
    await capture(cdp, 'console-devices', { path: '/devices' });
    const deviceHref = await evaluate(
      cdp,
      `(() => { const a = [...document.querySelectorAll('a[href^="/devices/dev-"]')][0]; return a ? a.getAttribute('href') : null; })()`,
    );
    if (deviceHref) {
      await capture(cdp, 'console-device-detail', { path: deviceHref });
      await capture(cdp, 'console-device-telemetry', {
        path: deviceHref,
        before: `(() => { const t = [...document.querySelectorAll('[role="tab"]')].find((el) => /telemetry/i.test(el.textContent || '')); if (t) { t.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); t.click(); } return !!t; })()`,
      });
    }
    const campaignHref = await (async () => {
      await cdp.send('Page.navigate', { url: `${BASE_URL}/campaigns` });
      await settle(cdp, 3000);
      return evaluate(
        cdp,
        `(() => {
          const links = [...document.querySelectorAll('a[href^="/campaigns/"]')].filter((el) => !el.getAttribute('href').endsWith('/new'));
          const rowText = (el) => (el.closest('tr, li, article, [data-slot="card"]') || el).textContent || '';
          const running = links.find((el) => /running/i.test(rowText(el)));
          const a = running || links[0];
          return a ? a.getAttribute('href') : null;
        })()`,
      );
    })();
    if (campaignHref) await capture(cdp, 'console-campaign', { path: campaignHref });
    await capture(cdp, 'console-campaign-builder', { path: '/campaigns/new' });
    await capture(cdp, 'console-policy', { path: '/policy' });
    await capture(cdp, 'console-alerts', { path: '/alerts' });
    const alertHref = await evaluate(
      cdp,
      `(() => { const a = [...document.querySelectorAll('a[href^="/alerts/"]')][0]; return a ? a.getAttribute('href') : null; })()`,
    );
    if (alertHref) await capture(cdp, 'console-alert-detail', { path: alertHref });
    await capture(cdp, 'console-audit', { path: '/audit' });
    cdp.close();
  } finally {
    browser.kill();
    await sleep(1500);
    try {
      rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
    } catch (error) {
      // The browser can keep the profile locked briefly on Windows; a leftover temp dir is harmless.
      console.warn(`could not remove ${profile}: ${error.code ?? error}`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

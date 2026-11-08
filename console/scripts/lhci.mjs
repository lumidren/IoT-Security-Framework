#!/usr/bin/env node
/**
 * Runs Lighthouse CI against the overview page of a mock-mode production build.
 *
 * The overview requires a session, so this script mints a valid Auth.js session cookie with the
 * same AUTH_SECRET the server uses and passes it to Lighthouse through `extraHeaders`. It expects
 * `npm run build:mock` to have been executed and starts `npm run start:mock` itself. Requires a
 * Chrome/Chromium binary (set CHROME_PATH when it is not on the default path).
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { encode } from 'next-auth/jwt';

const PORT = 3100;
const BASE = `http://127.0.0.1:${PORT}`;
const secret = process.env.AUTH_SECRET ?? 'lhci-only-secret-not-for-production-0123456789';
const role = process.env.LHCI_ROLE ?? 'operator';
const cookieName = 'authjs.session-token';

async function sessionCookie() {
  const now = Math.floor(Date.now() / 1000);
  const token = await encode({
    secret,
    salt: cookieName,
    maxAge: 60 * 60,
    token: {
      sub: `demo-${role}`,
      name: `Demo ${role}`,
      email: `${role}@demo.ironmesh.local`,
      role,
      tenantId: '7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11',
      tenantName: 'Acme Robotics (demo)',
      provider: 'demo',
      iat: now,
      exp: now + 60 * 60,
    },
  });
  return `${cookieName}=${token}`;
}

async function waitForServer(url, attempts = 60) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await sleep(1000);
  }
  throw new Error(`Server at ${url} did not become ready`);
}

function run(command, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: process.platform === 'win32',
      env,
    });
    child.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`)),
    );
    child.on('error', reject);
  });
}

const env = {
  ...process.env,
  NEXT_PUBLIC_MOCK_API: 'true',
  NEXT_DIST_DIR: '.next-mock',
  AUTH_SECRET: secret,
  AUTH_TRUST_HOST: 'true',
  AUTH_URL: BASE,
};

const server = spawn('npm', ['run', 'start:mock'], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env,
});
try {
  await waitForServer(`${BASE}/api/health`);
  const cookie = await sessionCookie();
  await run(
    'npx',
    ['lhci', 'autorun', `--collect.settings.extraHeaders=${JSON.stringify({ Cookie: cookie })}`],
    env,
  );
} finally {
  server.kill();
}

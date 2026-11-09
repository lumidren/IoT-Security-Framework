import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end suite. Runs against a production build in mock mode (`NEXT_PUBLIC_MOCK_API=true`), so
 * no backend services are needed. The web server builds into `.next-mock` to keep the regular
 * build intact. Browsers are installed in CI (`npx playwright install --with-deps chromium`).
 */
const PORT = 3100;
const baseURL = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    locale: 'en-GB',
    timezoneId: 'UTC',
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], storageState: 'test-results/.auth/operator.json' },
      dependencies: ['setup'],
    },
  ],
  webServer: {
    command: 'npm run build:mock && npm run start:mock',
    url: `${baseURL}/api/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
    env: {
      NEXT_PUBLIC_MOCK_API: 'true',
      NEXT_DIST_DIR: '.next-mock',
      AUTH_SECRET: process.env.AUTH_SECRET ?? 'e2e-only-secret-not-for-production-0123456789',
      AUTH_TRUST_HOST: 'true',
      AUTH_URL: baseURL,
      // The suite signs in once (auth.setup.ts) and may run longer than the default 300 s
      // step-up window; destructive-action specs are not about re-authentication.
      CONSOLE_STEP_UP_MAX_AGE: '3600',
      NEXT_TELEMETRY_DISABLED: '1',
    },
  },
});

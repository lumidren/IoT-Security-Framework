import { expect, test } from '@playwright/test';
import { expectNoSeriousA11yViolations } from './helpers';

test.use({ storageState: { cookies: [], origins: [] } });

test.describe('sign-in', () => {
  test('redirects anonymous visitors to /signin with the callback URL', async ({ page }) => {
    await page.goto('/devices?state=active');
    await expect(page).toHaveURL(/\/signin\?callbackUrl=%2Fdevices%3Fstate%3Dactive/);
    await expect(page.getByRole('heading', { name: 'IronMesh Console' })).toBeVisible();
    await expectNoSeriousA11yViolations(page, '/signin');
  });

  test('refuses unauthenticated API proxy calls with an RFC 9457 problem', async ({ request }) => {
    const response = await request.get('/api/proxy/registry/v1/devices');
    expect(response.status()).toBe(401);
    expect(response.headers()['content-type']).toContain('application/problem+json');
    expect(await response.json()).toMatchObject({ title: 'Authentication required', status: 401 });
  });

  test('demo sign-in lands on the requested page', async ({ page }) => {
    await page.goto('/signin?callbackUrl=%2Falerts');
    await page.getByLabel('Role').selectOption('viewer');
    await page.getByRole('button', { name: 'Sign in to the demo' }).click();
    await expect(page).toHaveURL(/\/alerts$/);
    await expect(page.getByRole('heading', { name: 'Alert center' })).toBeVisible();
  });
});

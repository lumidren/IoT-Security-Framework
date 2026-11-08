import { expect, test } from '@playwright/test';
import { OWNER_STATE, expectNoSeriousA11yViolations } from './helpers';

const PAGES: Array<{ path: string; heading: string }> = [
  { path: '/provisioning', heading: 'Provisioning queue' },
  { path: '/quarantine', heading: 'Quarantine' },
  { path: '/audit', heading: 'Audit log' },
];

for (const { path, heading } of PAGES) {
  test(`${path} renders and passes the axe scan`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
    await expect(page.getByRole('table').first()).toBeVisible();
    await expectNoSeriousA11yViolations(page, path);
  });
}

test.describe('access settings (owner)', () => {
  test.use({ storageState: OWNER_STATE });

  test('creates an API key and shows the secret once', async ({ page }) => {
    await page.goto('/settings/access');
    await expect(
      page.getByRole('heading', { level: 1, name: 'Access and tenant settings' }),
    ).toBeVisible();
    await expect(page.getByRole('table', { name: 'Tenant users and their roles' })).toBeVisible();
    await page.getByRole('button', { name: 'Create key' }).click();
    const dialog = page.getByRole('dialog', { name: 'Create an API key' });
    await dialog.getByLabel('Name').fill('e2e pipeline key');
    await dialog.getByRole('button', { name: 'Create key' }).click();
    await expect(page.getByRole('dialog', { name: 'API key created' })).toBeVisible();
    await expect(page.getByTestId('api-key-secret')).toContainText(/^imk_/);
    await expectNoSeriousA11yViolations(page, 'api key secret dialog');
    await page.getByRole('button', { name: 'Done' }).click();
    await expect(page.getByRole('table', { name: 'API keys' })).toContainText('e2e pipeline key');
    await expectNoSeriousA11yViolations(page, '/settings/access');
  });
});

test('dark theme keeps the overview accessible', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/');
  await expect(
    page.getByRole('region', { name: 'Key fleet indicators' }).getByText('50', { exact: true }),
  ).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/ (dark)');
});

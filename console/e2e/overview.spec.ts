import { expect, test } from '@playwright/test';
import { expectNoSeriousA11yViolations } from './helpers';

test.describe('fleet overview', () => {
  test('renders KPI tiles with data, the map and the live feed', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible();

    const kpis = page.getByRole('region', { name: 'Key fleet indicators' });
    await expect(kpis.getByText('Devices', { exact: true })).toBeVisible();
    // Fixtures ship 50 devices; the tile shows the count once the summary has loaded.
    await expect(kpis.getByText('50', { exact: true })).toBeVisible();
    await expect(kpis.getByText('Open alerts')).toBeVisible();
    await expect(kpis.getByText('Running campaigns')).toBeVisible();

    const map = page.getByTestId('fleet-map');
    await expect(map).toBeVisible();
    const box = await map.boundingBox();
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(400);
    await expect(page.getByRole('list', { name: 'Map legend' })).toContainText('Active');

    await expect(page.getByRole('heading', { name: 'Live activity' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Firmware distribution' })).toBeVisible();
    await expectNoSeriousA11yViolations(page, '/');
  });

  test('command palette jumps to a device', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Open command palette' }).click();
    const input = page.getByPlaceholder('Search pages, devices or actions…');
    await input.fill('gateway');
    const option = page.getByRole('option', { name: /dev-/ }).first();
    await expect(option).toBeVisible();
    await option.click();
    await expect(page).toHaveURL(/\/devices\/dev-[0-9a-f]{16}$/);
  });
});

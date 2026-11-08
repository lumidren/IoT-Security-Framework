import { expect, test } from '@playwright/test';
import { VIEWER_STATE, expectNoSeriousA11yViolations } from './helpers';

test.describe('alerts', () => {
  test('acknowledges an open alert from the list and sees it on the detail page', async ({
    page,
  }) => {
    await page.goto('/alerts?state=open');
    const table = page.getByRole('table', { name: 'Alerts matching the current filters' });
    const firstRow = table.locator('tbody tr').first();
    await expect(firstRow.getByText('Open')).toBeVisible();
    await expectNoSeriousA11yViolations(page, '/alerts');

    const openRowsBefore = await table.locator('tbody tr').count();
    await firstRow.getByRole('button', { name: /^Acknowledge alert/ }).click();
    const dialog = page.getByRole('dialog', { name: 'Acknowledge this alert?' });
    await dialog.getByLabel('Note').fill('Investigating with the field team');
    await dialog.getByRole('button', { name: 'Acknowledge' }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByText('Alert acknowledged')).toBeVisible();
    // The acknowledged alert leaves the "open" filter once the list refetches.
    await expect(table.locator('tbody tr')).toHaveCount(openRowsBefore - 1);

    await page.goto('/alerts?state=acked');
    const acked = page
      .getByRole('table', { name: 'Alerts matching the current filters' })
      .locator('tbody tr')
      .first();
    await acked.getByRole('link').first().click();
    await expect(page).toHaveURL(/\/alerts\/[0-9a-f-]{36}$/);
    await expect(page.locator('h1 + p').getByText('Acknowledged')).toBeVisible();
    await expect(page.getByText('Explanation')).toBeVisible();
    await expect(
      page.getByRole('table', { name: 'Features that contributed to the alert' }),
    ).toBeVisible();
    await expect(page.getByRole('img', { name: /Anomaly score/ })).toBeVisible();
    await expect(page.getByRole('list', { name: 'Device timeline' })).toBeVisible();
    await expectNoSeriousA11yViolations(page, 'alert detail');
  });
});

test.describe('alerts as viewer', () => {
  test.use({ storageState: VIEWER_STATE });

  test('hides mutations for read-only roles', async ({ page }) => {
    await page.goto('/alerts?state=open');
    await expect(
      page.getByRole('table', { name: 'Alerts matching the current filters' }),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: /^Acknowledge alert/ })).toHaveCount(0);
    await page.goto('/quarantine');
    await expect(page.getByRole('heading', { name: 'Quarantine' })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Release/ })).toHaveCount(0);
    await expectNoSeriousA11yViolations(page, '/quarantine');
  });
});

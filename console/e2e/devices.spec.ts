import { expect, test } from '@playwright/test';
import { expectNoSeriousA11yViolations } from './helpers';

test.describe('devices', () => {
  test('filters by state and navigates to the device detail', async ({ page }) => {
    await page.goto('/devices');
    const table = page.getByRole('table', { name: 'Devices matching the current filters' });
    await expect(table.getByRole('row')).not.toHaveCount(1);

    await page.getByRole('combobox', { name: 'State' }).click();
    await page.getByRole('option', { name: 'Quarantined' }).click();
    await expect(page).toHaveURL(/state=quarantined/);
    const rows = table.locator('tbody tr');
    await expect(rows).toHaveCount(4);
    for (const row of await rows.all()) await expect(row.getByText('Quarantined')).toBeVisible();
    await expectNoSeriousA11yViolations(page, '/devices');

    const firstLink = rows.first().getByRole('link', { name: /dev-/ });
    const id = (await firstLink.textContent())?.trim() ?? '';
    await firstLink.click();
    await expect(page).toHaveURL(new RegExp(`/devices/${id}$`));
    await expect(page.getByRole('heading', { level: 1, name: id })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await expect(page.getByText('Certificate', { exact: true })).toBeVisible();
    await expectNoSeriousA11yViolations(page, `/devices/${id}`);
  });

  test('quarantine dialog flow revokes the device', async ({ page }) => {
    await page.goto('/devices?state=active&connected=true');
    const table = page.getByRole('table', { name: 'Devices matching the current filters' });
    const firstLink = table.locator('tbody tr').first().getByRole('link', { name: /dev-/ });
    const id = (await firstLink.textContent())?.trim() ?? '';
    await firstLink.click();
    await expect(page.getByRole('heading', { level: 1, name: id })).toBeVisible();

    await page.getByRole('button', { name: 'Quarantine' }).click();
    const dialog = page.getByRole('dialog', { name: `Quarantine ${id}?` });
    await expect(dialog).toBeVisible();
    // Required reason: submitting empty shows an associated error.
    await dialog.getByRole('button', { name: 'Quarantine device' }).click();
    await expect(dialog.getByRole('alert')).toContainText('at least 3 characters');
    await expectNoSeriousA11yViolations(page, 'quarantine dialog');

    await dialog.getByLabel('Reason').fill('Suspicious firmware hash reported by field team');
    await dialog.getByRole('button', { name: 'Quarantine device' }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByText('Device quarantined')).toBeVisible();
    await expect(page.locator('h1 + p').getByText('Quarantined')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Quarantine' })).toHaveCount(0);
    await expect(page.locator('h1 + p').getByText('Revoked')).toBeVisible();
  });

  test('tables collapse to cards on small screens', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 800 });
    await page.goto('/devices');
    await expect(
      page.getByRole('table', { name: 'Devices matching the current filters' }),
    ).toHaveCount(0);
    await expect(page.getByRole('link', { name: /dev-/ }).first()).toBeVisible();
    await expectNoSeriousA11yViolations(page, '/devices (mobile)');
  });
});

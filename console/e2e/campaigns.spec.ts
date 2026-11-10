import { expect, test } from '@playwright/test';
import { expectNoSeriousA11yViolations } from './helpers';

test.describe('campaign builder', () => {
  test('validates stages and creates a draft campaign', async ({ page }) => {
    await page.goto('/campaigns');
    await expect(page.getByRole('heading', { name: 'OTA campaigns' })).toBeVisible();
    await expectNoSeriousA11yViolations(page, '/campaigns');
    await page.getByRole('link', { name: 'New campaign' }).click();
    await expect(page).toHaveURL(/\/campaigns\/new$/);

    // 1. Firmware
    const next = page.getByRole('button', { name: 'Next' });
    await expect(next).toBeDisabled();
    await page.getByRole('radio', { name: /gateway-rpi\/2\.4\.1/ }).check();
    await expect(next).toBeEnabled();
    await expectNoSeriousA11yViolations(page, 'builder: firmware');
    await next.click();

    // 2. Target
    await expect(next).toBeDisabled();
    await page.getByRole('checkbox', { name: /EU West gateways/ }).check();
    await expect(page.getByText(/active devices?$/)).toBeVisible();
    await expect(next).toBeEnabled();
    await next.click();

    // 3. Stages: a non-increasing percent blocks progress with an inline error.
    const second = page.getByLabel('Stage 2 target percent');
    await second.fill('1');
    await expect(
      page.getByRole('alert').filter({ hasText: 'greater than the previous stage' }),
    ).toBeVisible();
    await expect(second).toHaveAttribute('aria-invalid', 'true');
    await expect(next).toBeDisabled();
    await page.getByLabel('Stage 3 target percent').fill('90');
    await expect(
      page.getByRole('alert').filter({ hasText: 'final stage must reach 100%' }),
    ).toBeVisible();
    await second.fill('25');
    await page.getByLabel('Stage 3 target percent').fill('100');
    // Scoped to the page content: Next's route announcer is also a role=alert element.
    await expect(page.getByRole('main').getByRole('alert')).toHaveCount(0);
    await expectNoSeriousA11yViolations(page, 'builder: stages');
    await next.click();

    // 4. Review and create
    await page.getByLabel('Campaign name').fill('e2e gateway rollout');
    await expect(page.getByText('Four-eyes rule')).toBeVisible();
    await page.getByRole('button', { name: 'Create campaign' }).click();
    await expect(page).toHaveURL(/\/campaigns\/[0-9a-f-]{36}$/);
    await expect(
      page.getByRole('heading', { level: 1, name: 'e2e gateway rollout' }),
    ).toBeVisible();
    await expect(page.locator('h1 + p').getByText('Draft')).toBeVisible();
    await expect(page.getByText('1% of targets')).toBeVisible();
    await expect(page.getByText('25% of targets')).toBeVisible();
    await expectNoSeriousA11yViolations(page, 'campaign detail');

    // Start it and see the stage run.
    await page.getByRole('button', { name: 'Start' }).click();
    await expect(page.locator('h1 + p').getByText('Running')).toBeVisible();
  });
});

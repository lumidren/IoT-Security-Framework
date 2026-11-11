import { expect, test } from '@playwright/test';
import { OWNER_STATE, expectNoSeriousA11yViolations } from './helpers';

test.describe('policy dry run (operator)', () => {
  test('evaluates allow and deny decisions with matched rules and trace', async ({ page }) => {
    await page.goto('/policy');
    await expect(page.getByRole('heading', { name: 'MQTT authorization policy' })).toBeVisible();
    // Operators cannot read the source but can dry-run.
    await expect(page.getByText('Requires the admin role')).toBeVisible();

    await page.getByRole('button', { name: 'Evaluate' }).click();
    const result = page.getByTestId('dry-run-result');
    await expect(result).toContainText('Allow');
    await expect(result).toContainText('allow[device_publish_own_topic]');
    await expect(result).toContainText('owns_topic=true');

    await page.getByRole('combobox', { name: 'QoS' }).click();
    await page.getByRole('option', { name: '2' }).click();
    await page.getByRole('button', { name: 'Evaluate' }).click();
    await expect(result).toContainText('Deny');
    await expect(result).toContainText('reason: qos_too_high');
    await expectNoSeriousA11yViolations(page, '/policy');
  });
});

test.describe('policy editor (owner)', () => {
  test.use({ storageState: OWNER_STATE });

  test('shows compiler diagnostics on 422 and saves a valid version', async ({ page }) => {
    await page.goto('/policy');
    await expect(page.getByText('Rego source')).toBeVisible();
    await expect(page.getByRole('list', { name: 'Policy versions' }).getByText('v7')).toBeVisible();

    const editor = page.getByRole('textbox', { name: 'Rego policy source' });
    await editor.click();
    await page.keyboard.press('Control+End');
    // insertText bypasses the editor's bracket auto-closing, so the rule stays unclosed.
    await page.keyboard.insertText('\nbroken_rule if {\n  input.x == 1\n');
    await expect(page.getByText('Unsaved changes')).toBeVisible();

    await page.getByRole('button', { name: 'Save new version' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Change message').fill('e2e: intentionally broken');
    await dialog.getByRole('button', { name: 'Compile and save' }).click();
    await expect(dialog.getByText('The policy was rejected')).toBeVisible();
    await expect(dialog.getByTestId('policy-diagnostics')).toContainText('unclosed');
    await expectNoSeriousA11yViolations(page, 'policy save diagnostics');

    await dialog.getByRole('button', { name: 'Cancel' }).click();
    // The dialog returns focus to its trigger; put the caret back at the end of the source.
    await editor.click();
    await page.keyboard.press('Control+End');
    await page.keyboard.insertText('}\n');
    await page.getByRole('button', { name: 'Save new version' }).click();
    await page.getByRole('dialog').getByLabel('Change message').fill('e2e: add broken_rule');
    await page.getByRole('dialog').getByRole('button', { name: 'Compile and save' }).click();
    await expect(page.getByText('Policy saved as version 8')).toBeVisible();
    await expect(page.getByRole('list', { name: 'Policy versions' }).getByText('v8')).toBeVisible();
  });
});

import { test as setup } from '@playwright/test';
import { OPERATOR_STATE, OWNER_STATE, VIEWER_STATE, signInDemo } from './helpers';

setup('sign in as operator', async ({ page }) => {
  await signInDemo(page, 'operator');
  await page.context().storageState({ path: OPERATOR_STATE });
});

setup('sign in as owner', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signInDemo(page, 'owner');
  await context.storageState({ path: OWNER_STATE });
  await context.close();
});

setup('sign in as viewer', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signInDemo(page, 'viewer');
  await context.storageState({ path: VIEWER_STATE });
  await context.close();
});

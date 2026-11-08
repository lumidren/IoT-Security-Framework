import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

// @axe-core/playwright resolves its own copy of playwright-core, so the structural Page types differ.
type AxePage = ConstructorParameters<typeof AxeBuilder>[0]['page'];

/** Fails the test when axe reports any serious or critical WCAG 2.x A/AA violation. */
export async function expectNoSeriousA11yViolations(page: Page, context = 'page') {
  const results = await new AxeBuilder({ page: page as unknown as AxePage })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    // Third-party map canvas / tiles are outside our control.
    .exclude('.maplibregl-canvas-container')
    .analyze();
  const blocking = results.violations.filter(
    (v) => v.impact === 'serious' || v.impact === 'critical',
  );
  const summary = blocking
    .map(
      (v) =>
        `${v.id} (${v.impact}): ${v.help}\n  ${v.nodes.map((n) => n.target.join(' ')).join('\n  ')}`,
    )
    .join('\n');
  expect(blocking, `axe violations on ${context}:\n${summary}`).toEqual([]);
}

export const OPERATOR_STATE = 'test-results/.auth/operator.json';
export const OWNER_STATE = 'test-results/.auth/owner.json';
export const VIEWER_STATE = 'test-results/.auth/viewer.json';

export async function signInDemo(
  page: Page,
  role: 'owner' | 'admin' | 'operator' | 'viewer' | 'factory',
) {
  await page.goto('/signin');
  await page.getByLabel('Role').selectOption(role);
  await page.getByRole('button', { name: 'Sign in to the demo' }).click();
  await page.waitForURL((url) => !url.pathname.startsWith('/signin'));
}

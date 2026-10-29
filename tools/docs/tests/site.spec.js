import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const pages = ['', 'getting-started/', 'getting-started/first-event/', 'getting-started/concepts/', 'getting-started/deployment/', 'guides/', 'operations/', 'security/', 'reference/', 'deployment/installers/', 'deployment/relay/', 'operations/console-fleet/', 'privacy/privacy-secret-engine/', 'architecture/overview/'];
for (const theme of ['light', 'dark']) {
  test(`accessible documentation in ${theme} mode`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
    for (const path of pages) {
      await page.goto(path || './');
      if (theme === 'light' && await page.locator('body').getAttribute('data-md-color-scheme') !== 'default') {
        await page.locator('label[title="Switch to light mode"]').click();
      }
      await expect(page.locator('body')).toHaveAttribute('data-md-color-scheme', theme === 'light' ? 'default' : 'slate');
      await page.evaluate(() => document.fonts.ready);
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations, `${theme} ${path}: ${JSON.stringify(result.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })))}`).toEqual([]);
    }
  });
}

test('flow controls work with keyboard and respect reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('./');
  const pause = page.getByRole('button', { name: 'Pause animation' });
  await pause.focus();
  await page.keyboard.press('Enter');
  await expect.poll(() => page.locator('.flow-map').evaluate(svg => svg.animationsPaused())).toBe(true);
  await page.getByRole('button', { name: 'Play animation' }).click();
  expect(await page.locator('.flow-map').evaluate(svg => svg.animationsPaused())).toBe(false);
  const step = page.getByRole('button', { name: '05 Prove' });
  await step.focus();
  await page.keyboard.press('Space');
  await expect(step).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('[data-evidence]')).toHaveText('Verified only when found');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(page.locator('.flow-packets')).toBeHidden();
  await expect.poll(() => page.locator('.flow-map').evaluate(svg => svg.animationsPaused())).toBe(true);
});

test('search is local and routes to actual documentation', async ({ page }) => {
  const remote = [];
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:50331/') && !request.url().startsWith('data:')) remote.push(request.url()); });
  await page.goto('./');
  await page.getByRole('textbox', { name: 'Search' }).fill('canary');
  await expect(page.locator('.md-search-result__item').first()).toBeVisible();
  await page.locator('.md-search-result__link').first().click();
  await expect(page.locator('main h1')).toBeVisible();
  expect(remote).toEqual([]);
});

test('homepage and docs fit a 320px screen and support navigation', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  for (const path of ['', 'getting-started/first-event/', 'getting-started/concepts/']) {
    await page.goto(path || './');
    const widths = await page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: innerWidth }));
    expect(widths.content).toBeLessThanOrEqual(widths.viewport + 1);
  }
  await page.goto('./');
  await page.getByRole('link', { name: 'Get started' }).click();
  await expect(page.locator('h1')).toContainText('Security events you can trust');
});

test('core documentation remains available without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:50331/Bower/');
  await expect(page.getByRole('link', { name: 'Read about every stage' })).toBeVisible();
  await page.getByRole('link', { name: 'Get started' }).click();
  await expect(page.locator('h1')).toContainText('Security events you can trust');
  await context.close();
});

test('screenshots of the homepage and guide', async ({ page }, testInfo) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('./');
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: testInfo.outputPath('home-desktop.png'), fullPage: true });
  await page.goto('getting-started/first-event/');
  await page.screenshot({ path: testInfo.outputPath('guide-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto('./');
  await expect(page.locator('body')).toHaveAttribute('data-md-color-scheme', 'slate');
  await page.locator('label[title="Switch to light mode"]').click();
  await expect(page.locator('body')).toHaveAttribute('data-md-color-scheme', 'default');
  await page.reload();
  await expect(page.locator('body')).toHaveAttribute('data-md-color-scheme', 'default');
  await page.locator('label[title="Switch to dark mode"]').click();
  await expect(page.locator('body')).toHaveAttribute('data-md-color-scheme', 'slate');
  await page.screenshot({ path: testInfo.outputPath('home-mobile-dark.png'), fullPage: true });
});

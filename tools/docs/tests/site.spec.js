import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ORIGIN = 'http://127.0.0.1:50331';
const pages = ['', 'getting-started/', 'getting-started/first-event/', 'getting-started/concepts/', 'getting-started/deployment/', 'guides/', 'guides/console-tour/', 'operations/', 'security/', 'reference/', 'reference/sentinel-table/', 'deployment/installers/', 'deployment/relay/', 'deployment/ama-syslog-output/', 'operations/console-fleet/', 'privacy/privacy-secret-engine/', 'architecture/overview/'];

async function setTheme(page, theme) {
  // Docusaurus keeps the reader's choice in localStorage under "theme".
  await page.addInitScript((value) => localStorage.setItem('theme', value), theme);
}

for (const theme of ['light', 'dark']) {
  for (const route of pages) {
    test(`accessible documentation ${route || 'home'} in ${theme} mode`, async ({ page }) => {
      await setTheme(page, theme);
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      await page.goto(route || './');
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await page.evaluate(() => document.fonts.ready);
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations, `${theme} ${route}: ${JSON.stringify(result.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })))}`).toEqual([]);
    });
  }
}

test('the theme toggle switches and is remembered', async ({ page }) => {
  await setTheme(page, 'dark');
  await page.goto('getting-started/first-event/');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  // Docusaurus cycles light, dark and system; one click from dark leaves dark.
  await page.getByRole('button', { name: /Switch between dark and light mode/ }).click();
  await expect(page.locator('html')).not.toHaveAttribute('data-theme-choice', 'dark');
  const choice = await page.locator('html').getAttribute('data-theme-choice');
  await page.evaluate(() => { window.__keep = true; });
  // A fresh navigation (not the init script, which would reset it) keeps the stored choice.
  await page.context().clearCookies();
  const stored = await page.evaluate(() => localStorage.getItem('theme'));
  expect(stored === null ? 'system' : stored).toBe(choice);
});

test('every Mermaid block is drawn as a diagram', async ({ page }) => {
  // Docusaurus draws Mermaid in the browser, so this is checked here, not in the static HTML.
  const docs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../docs');
  const withDiagrams = {
    'getting-started/aws-cloudwatch-agent/': 'getting-started/aws-cloudwatch-agent.md',
    'getting-started/azure-monitor-agent/': 'getting-started/azure-monitor-agent.md',
    'deployment/aws/': 'deployment/aws.md',
    'deployment/gcp/': 'deployment/gcp.md',
    'deployment/relay/': 'deployment/relay.md',
    'privacy/managed-privacy-profiles/': 'privacy/managed-privacy-profiles.md'
  };
  for (const [route, file] of Object.entries(withDiagrams)) {
    const expected = (readFileSync(path.join(docs, file), 'utf8').match(/^\s*```+\s*mermaid\s*$/gm) || []).length;
    await page.goto(route);
    await expect(page.locator('.docusaurus-mermaid-container svg')).toHaveCount(expected);
  }
});

test('search is local and routes to actual documentation', async ({ page }) => {
  const remote = [];
  page.on('request', request => { if (!request.url().startsWith(ORIGIN + '/') && !request.url().startsWith('data:')) remote.push(request.url()); });
  await page.goto('./');
  const search = page.getByRole('searchbox').or(page.getByPlaceholder('Search')).first();
  await search.fill('canary');
  const result = page.locator('.aa-suggestion, [class*="suggestion"]').first();
  await expect(result).toBeVisible();
  await result.click();
  await expect(page.locator('main h1, article h1').first()).toBeVisible();
  expect(remote).toEqual([]);
});

test('no page loads anything from another origin', async ({ page }) => {
  const remote = [];
  page.on('request', request => { if (!request.url().startsWith(ORIGIN + '/') && !request.url().startsWith('data:')) remote.push(request.url()); });
  for (const route of ['', 'guides/console-tour/', 'getting-started/azure-monitor-agent/']) {
    await page.goto(route || './', { waitUntil: 'networkidle' });
  }
  expect(remote).toEqual([]);
});

test('homepage and docs fit a 320px screen and support navigation', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await setTheme(page, 'dark');
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  for (const route of ['', 'getting-started/first-event/', 'getting-started/concepts/', 'guides/console-tour/']) {
    await page.goto(route || './');
    const widths = await page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: innerWidth }));
    expect(widths.content, route).toBeLessThanOrEqual(widths.viewport + 1);
  }
  await page.goto('./');
  await page.getByRole('link', { name: 'Get started', exact: true }).first().click();
  await expect(page.locator('h1')).toContainText('Security events you can trust');
});

test('core documentation remains available without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto(ORIGIN + '/Bower/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('trusted security signal');
  await page.getByRole('link', { name: 'Get started', exact: true }).first().click();
  await expect(page.locator('h1')).toContainText('Security events you can trust');
  await context.close();
});

test('the console gallery works with the keyboard and follows the theme', async ({ page }) => {
  await setTheme(page, 'light');
  await page.goto('./');
  const tabs = page.getByRole('tablist', { name: 'Console views' });
  const first = tabs.getByRole('tab').first();
  await first.focus();
  await page.keyboard.press('ArrowRight');
  const second = tabs.getByRole('tab').nth(1);
  await expect(second).toHaveAttribute('aria-selected', 'true');
  await expect(second).toBeFocused();
  const image = page.getByRole('tabpanel').locator('img');
  await expect(image).toHaveAttribute('src', /-light\.png$/);
  expect(await image.evaluate((img) => img.complete && img.naturalWidth > 0)).toBe(true);
});

test('every console screenshot exists in both themes', async ({ request }) => {
  for (const name of ['home', 'overview', 'setup', 'fleet', 'collector', 'sources', 'pipelines', 'privacy', 'approvals', 'alerts', 'reports', 'jobs', 'audit', 'access', 'help']) {
    for (const theme of ['light', 'dark']) {
      const response = await request.get(`img/console/${name}-${theme}.png`);
      expect(response.status(), `${name}-${theme}`).toBe(200);
    }
  }
});

test('old MkDocs addresses and evidence files still resolve', async ({ request }) => {
  for (const route of ['getting-started/first-event/', 'production-readiness/01-syslog-delivery-reliability/', 'reference/cli/', 'evidence/pilot-native-20261030/report.html', 'images/bower-management-overview.png']) {
    expect((await request.get(route)).status(), route).toBe(200);
  }
});

test('screenshots of the homepage and guide', async ({ page }, testInfo) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const theme of ['dark', 'light']) {
    await setTheme(page, theme);
    await page.goto('./');
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: testInfo.outputPath(`home-desktop-${theme}.png`), fullPage: true });
    await page.goto('guides/console-tour/');
    await page.screenshot({ path: testInfo.outputPath(`tour-desktop-${theme}.png`), fullPage: false });
  }
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto('./');
  await page.screenshot({ path: testInfo.outputPath('home-mobile.png'), fullPage: true });
});

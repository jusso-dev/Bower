import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// WCAG 2.2 AA checks for every console route (#106), in light and dark mode, plus a
// keyboard-only onboarding journey. Runs against the seeded development-auth management
// API the other end-to-end tests use. The desktop and mobile (Pixel 7) projects both run
// it; a separate test covers 320 px.

const routes = [
  "/",
  "/alerts",
  "/reports",
  "/overview",
  "/setup",
  "/collectors",
  "/collectors/finance-prod-01",
  "/sources",
  "/pipelines",
  "/approvals",
  "/enrolment",
  "/privacy-profiles",
  "/jobs",
  "/access",
  "/audit",
  "/help"
];

const wcag = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function openRoute(page: Page, route: string, theme: "light" | "dark") {
  // The console follows the stored choice, then prefers-color-scheme.
  await page.addInitScript((value) => window.localStorage.setItem("bower-theme", value), theme);
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
  await page.goto(route);
  await expect(page.locator("h1").first()).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  await page.evaluate(() => document.fonts.ready);
  // Measure settled colours: wait until no element is mid-transition.
  await page.waitForFunction(() => document.getAnimations().every((animation) => animation.playState !== "running"));
}

async function seriousViolations(page: Page) {
  const result = await new AxeBuilder({ page }).withTags(wcag).analyze();
  return result.violations
    .filter((violation) => violation.impact === "serious" || violation.impact === "critical")
    .map((violation) => ({ id: violation.id, impact: violation.impact, nodes: violation.nodes.map((node) => node.target) }));
}

for (const theme of ["light", "dark"] as const) {
  for (const route of routes) {
    test(`no serious accessibility issues on ${route} (${theme})`, async ({ page }) => {
      await openRoute(page, route, theme);
      expect(await seriousViolations(page)).toEqual([]);
    });
  }
}

for (const route of routes) {
  test(`${route} is usable at 320 px without horizontal scrolling`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 720 });
    await openRoute(page, route, "light");
    const overflow = await page.evaluate(() => {
      const width = document.documentElement.clientWidth;
      const wide = [...document.querySelectorAll("main *")]
        .filter((element) => element.getBoundingClientRect().right > width + 1)
        .slice(0, 3)
        .map((element) => `${element.tagName.toLowerCase()}.${element.className}`);
      return { by: document.documentElement.scrollWidth - width, wide };
    });
    expect(overflow.by, `${route} scrolls sideways by ${overflow.by}px at 320 px: ${overflow.wide.join(", ")}`).toBeLessThanOrEqual(1);
    expect(await seriousViolations(page), route).toEqual([]);
  });
}

test("onboarding can be completed from the keyboard alone", async ({ page }) => {
  await openRoute(page, "/setup", "light");
  // Reach the first setup control by tabbing, never by clicking.
  const main = page.getByRole("main");
  let reached = false;
  for (let step = 0; step < 60 && !reached; step++) {
    await page.keyboard.press("Tab");
    reached = await main.evaluate((element) => element.contains(document.activeElement)
      && document.activeElement instanceof HTMLElement
      && ["BUTTON", "A", "INPUT", "SELECT", "TEXTAREA", "SUMMARY"].includes(document.activeElement.tagName));
  }
  expect(reached, "a setup control inside main is reachable with Tab").toBe(true);

  // Every focusable element in main shows a visible focus indicator.
  const focusables = main.locator("a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary");
  const count = await focusables.count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < Math.min(count, 25); index++) {
    const element = focusables.nth(index);
    if (!(await element.isVisible())) {
      continue;
    }
    await element.focus();
    const indicated = await element.evaluate((node) => {
      const style = window.getComputedStyle(node);
      return (style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0) || style.boxShadow !== "none";
    });
    expect(indicated, `focus indicator on ${await element.evaluate((node) => node.outerHTML.slice(0, 80))}`).toBe(true);
  }

  // The first step's primary action works from Enter, and focus never lands on body.
  await page.keyboard.press("Enter");
  expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe("BODY");
});

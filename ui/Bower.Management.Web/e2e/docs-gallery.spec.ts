import { expect, test, type Page } from "@playwright/test";
import path from "node:path";

// Light and dark captures of every console page for the documentation site's gallery
// (website/static/img/console). Run against a development-auth console seeded with
// `npm run seed:preview`, which holds only synthetic, clearly labelled preview data:
//   BOWER_UI_BASE_URL=http://127.0.0.1:4320 npx playwright test e2e/docs-gallery.spec.ts
const directory = path.resolve(process.cwd(), "../../website/static/img/console");

const views: { name: string; route: string; ready: (page: Page) => Promise<void> }[] = [
  { name: "home", route: "/", ready: (page) => expect(page.getByRole("heading", { name: "What needs my attention?" })).toBeVisible() },
  { name: "overview", route: "/overview", ready: (page) => expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible() },
  { name: "setup", route: "/setup", ready: (page) => expect(page.getByRole("navigation", { name: "Setup steps" })).toBeVisible() },
  { name: "fleet", route: "/collectors", ready: (page) => expect(page.getByText("claims-api-03").first()).toBeVisible() },
  { name: "collector", route: "/collectors/claims-prod-03", ready: (page) => expect(page.getByText("claims-api-03").first()).toBeVisible() },
  { name: "sources", route: "/sources", ready: (page) => expect(page.getByRole("radio", { name: /^Syslog/ })).toBeVisible() },
  { name: "pipelines", route: "/pipelines", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "privacy", route: "/privacy-profiles", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "approvals", route: "/approvals", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "alerts", route: "/alerts", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "reports", route: "/reports", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "jobs", route: "/jobs", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "audit", route: "/audit", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "access", route: "/access", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() },
  { name: "help", route: "/help", ready: (page) => expect(page.locator("main h1, main h2").first()).toBeVisible() }
];

for (const theme of ["light", "dark"] as const) {
  for (const view of views) {
    test(`docs gallery ${view.name} ${theme}`, async ({ page }, testInfo) => {
      test.skip(testInfo.project.name !== "readme-chromium");
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.addInitScript((value) => localStorage.setItem("bower-theme", value), theme);
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.goto(view.route);
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      await view.ready(page);
      await page.waitForLoadState("networkidle");
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({
        path: path.join(directory, `${view.name}-${theme}.png`),
        animations: "disabled"
      });
    });
  }
}

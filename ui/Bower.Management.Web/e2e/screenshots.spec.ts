import { expect, test } from "@playwright/test";
import path from "node:path";

const screenshotDirectory = path.resolve(process.cwd(), "../../docs/images");

test("capture polished desktop overview", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-overview.png"),
    fullPage: true
  });
});

test("capture polished dark approvals view", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/approvals");
  await expect(page.getByRole("heading", { name: "hr-app-02" })).toBeVisible();
  await page.getByRole("button", { name: "Dark mode" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-approvals-dark.png"),
    fullPage: true
  });
});

test("capture polished mobile fleet view", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chromium");
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-mobile.png"),
    fullPage: false
  });
});

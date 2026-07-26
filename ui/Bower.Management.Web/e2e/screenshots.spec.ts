import { expect, test } from "@playwright/test";
import path from "node:path";

const screenshotDirectory = path.resolve(process.cwd(), "../../docs/images");

test("capture polished desktop overview", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  await expect(page.getByText("claims-api-03")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-overview.png"),
    fullPage: true
  });
});

test("capture collector inventory", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/collectors");
  await expect(page.getByRole("heading", { name: "Collectors" })).toBeVisible();
  await expect(page.getByText("finance-app-01")).toBeVisible();
  await expect(page.getByText("records-app-04")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-collectors.png"),
    fullPage: true,
    animations: "disabled"
  });
});

test("capture polished dark approvals view", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/approvals");
  await expect(page.getByRole("heading", { name: "hr-app-02" })).toBeVisible();
  await expect(page.getByText("hr-legacy-02")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.getByRole("button", { name: "Dark mode" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByRole("heading", { name: "hr-app-02" })).toBeVisible();
  await expect(page.getByText("records-prod-04").first()).toBeVisible();
  await expect(page.getByLabel("Loading")).toHaveCount(0);
  await page.waitForTimeout(250);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-approvals-dark.png"),
    fullPage: true,
    animations: "disabled"
  });
});

test("capture Entra access and RBAC model", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/access");
  await expect(page.getByRole("heading", { name: "Access control" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Current session" })).toBeVisible();
  await expect(page.getByText("Bower.Administrator").first()).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-access.png"),
    fullPage: true,
    animations: "disabled"
  });
});

test("capture management audit history", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Management audit" })).toBeVisible();
  await expect(page.getByText("records-prod-04").first()).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-audit.png"),
    fullPage: true,
    animations: "disabled"
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

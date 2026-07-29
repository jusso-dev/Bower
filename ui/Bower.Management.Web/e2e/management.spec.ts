import { expect, test, type Page } from "@playwright/test";

test("fleet overview reports real management state", async ({ page }, testInfo) => {
  const consoleErrors = collectConsoleErrors(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  if (testInfo.project.name === "readme-chromium") {
    await expect(page.getByText("Tenant controlled")).toBeVisible();
  }
  await expect(page.getByText("claims-api-03")).toBeVisible();
  await expect(page.getByText("hr-app-02")).toBeVisible();
  await expect(page.getByText("Development authentication active")).toBeVisible();
  await expectNoHorizontalOverflow(page);
  expect(consoleErrors).toEqual([]);
});

test("collector inventory exposes machine and delivery state", async ({ page }) => {
  await page.goto("/collectors");

  await expect(page.getByRole("heading", { name: "Collectors" })).toBeVisible();
  await expect(page.getByText("finance-app-01")).toBeVisible();
  await expect(page.getByText("claims-api-03")).toBeVisible();
  await expect(page.getByText("records-app-04")).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("approval view requires a reason and identifies the pending machine", async ({
  page
}) => {
  await page.goto("/approvals");

  await expect(
    page.getByRole("heading", { name: "Enrollment approvals" })
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "hr-app-02" })).toBeVisible();
  await expect(page.getByLabel("Decision reason")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeEnabled();
  await expectNoHorizontalOverflow(page);
});

test("custom log parser infers mappings and redacts live preview", async ({ page }) => {
  await page.goto("/pipelines");

  await page.getByLabel("Sample records").fill(
    JSON.stringify({
      timestamp: "2026-07-29T10:00:00Z",
      severity: "warning",
      user: "alex@example.test",
      source_ip: "192.0.2.10",
      action: "login"
    })
  );
  await page.getByRole("button", { name: "Infer parser and schema" }).click();

  await expect(page.getByText("Json · 100%")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Live transformation preview" }))
    .toBeVisible();
  await expect(page.getByText("[redacted]", { exact: true })).toBeVisible();
  await expect(page.getByText("[redacted:ip]", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("mobile navigation remains usable without horizontal overflow", async ({
  page
}, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chromium");
  await page.goto("/");

  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
  await page.getByRole("link", { name: "Collectors" }).click();
  await expect(page.getByRole("heading", { name: "Collectors" })).toBeVisible();
  await expect(page.getByText("finance-app-01")).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      errors.push(message.text());
    }
  });
  return errors;
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth
      )
    )
    .toBe(true);
}

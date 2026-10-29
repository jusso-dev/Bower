import { expect, test } from "@playwright/test";
import path from "node:path";

const screenshotDirectory = path.resolve(process.cwd(), "../../docs/images");

test("capture plain-English home", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "What needs my attention?" })).toBeVisible();
  await expect(page.getByText("Tax file numbers removed")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  // The three answers and the groups only: the proof line depends on canary runs left by
  // other tests, so it is not part of the image.
  await page.getByRole("region", { name: "What was protected this week?" }).screenshot({
    path: path.join(screenshotDirectory, "bower-management-home-protected.png"),
    animations: "disabled"
  });
  await page.getByRole("region", { name: "Collector groups" }).screenshot({
    path: path.join(screenshotDirectory, "bower-management-home-groups.png"),
    animations: "disabled"
  });
});

test("capture polished desktop overview", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/overview");
  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  await expect(page.getByText("claims-api-03")).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-overview.png"),
    fullPage: true
  });
});

test("capture onboarding wizard", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/setup");
  const steps = page.getByRole("navigation", { name: "Setup steps" });
  await steps.getByRole("button", { name: /^Step 4: Approve the first collector/ }).click();
  // Only the collector step is captured: it depends on seeded collectors alone, so the image
  // does not change with destination, probe or canary state left by other runs.
  const step = page.getByRole("region", { name: "Approve the first collector" });
  await expect(step.getByText(/2 collectors approved/)).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await step.screenshot({
    path: path.join(screenshotDirectory, "bower-management-setup.png"),
    animations: "disabled"
  });
});

test("capture guided source setup", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/sources");
  await page.getByRole("radio", { name: /^Syslog/ }).check();
  await page.getByRole("button", { name: "Continue" }).click();
  const settings = page.getByRole("region", { name: "Fill in the settings" });
  await settings.getByLabel("Collector", { exact: true }).selectOption("finance-prod-01");
  await settings.getByLabel("Allowed senders").fill("10.20.0.0/24");
  await settings.getByLabel("Server certificate file").fill("/etc/bower/syslog/server.pem");
  await settings.getByLabel("Server private key file").fill("/etc/bower/syslog/server-key.pem");
  await settings.getByLabel("Collector name senders use").fill("collector.example.org");
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await settings.screenshot({
    path: path.join(screenshotDirectory, "bower-management-sources.png"),
    animations: "disabled"
  });
  await settings.getByRole("button", { name: "Check settings" }).click();
  const review = page.getByRole("region", { name: "Review and preview" });
  await expect(review.getByLabel("Example event after redaction")).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await review.screenshot({
    path: path.join(screenshotDirectory, "bower-management-source-review.png"),
    animations: "disabled"
  });

  // The seeded, approved syslog request after the collector reports the source.
  const now = new Date().toISOString();
  const heartbeat = await page.request.post("/api/collectors/finance-prod-01/heartbeat", {
    data: {
      version: "0.1.0",
      configurationHash: "sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
      policyHash: "sha256:4f2a9c1e7b3d58a6c0e2f91b4d7a8c3e5f6b1a2d9c0e7f84b3a5d6c1e2f9a7b8",
      queueDepth: 3,
      deliveryStatus: "healthy",
      ledger: { sequence: 48211, hash: "preview-ledger-48211" },
      sources: [
        { id: "local-http", type: "local-http", status: "healthy", lagSeconds: null, lastEventAt: now },
        { id: "ssh-gateway/production", type: "application", status: "healthy", lagSeconds: 0, lastEventAt: now }
      ],
      outputs: [{ id: "azure-logs-ingestion", type: "azure-logs-ingestion", status: "healthy", lastAcknowledgedAt: now, lastErrorCode: null }]
    }
  });
  expect(heartbeat.ok()).toBeTruthy();
  const requests = (await (await page.request.get("/api/sources/requests")).json()) as {
    id: string;
    type: string;
    status: string;
    collectorId: string;
    check: { label: string };
  }[];
  const approved = requests.find(
    (item) => item.type === "syslog" && item.status === "approved" && item.collectorId === "finance-prod-01"
      && item.check.label === "Receiving events"
  );
  expect(approved, "Seed data must include an approved syslog request matching the reported source.").toBeDefined();
  await page.goto(`/sources?request=${approved!.id}`);
  await page.getByRole("navigation", { name: "Source request steps" })
    .getByRole("button", { name: /^Step 3: Check it works/ }).click();
  const check = page.getByRole("region", { name: "Check it works" });
  await expect(check.getByText(/The collector reports events from/)).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await check.screenshot({
    path: path.join(screenshotDirectory, "bower-management-source-check.png"),
    animations: "disabled"
  });
});

test("capture guided privacy editing", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  const content = `apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: privacy-preview-${Date.now()}\n  version: 1.0.0\n  description: Protect usernames in authentication events.\n`;
  const baseline = await page.request.post("/api/privacy-profiles", { data: { content, changeSummary: "Synthetic screenshot example" } });
  expect(baseline.ok()).toBeTruthy();
  await page.goto(`/privacy-profiles?version=${(await baseline.json()).id}`);
  await page.getByRole("button", { name: "Edit with forms" }).click();
  await page.getByLabel("Profile name", { exact: true }).fill("sign-in-privacy");
  await page.getByLabel("New version", { exact: true }).fill("1.0.1");
  await page.getByRole("button", { name: "Add a field" }).click();
  await page.getByLabel("Field path", { exact: true }).fill("actor.username");
  await page.getByLabel("How to protect it").selectOption("hmac");
  await page.getByRole("button", { name: "Review changes" }).click();
  await expect(page.getByLabel("Protected privacy example")).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.getByRole("region", { name: "Choose what to protect" }).screenshot({
    path: path.join(screenshotDirectory, "bower-management-privacy-editor.png"), animations: "disabled"
  });
});

test("capture simplified viewer reports", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.setExtraHTTPHeaders({ "X-Bower-Development-Roles": "Bower.Viewer" });
  await page.goto("/reports");
  await expect(page.getByRole("heading", { name: "Reports", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Show technical pages" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(screenshotDirectory, "bower-management-viewer-reports.png"), fullPage: true, animations: "disabled" });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.getByRole("button", { name: "Dark mode" }).click();
  await page.setViewportSize({ width: 320, height: 780 });
  await page.screenshot({ path: path.join(screenshotDirectory, "bower-management-viewer-mobile.png"), fullPage: true, animations: "disabled" });
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

test("capture background jobs view", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/jobs");
  await expect(page.getByRole("heading", { name: "Background jobs" })).toBeVisible();
  await expect(page.getByText("collector-staleness")).toBeVisible();
  await expect(page.getByText("claims-api-03").first()).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-jobs.png"),
    fullPage: true,
    animations: "disabled"
  });
});

test("capture custom log parser workbench", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/pipelines");
  await page.getByLabel("Sample records").fill(
    [
      '{"timestamp":"2026-10-07T09:58:12Z","severity":"warning","user":"alex@example.test","source_ip":"192.0.2.10","action":"login","result":"failure"}',
      '{"timestamp":"2026-10-07T09:58:40Z","severity":"info","user":"sam@example.test","source_ip":"198.51.100.7","action":"login","result":"success"}'
    ].join("\n")
  );
  await page.getByRole("button", { name: "Infer parser and schema" }).click();
  await expect(page.getByRole("heading", { name: "Live transformation preview" })).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-pipelines.png"),
    fullPage: true,
    animations: "disabled"
  });
});

test("capture polished mobile fleet view", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chromium");
  await page.goto("/overview");
  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: path.join(screenshotDirectory, "bower-management-mobile.png"),
    fullPage: false
  });
});

test("capture fleet detail and narrow dark fleet", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "readme-chromium");
  await page.goto("/collectors/claims-prod-03");
  await expect(page.getByRole("heading", { name: "Machine details" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(screenshotDirectory, "bower-management-collector-detail.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 320, height: 720 });
  await page.evaluate(() => localStorage.setItem("bower-theme", "dark"));
  await page.goto("/collectors");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByRole("link", { name: "View details for claims-api-03" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(screenshotDirectory, "bower-management-fleet-mobile-dark.png"), fullPage: true, animations: "disabled" });
});

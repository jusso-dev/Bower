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

test("background jobs show management and collector job health", async ({ page }) => {
  const consoleErrors = collectConsoleErrors(page);
  await page.goto("/jobs");

  await expect(page.getByRole("heading", { name: "Background jobs" })).toBeVisible();
  await expect(page.getByText("collector-staleness")).toBeVisible();
  await expect(page.getByText("queue-retention").first()).toBeVisible();
  const stalenessRow = page.getByRole("row", { name: /collector-staleness/ });
  await expect(stalenessRow.getByRole("button", { name: "Run now" })).toBeEnabled();
  await stalenessRow.getByRole("button", { name: "Run now" }).click();
  await expect(page.getByText(/Queued collector-staleness/)).toBeVisible();
  await expectNoHorizontalOverflow(page);
  expect(consoleErrors).toEqual([]);
});

test.describe("setup wizard", () => {
  // These journeys share one management database: run them in order, and change setup state
  // from one project only so desktop and mobile runs never race each other.
  test.describe.configure({ mode: "serial" });

  test("an administrator saves progress server side and reaches a labelled proof", async ({
    page
  }, testInfo) => {
    test.skip(testInfo.project.name !== "readme-chromium", "Setup state is changed by one project only.");
    await page.goto("/setup");

    await expect(page.getByRole("heading", { name: "Set up Bower" })).toBeVisible();
    const steps = page.getByRole("navigation", { name: "Setup steps" });
    await expect(steps.getByRole("listitem")).toHaveCount(7);
    // Development sign-in is never reported as production-ready, so step 2 needs attention.
    await expect(
      steps.getByRole("button", { name: "Step 2: Connect Entra apps, Needs attention" })
    ).toBeVisible();

    // The seeded approvals complete the collector step; setup itself approves nothing.
    await steps.getByRole("button", { name: "Step 4: Approve the first collector, Done" }).click();
    await expect(page.getByRole("heading", { name: "Approve the first collector" })).toBeFocused();
    await expect(page.getByText(/2 collectors approved: claims-api-03, finance-app-01/)).toBeVisible();
    await expect(page.getByText(/1 collector waiting for approval: hr-app-02/)).toBeVisible();

    await steps.getByRole("button", { name: /^Step 3: Choose where events go/ }).click();
    await page.getByLabel("Workspace ID").fill("not-a-workspace");
    await page.getByRole("button", { name: "Save destination" }).click();
    await expect(page.getByRole("alert")).toContainText("Enter the workspace ID as a GUID");
    await page.getByLabel("Workspace ID").fill("6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b");
    await page.getByRole("button", { name: "Save destination" }).click();
    await expect(steps.getByRole("button", { name: "Step 3: Choose where events go, Done" }))
      .toBeVisible();

    await page.getByRole("button", { name: "Next step" }).click();
    await page.getByRole("button", { name: "Next step" }).click();
    await expect(page.getByRole("heading", { name: "Choose what the test proves" })).toBeFocused();
    await page.getByLabel(/Generic test event/).check();
    await page.getByRole("button", { name: "Save choice" }).click();
    await expect(steps.getByRole("button", { name: "Step 5: Choose what the test proves, Done" }))
      .toBeVisible();

    await steps.getByRole("button", { name: /^Step 6: Send a test event/ }).click();
    if (process.env.BOWER_E2E_CANARY === "1") {
      // The API sends to the loopback stub collector with no verifier identity: the run is
      // accepted but must be labelled simulated, never verified.
      await expect(page.getByText(/No read-only verifier identity/)).toBeVisible();
      await page.getByRole("button", { name: /^Send (another )?test event$/ }).click();
      // The live region announces this run's result, so earlier runs cannot satisfy the wait.
      await expect(page.getByTestId("setup-announcer")).toContainText("Test event finished", {
        timeout: 30_000
      });
      await expect(steps.getByRole("button", { name: "Step 6: Send a test event, Done" }))
        .toBeVisible();
      await steps.getByRole("button", { name: /^Step 7: See proof it arrived/ }).click();
      const proof = page.getByRole("region", { name: "See proof it arrived" });
      await expect(proof.getByText("Simulated, not proof")).toBeVisible();
      await expect(proof.getByText(/no Sentinel query ran, so this is not proof/)).toBeVisible();
    } else {
      await expect(page.getByText("The management server is not set up to send test events."))
        .toBeVisible();
      await expect(page.getByRole("button", { name: /Send (another )?test event/ })).toBeDisabled();
    }
    await expect(page.getByText("Verified in Sentinel")).toHaveCount(0);

    // Progress survives a reload: it is stored by the API, not the browser.
    await page.reload();
    await expect(steps.getByRole("button", { name: "Step 3: Choose where events go, Done" }))
      .toBeVisible();
    await expect(page.getByText("Verified in Sentinel")).toHaveCount(0);
    await expectNoHorizontalOverflow(page);
  });

  test("a viewer follows progress without any write controls", async ({ page }) => {
    // Development sign-in grants every role; this header narrows it to Bower.Viewer.
    await page.setExtraHTTPHeaders({ "X-Bower-Development-Roles": "Bower.Viewer" });
    await page.goto("/setup");

    await expect(page.getByText(/Viewing only/)).toBeVisible();
    const steps = page.getByRole("navigation", { name: "Setup steps" });
    for (const step of [3, 5, 6, 7]) {
      await steps.getByRole("button", { name: new RegExp(`^Step ${step}:`) }).click();
      await expect(page.getByRole("textbox")).toHaveCount(0);
      await expect(page.getByRole("radio")).toHaveCount(0);
      await expect(
        page.getByRole("button", { name: /^(Save|Send|Check the rule)/ })
      ).toHaveCount(0);
    }
    // The API refuses the change regardless of what the console shows.
    const refused = await page.request.post("/api/setup/destination", {
      headers: { "X-Bower-Development-Roles": "Bower.Viewer" },
      data: { workspaceId: "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b" }
    });
    expect(refused.status()).toBe(403);
    await expectNoHorizontalOverflow(page);
  });
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

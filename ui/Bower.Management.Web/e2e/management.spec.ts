import { expect, test, type Page } from "@playwright/test";

test("home answers the three questions in plain English with fixes", async ({ page }) => {
  const consoleErrors = collectConsoleErrors(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Home", level: 1 })).toBeVisible();
  const flow = page.getByRole("region", { name: "Is my data flowing?" });
  await expect(flow.getByText(/sending events/)).toBeVisible();
  // The stub collector never verifies, so the home view must never claim Sentinel proof.
  await expect(flow.getByText(/^Proven:/)).toHaveCount(0);

  const protectedRegion = page.getByRole("region", { name: "What was protected this week?" });
  const removed = protectedRegion.getByRole("list", { name: "Sensitive details removed this week" });
  await expect(removed.getByText("Tax file numbers removed")).toBeVisible();
  await expect(removed.getByText("Email addresses removed")).toBeVisible();
  await expect(removed.getByText("40", { exact: true })).toBeVisible();

  const attention = page.getByRole("region", { name: "What needs my attention?" });
  await expect(attention.getByText("1 collector has asked to join.")).toBeVisible();
  await expect(attention.getByRole("link", { name: /^Go to Approvals for: 1 collector has asked to join/ }))
    .toHaveAttribute("href", "/approvals");

  const groups = page.getByRole("region", { name: "Collector groups" });
  await expect(groups.getByRole("heading", { name: "production" })).toBeVisible();
  await expect(groups.getByRole("heading", { name: "hr" })).toBeVisible();

  await flow.getByRole("link", { name: "collectors" }).first().click();
  await expect(page.getByRole("heading", { name: "Glossary" })).toBeVisible();
  await expect(page.locator("#collector")).toBeFocused();

  await page.goto("/");
  await page.getByRole("link", { name: "See the detailed overview" }).click();
  await expect(page.getByRole("heading", { name: "Fleet posture" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  expect(consoleErrors).toEqual([]);
});

test("fleet overview reports real management state", async ({ page }, testInfo) => {
  const consoleErrors = collectConsoleErrors(page);
  await page.goto("/overview");

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

test("fleet filters by site and state and opens read-only machine details", async ({ page }) => {
  await page.setExtraHTTPHeaders({ "X-Bower-Development-Roles": "Bower.Viewer" });
  await page.goto("/collectors");
  await expect(page.getByRole("heading", { name: "Collectors", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "View details for finance-app-01" })).toBeVisible();
  await page.getByLabel("Site", { exact: true }).selectOption("hr");
  await expect(page.getByRole("link", { name: "View details for hr-app-02" })).toBeVisible();
  await expect(page.getByRole("link", { name: "View details for finance-app-01" })).toHaveCount(0);
  await page.getByLabel("State", { exact: true }).selectOption("waiting-for-approval");
  await expect(page.getByText("Showing 1 of 4 collectors")).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Site", { exact: true })).toHaveValue("hr");
  await expect(page.getByText("Waiting for approval", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await page.getByRole("button", { name: "Clear filters" }).click();
  await page.getByLabel("Find a machine").fill("finance-app-01");
  await page.getByRole("link", { name: "View details for finance-app-01" }).click();
  await expect(page.getByRole("heading", { name: "Collector details" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Configured sources" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Check arrival in Microsoft Sentinel" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Approve|Suspend|Revoke/ })).toHaveCount(0);
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
    const approvedCollectors = page.getByText(/2 collectors approved:/);
    await expect(approvedCollectors).toContainText("claims-api-03");
    await expect(approvedCollectors).toContainText("finance-app-01");
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

test("enrolment shows a new token once and then lists only its metadata", async ({ page }) => {
  const consoleErrors = collectConsoleErrors(page);
  await page.goto("/enrolment");

  await expect(page.getByRole("heading", { name: "Token enrolment" })).toBeVisible();
  await page.getByLabel("Environment").fill("production");
  await page.getByLabel("Reason").fill("Playwright enrolment check");
  await page.getByRole("button", { name: "Create token" }).click();
  const shown = page.getByLabel("Enrolment token", { exact: true });
  await expect(shown).toContainText("bwe1.");
  await expectNoHorizontalOverflow(page);
  const token = ((await shown.textContent()) ?? "").trim();
  const id = token.split(".")[1] ?? "";

  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText(token)).toHaveCount(0);
  await expect(page.getByText(id, { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  expect(consoleErrors).toEqual([]);
});

test.describe("guided source setup", () => {
  test.describe.configure({ mode: "serial" });

  test("an operator sets up syslog, a second person approves it and the server proves events arrive", async ({
    page
  }, testInfo) => {
    test.skip(testInfo.project.name !== "readme-chromium", "Source requests are created by one project only.");
    const consoleErrors = collectConsoleErrors(page);
    await page.goto("/sources");

    await expect(page.getByRole("heading", { name: "Sources", level: 1 })).toBeVisible();
    await page.getByRole("radio", { name: /^Syslog/ }).check();
    await page.getByRole("button", { name: "Continue" }).click();
    const settings = page.getByRole("region", { name: "Fill in the settings" });
    await expect(settings.getByText("What you need")).toBeVisible();
    await settings.getByLabel("Collector", { exact: true }).selectOption("finance-prod-01");
    await settings.getByLabel("Allowed senders").fill("10.40.0.0/24");
    await settings.getByLabel("Server certificate file").fill("/etc/bower/syslog/server.pem");
    // A secret is refused: only where it is stored may be entered.
    await settings.getByLabel("Server private key file").fill("-----BEGIN PRIVATE KEY-----");
    await settings.getByLabel("Application name").fill("edge-firewall");
    await settings.getByLabel("Collector name senders use").fill("collector.example.org");
    await settings.getByRole("button", { name: "Check settings" }).click();
    await expect(settings.getByText(/must say where the secret is stored/)).toBeVisible();
    await expect(settings.getByText("-----BEGIN PRIVATE KEY-----")).toHaveCount(0);
    await settings.getByLabel("Server private key file").fill("/etc/bower/syslog/server-key.pem");
    await settings.getByRole("button", { name: "Check settings" }).click();

    const review = page.getByRole("region", { name: "Review and preview" });
    const preview = review.getByLabel("Example event after redaction");
    await expect(preview).toBeVisible();
    // The synthetic sample's raw values never reach the browser.
    await expect(preview).not.toContainText("alex.citizen@example.com");
    await expect(review.getByLabel("Contents of syslog.json")).toContainText("\"kind\": \"SyslogSource\"");
    await expect(review.getByLabel("Sender: rsyslog")).toContainText("StreamDriver=\"gtls\"");
    await expectNoHorizontalOverflow(page);
    await review.getByRole("button", { name: "Continue" }).click();

    const approval = page.getByRole("region", { name: "Ask for approval" });
    await approval.getByLabel("Why this source is needed").fill("Playwright: edge firewall SSH failures");
    await approval.getByRole("button", { name: "Ask for approval" }).click();
    await expect(page.getByRole("heading", { name: "Syslog on finance-prod-01" })).toBeVisible();
    await expect(page.getByRole("region", { name: "Approval" }).getByText("Waiting for an approver other than the person who asked.")).toBeVisible();
    const id = new URL(page.url()).searchParams.get("request") ?? "";
    expect(id).toMatch(/^[0-9a-f]{32}$/);

    // Four-eyes: the person who asked cannot approve, in the console or through the API.
    await page.goto("/approvals");
    await expect(page.getByRole("region", { name: "Source setup requests" })
      .getByText("You asked for this source, so another approver must decide it.").first()).toBeVisible();
    const self = await page.request.post(`/api/sources/requests/${id}/approve`, { data: { reason: "Self approval" } });
    expect(self.status()).toBe(409);
    const approved = await page.request.post(`/api/sources/requests/${id}/approve`, {
      headers: { "X-Bower-Development-Person": "reviewer" },
      data: { reason: "Playwright: matches the firewall change" }
    });
    expect(approved.status()).toBe(200);

    // Only the collector's own heartbeat can make the check pass.
    await heartbeatFinance(page);
    await page.goto(`/sources?request=${id}`);
    await expect(page.getByRole("heading", { name: "Syslog on finance-prod-01" })).toBeVisible();
    await page.getByRole("navigation", { name: "Source request steps" })
      .getByRole("button", { name: /^Step 3: Check it works/ }).click();
    const check = page.getByRole("region", { name: "Check it works" });
    await expect(check.getByText("The collector reports events from edge-firewall/production.")).toBeVisible();

    await page.goto("/audit");
    await expect(page.getByText("source-setup.approved").first()).toBeVisible();
    await expect(page.getByText("source-setup.self-review-refused").first()).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("a viewer reads source needs and requests without write controls", async ({ page }) => {
    await page.setExtraHTTPHeaders({ "X-Bower-Development-Roles": "Bower.Viewer" });
    await page.goto("/sources");

    await expect(page.getByText(/Viewing only/)).toBeVisible();
    await page.getByRole("radio", { name: /^Docker containers/ }).check();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("button", { name: "Check settings" })).toBeDisabled();
    await expect(page.getByRole("region", { name: "Source setup requests" }).getByText("Docker containers").first())
      .toBeVisible();
    const refused = await page.request.post("/api/sources/plan", {
      headers: { "X-Bower-Development-Roles": "Bower.Viewer" },
      data: { type: "ama", collectorId: "finance-prod-01", values: {} }
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
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation).toBeVisible();
  // The home page links to Collectors too; use the navigation's link.
  await navigation.getByRole("link", { name: "Collectors" }).click();
  await expect(page.getByRole("heading", { name: "Collectors" })).toBeVisible();
  await expect(page.getByText("finance-app-01")).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

/**
 * Reports finance-prod-01's expected sources as healthy, as its collector would. Development
 * sign-in holds the collector role and seeded the collector, so it may act for it. Every
 * other field matches the seed, so only the source report changes.
 */
async function heartbeatFinance(page: Page): Promise<void> {
  const now = new Date().toISOString();
  const response = await page.request.post("/api/collectors/finance-prod-01/heartbeat", {
    data: {
      version: "0.1.0",
      configurationHash: "sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
      policyHash: "sha256:4f2a9c1e7b3d58a6c0e2f91b4d7a8c3e5f6b1a2d9c0e7f84b3a5d6c1e2f9a7b8",
      queueDepth: 3,
      deliveryStatus: "healthy",
      deadLettered: 0,
      ledger: { sequence: 48211, hash: "preview-ledger-48211" },
      sources: [
        { id: "local-http", type: "local-http", status: "healthy", lagSeconds: null, lastEventAt: now },
        { id: "ssh-gateway/production", type: "application", status: "healthy", lagSeconds: 0, lastEventAt: now },
        { id: "edge-firewall/production", type: "application", status: "healthy", lagSeconds: 0, lastEventAt: now }
      ],
      outputs: [
        {
          id: "azure-logs-ingestion",
          type: "azure-logs-ingestion",
          status: "healthy",
          lastAcknowledgedAt: now,
          lastErrorCode: null
        }
      ]
    }
  });
  expect(response.status()).toBe(200);
}

test("privacy actions can be edited with forms and need a different approver", async ({ page }, testInfo) => {
  const profile = `guided-${testInfo.project.name}-${Date.now()}`;
  const initial = `apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: ${profile}\n  version: 1.0.0\n`;
  const baseline = await page.request.post("/api/privacy-profiles", { data: { content: initial, changeSummary: "Synthetic browser-test baseline" } });
  expect(baseline.ok()).toBeTruthy();
  const baselineId = (await baseline.json()).id as string;
  await page.goto(`/privacy-profiles?version=${baselineId}`);
  await page.getByRole("button", { name: "Edit with forms" }).click();
  await page.getByLabel("New version", { exact: true }).fill("1.0.1");
  await page.getByRole("button", { name: "Add a field" }).click();
  await page.getByLabel("Field path", { exact: true }).fill("actor.username");
  await page.getByLabel("How to protect it").selectOption("hmac");
  await page.getByRole("button", { name: "Review changes" }).click();
  const review = page.getByRole("region", { name: "Review privacy changes" });
  await expect(review.getByLabel("Protected privacy example")).not.toContainText("alex.example@example.com");
  await expect(review.getByRole("region", { name: "Line diff" })).toContainText("hmac");
  await expectNoHorizontalOverflow(page);
  await page.getByLabel("Why this change is needed").fill("Synthetic browser test: protect usernames");
  await page.getByRole("button", { name: "Ask another person to approve" }).click();
  await expect(page.getByText(`Submitted ${profile}@1.0.1 for review. Another approver must approve it.`)).toBeVisible();
  const id = new URL(page.url()).searchParams.get("version");
  const self = await page.request.post(`/api/privacy-profiles/versions/${id}/approve`, { data: { reason: "Self review" } });
  expect(self.status()).toBe(409);
  const approval = await page.request.post(`/api/privacy-profiles/versions/${id}/approve`, { headers: { "X-Bower-Development-Person": "reviewer" }, data: { reason: "Synthetic second-person review" } });
  expect(approval.ok()).toBeTruthy();
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

test("fleet supports keyboard filters, dark mode and a 320px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.addInitScript(() => localStorage.setItem("bower-theme", "dark"));
  await page.goto("/collectors");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  const state = page.getByRole("combobox", { name: "State", exact: true });
  await state.focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("combobox", { name: "Site", exact: true })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("searchbox", { name: "Find a machine" })).toBeFocused();
  await page.keyboard.type("claims-api-03");
  await expect(page.getByText("Showing 1 of 4 collectors")).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await page.getByRole("link", { name: "View details for claims-api-03" }).click();
  await expect(page.getByRole("heading", { name: "Machine details" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

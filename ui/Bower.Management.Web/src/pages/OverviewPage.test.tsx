import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import type { Collector, Overview } from "../types";

const assignedHash = `sha256:${"ab".repeat(32)}`;

const driftedCollector: Collector = {
  id: "claims-prod-03",
  machineName: "claims-api-03",
  environment: "production",
  version: "0.1.0",
  status: "Active",
  principalObjectId: "collector-principal",
  firstSeenAt: "2026-10-07T00:00:00Z",
  lastSeenAt: "2026-10-07T01:10:00Z",
  configurationHash: "sha256:configuration",
  policyHash: "sha256:policy",
  queueDepth: 0,
  deliveryStatus: "healthy",
  sources: [],
  outputs: [],
  desiredPrivacyProfile: {
    versionId: "a".repeat(32),
    profileId: "contoso-hr",
    version: "1.1.0",
    contentHash: assignedHash
  },
  reportedPrivacyProfileHash: "default",
  privacyProfileInSync: false
};

const healthyOverview: Overview = {
  totalCollectors: 1,
  pendingApproval: 0,
  unhealthyCollectors: 0,
  staleCollectors: 0,
  totalQueueDepth: 0,
  sourcesReporting: 4,
  sourcesDegraded: 0,
  exceptions: [],
  policyDrift: 0,
  deadLettered: 0,
  privacyProfileDrift: 0,
  privacyProfileExceptions: [],
  sourcesUnknown: 0
};

function stubOverview(overview: Overview) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path === "/api/access/me") {
        return json({
          objectId: "viewer-oid",
          displayName: "Morgan Lee",
          roles: ["Bower.Viewer"],
          developmentAuthentication: false
        });
      }
      if (path === "/api/overview") {
        return json(overview);
      }
      return new Response(JSON.stringify({ error: `Unexpected ${path}` }), { status: 500 });
    })
  );
}

describe("Overview page", () => {
  beforeEach(() => {
    vi.stubGlobal("matchMedia", () => ({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows a rejected privacy profile rollout as an actionable exception", async () => {
    stubOverview({
      ...healthyOverview,
      exceptions: [driftedCollector],
      privacyProfileDrift: 1,
      privacyProfileExceptions: [
        {
          collectorId: "claims-prod-03",
          machineName: "claims-api-03",
          assignmentRevision: 7,
          assignedAt: "2026-10-07T01:00:00Z",
          versionId: "a".repeat(32),
          profileId: "contoso-hr",
          version: "1.1.0",
          assignedHash,
          observedHash: "default",
          observedAt: "2026-10-07T01:10:00Z",
          mismatchConfirmed: true
        }
      ]
    });
    renderApp();

    const drift = await screen.findByRole("region", { name: "Privacy profile not applied" });
    const summary = screen.getByLabelText("Fleet summary");
    expect(within(summary).getByText("Privacy drift").nextSibling?.textContent).toBe("1");
    // Delivery and heartbeat health are normal; the collector is still an open exception.
    expect(within(summary).getByText("Unhealthy").nextSibling?.textContent).toBe("0");
    expect(screen.getByText("1 open")).toBeTruthy();
    expect(screen.queryByText("No fleet exceptions")).toBeNull();
    expect(within(drift).getByText("claims-api-03")).toBeTruthy();
    expect(within(drift).getByText("contoso-hr@1.1.0 · abababab")).toBeTruthy();
    expect(within(drift).getByText(/Revision 7/)).toBeTruthy();
    expect(within(drift).getByText("Not applied · default")).toBeTruthy();
    expect(within(drift).getByText(/^Heartbeat /)).toBeTruthy();
    const link = within(drift).getByRole("link", {
      name: "Privacy profile details for claims-api-03"
    });
    expect(link.getAttribute("href")).toBe(`/privacy-profiles?version=${"a".repeat(32)}`);
  });

  it("distinguishes an assignment the collector has not heartbeated since", async () => {
    stubOverview({
      ...healthyOverview,
      exceptions: [driftedCollector],
      privacyProfileDrift: 1,
      privacyProfileExceptions: [
        {
          collectorId: "claims-prod-03",
          machineName: "claims-api-03",
          assignmentRevision: 8,
          assignedAt: "2026-10-07T01:20:00Z",
          versionId: "a".repeat(32),
          profileId: "contoso-hr",
          version: "1.1.0",
          assignedHash,
          observedHash: null,
          observedAt: "2026-10-07T01:10:00Z",
          mismatchConfirmed: false
        }
      ]
    });
    renderApp();

    const drift = await screen.findByRole("region", { name: "Privacy profile not applied" });
    const awaiting = within(drift).getByText("Awaiting heartbeat · not reported");
    // Not yet a failed rollout: no drift (danger) styling.
    expect(awaiting.className).not.toContain("policy-label--drift");
    expect(within(drift).queryByText(/Not applied/)).toBeNull();
    expect(within(drift).getByText("Assigned version against the hash in the latest heartbeat")).toBeTruthy();
  });

  it("states how many drifting collectors are shown when the list is truncated", async () => {
    const rows = Array.from({ length: 12 }, (_, index) => ({
      collectorId: `edge-${index}`,
      machineName: `edge-app-${index}`,
      assignmentRevision: index + 1,
      assignedAt: "2026-10-07T01:00:00Z",
      versionId: "a".repeat(32),
      profileId: "contoso-hr",
      version: "1.1.0",
      assignedHash,
      observedHash: "default",
      observedAt: "2026-10-07T01:10:00Z",
      mismatchConfirmed: true
    }));
    stubOverview({
      ...healthyOverview,
      exceptions: [driftedCollector],
      privacyProfileDrift: 30,
      privacyProfileExceptions: rows
    });
    renderApp();

    const drift = await screen.findByRole("region", { name: "Privacy profile not applied" });
    expect(within(drift).getByText("12 of 30 shown")).toBeTruthy();
    expect(within(drift).getAllByRole("link")).toHaveLength(12);
  });

  it("omits the privacy drift section and keeps the empty state when nothing is drifting", async () => {
    stubOverview(healthyOverview);
    renderApp();

    expect(await screen.findByText("No fleet exceptions")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Privacy profile not applied" })).toBeNull();
    expect(screen.getByLabelText("Reporting: 100%")).toBeTruthy();
    expect(screen.getByLabelText("Unknown: 0%")).toBeTruthy();
  });

  it("explains that pending sources count as unknown", async () => {
    stubOverview(healthyOverview);
    renderApp();

    expect(await screen.findByText(/pending sources not yet seen/)).toBeTruthy();
  });

  it("counts stale and inactive collectors' sources as unknown within the coverage total", async () => {
    // 2 reporting, 1 degraded on fresh collectors, 3 unknown on a stale one: total 6.
    stubOverview({
      ...healthyOverview,
      staleCollectors: 1,
      sourcesReporting: 2,
      sourcesDegraded: 4,
      sourcesUnknown: 3
    });
    renderApp();

    expect(await screen.findByLabelText("Reporting: 33%")).toBeTruthy();
    expect(screen.getByLabelText("Degraded: 17%")).toBeTruthy();
    expect(screen.getByLabelText("Unknown: 50%")).toBeTruthy();
    const coverage = screen.getByRole("heading", { name: "Source coverage" }).parentElement!;
    expect(within(coverage).getByText("Unknown").nextSibling?.textContent).toBe("3");
    expect(within(coverage).getByText("Degraded").nextSibling?.textContent).toBe("1");
  });

  it("keeps the previous two-row coverage arithmetic for an API without unknown sources", async () => {
    const legacy: Overview = { ...healthyOverview, sourcesReporting: 3, sourcesDegraded: 1 };
    delete legacy.sourcesUnknown;
    delete legacy.privacyProfileExceptions;
    delete legacy.privacyProfileDrift;
    stubOverview(legacy);
    renderApp();

    expect(await screen.findByLabelText("Reporting: 75%")).toBeTruthy();
    expect(screen.getByLabelText("Degraded: 25%")).toBeTruthy();
    expect(screen.getByLabelText("Unknown: 0%")).toBeTruthy();
  });
});

function renderApp() {
  render(
    <AuthenticationProvider>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </AuthenticationProvider>
  );
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import type { SetupCanaryRun, SetupStatus, SetupStep, SetupStepId } from "../types";

const ids: SetupStepId[] = ["sign-in", "entra", "destination", "collector", "probe", "canary", "proof"];

function steps(states: Partial<Record<SetupStepId, SetupStep["state"]>>, overrides: Partial<Record<SetupStepId, Partial<SetupStep>>> = {}): SetupStep[] {
  return ids.map((id) => ({
    id,
    state: states[id] ?? "complete",
    checks: [],
    updatedBy: null,
    updatedAt: null,
    ...overrides[id]
  }));
}

const baseStatus: SetupStatus = {
  canChange: true,
  steps: steps({ destination: "not-started", probe: "not-started", canary: "blocked", proof: "not-started" }, {
    destination: {
      checks: [
        {
          id: "workspace",
          state: "pending",
          message: "No Log Analytics workspace chosen yet.",
          fix: "Enter the workspace ID from the workspace's Overview page in the Azure portal."
        }
      ]
    }
  }),
  destination: null,
  probe: null,
  probeOptions: [
    {
      profile: "generic",
      title: "Generic test event",
      description: "Sends Bower's canary event through the collector's event intake.",
      packId: null,
      expectedEventType: "collector_canary"
    }
  ],
  canary: {
    configured: true,
    verifierConfigured: true,
    signingConfigured: true,
    collectorHost: "collector.example.test",
    timeoutMinutes: 15
  },
  latestRun: null
};

const finishedRun: SetupCanaryRun = {
  id: "a".repeat(32),
  profile: "generic",
  state: "completed",
  mode: "verified",
  outcome: "verified",
  message: "Verified: Bower queried Microsoft Sentinel and found the exact test event.",
  fix: "Nothing to fix.",
  collectorAccepted: true,
  eventId: "bower-canary-0192",
  workspaceId: "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b",
  table: "BowerSecurity_CL",
  latencySeconds: 42,
  hasSignature: true,
  hasBundle: true,
  requestedBy: "Alex Admin",
  requestedAt: "2026-10-27T00:00:00Z",
  completedAt: "2026-10-27T00:01:00Z"
};

let requests: { method: string; path: string; body: unknown }[] = [];

function stubSetup(sequence: SetupStatus[], roles = ["Bower.Administrator"]) {
  let index = 0;
  requests = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), "http://localhost").pathname;
      const method = init?.method ?? "GET";
      requests.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/api/access/me") {
        return json({ objectId: "oid", displayName: "Alex", roles, developmentAuthentication: false });
      }
      if (path === "/api/setup" && method === "GET") {
        const status = sequence[Math.min(index, sequence.length - 1)]!;
        index += 1;
        return json(status);
      }
      if (path === "/api/setup/destination" && method === "POST") {
        return json({});
      }
      return json({ error: `Unexpected ${method} ${path}` }, 500);
    })
  );
}

describe("Setup page", () => {
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

  it("opens the first unfinished step with its reason and suggested fix", async () => {
    stubSetup([baseStatus]);
    renderSetup();

    const step = await screen.findByRole("region", { name: "Choose where events go" });
    expect(within(step).getByText("Step 3 of 7")).toBeTruthy();
    expect(within(step).getByText("Why this matters:")).toBeTruthy();
    expect(within(step).getByText(/Enter the workspace ID from the workspace's Overview page/)).toBeTruthy();
    const nav = screen.getByRole("navigation", { name: "Setup steps" });
    expect(within(nav).getByRole("button", { name: /Step 3: Choose where events go/ }).getAttribute("aria-current")).toBe("step");
    expect(screen.getByRole("link", { name: "Setup" })).toBeTruthy();
  });

  it("shows read-only progress to people who cannot change setup", async () => {
    stubSetup([{ ...baseStatus, canChange: false }], ["Bower.Viewer"]);
    renderSetup();

    await screen.findByRole("region", { name: "Choose where events go" });
    expect(screen.getByText(/Viewing only/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Save destination" })).toBeNull();
    expect(screen.queryByLabelText("Workspace ID")).toBeNull();
  });

  it("saves the destination on the server and refreshes progress in place", async () => {
    const saved: SetupStatus = {
      ...baseStatus,
      steps: steps({ probe: "not-started", canary: "blocked", proof: "not-started" }),
      destination: {
        workspaceId: "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b",
        workspaceResourceId: null,
        dcrResourceId: null,
        table: "BowerSecurity_CL",
        updatedBy: "Alex Admin",
        updatedAt: "2026-10-27T00:00:00Z"
      }
    };
    stubSetup([baseStatus, saved]);
    renderSetup();

    fireEvent.change(await screen.findByLabelText("Workspace ID"), {
      target: { value: "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save destination" }));

    await waitFor(() =>
      expect(requests).toContainEqual({
        method: "POST",
        path: "/api/setup/destination",
        body: {
          workspaceId: "6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b",
          workspaceResourceId: "",
          dcrResourceId: "",
          table: "BowerSecurity_CL"
        }
      })
    );
    const step = screen.getByRole("region", { name: "Choose where events go" });
    await waitFor(() => expect(within(step).getByText("Done")).toBeTruthy());
    expect(screen.queryByLabelText("Loading")).toBeNull();
  });

  it("labels a simulated run as simulated and never as verified", async () => {
    stubSetup([
      {
        ...baseStatus,
        steps: steps({ proof: "attention" }, {
          proof: {
            checks: [
              {
                id: "proof",
                state: "warn",
                message: "Simulated: the collector accepted the test event, but Bower did not query Sentinel, so this is not proof of delivery.",
                fix: "Configure a read-only verifier identity."
              }
            ]
          }
        }),
        latestRun: { ...finishedRun, mode: "simulated", outcome: "accepted-not-verified", hasSignature: false }
      }
    ]);
    renderSetup();

    const step = await screen.findByRole("region", { name: "See proof it arrived" });
    expect(within(step).getByText("Simulated, not proof")).toBeTruthy();
    expect(within(step).getByText(/no Sentinel query ran, so this is not proof/)).toBeTruthy();
    expect(within(step).queryByText(/Verified/)).toBeNull();
    expect(within(step).getByRole("button", { name: "Download simulated evidence bundle" })).toBeTruthy();
  });

  it("shows verified proof only for a query-verified run", async () => {
    stubSetup([{ ...baseStatus, steps: steps({}), latestRun: finishedRun }]);
    renderSetup();

    const step = await screen.findByRole("region", { name: "See proof it arrived" });
    expect(within(step).getAllByText("Verified in Sentinel").length).toBeGreaterThan(0);
    expect(within(step).getByText("bower-canary-0192")).toBeTruthy();
    expect(within(step).getByText("42 seconds")).toBeTruthy();
    expect(within(step).getByText("Signed")).toBeTruthy();
    expect(within(step).getByRole("button", { name: "Download evidence bundle" })).toBeTruthy();
  });

  it("keeps an accepted but unproven run out of the verified state", async () => {
    stubSetup([
      {
        ...baseStatus,
        steps: steps({ proof: "attention" }),
        latestRun: { ...finishedRun, mode: "failed", outcome: "destination-row-missing", latencySeconds: null }
      }
    ]);
    renderSetup();

    const step = await screen.findByRole("region", { name: "See proof it arrived" });
    expect(within(step).getByText("Needs attention")).toBeTruthy();
    expect(within(step).getByText(/accepted by the collector, not found in Sentinel/)).toBeTruthy();
    expect(within(step).queryByText("Verified in Sentinel")).toBeNull();
  });

  it("disables sending while a test is in progress", async () => {
    stubSetup([
      {
        ...baseStatus,
        steps: steps({ canary: "in-progress", proof: "in-progress" }),
        latestRun: { ...finishedRun, state: "running", mode: null, outcome: null, completedAt: null }
      }
    ]);
    renderSetup();

    const step = await screen.findByRole("region", { name: "Send a test event" });
    const button = within(step).getByRole("button", { name: "Test in progress…" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});

function renderSetup() {
  render(
    <AuthenticationProvider>
      <MemoryRouter initialEntries={["/setup"]}>
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

import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { AuthenticationProvider } from "./auth";

const collector = {
  id: "finance-prod-01",
  machineName: "finance-app-01",
  environment: "production",
  version: "0.1.0",
  status: "Pending",
  principalObjectId: "collector-principal",
  firstSeenAt: "2026-07-26T01:00:00Z",
  lastSeenAt: "2026-07-26T01:01:00Z",
  configurationHash: "sha256:configuration",
  policyHash: "sha256:policy",
  queueDepth: 0,
  deliveryStatus: "unknown",
  sources: [],
  outputs: []
};

describe("Bower management shell", () => {
  beforeEach(() => {
    const storage = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
      clear: () => storage.clear()
    });
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

  it("renders a real empty fleet state from the API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({
          totalCollectors: 0,
          pendingApproval: 0,
          unhealthyCollectors: 0,
          staleCollectors: 0,
          totalQueueDepth: 0,
          sourcesReporting: 0,
          sourcesDegraded: 0,
          exceptions: []
        })
      )
    );

    renderApp("/");

    expect(await screen.findByText("Fleet posture")).toBeTruthy();
    expect(await screen.findByText("No fleet exceptions")).toBeTruthy();
    expect(screen.getByText(/Development authentication active/)).toBeTruthy();
  });

  it("keeps approval controls unavailable for a viewer", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        if (path.includes("/api/collectors?status=Pending")) {
          return json([collector]);
        }
        if (path.includes("/api/approvals")) {
          return json([]);
        }
        return json({
          objectId: "viewer-object",
          displayName: "Morgan Lee",
          roles: ["Bower.Viewer"],
          developmentAuthentication: false
        });
      })
    );

    renderApp("/approvals");

    expect(await screen.findByText(/Viewing only/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });
});

function renderApp(path: string) {
  render(
    <AuthenticationProvider>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </AuthenticationProvider>
  );
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

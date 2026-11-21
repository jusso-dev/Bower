import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthenticationProvider } from "../auth";
import { PipelinesPage } from "./PipelinesPage";
import type { CollectorPipelineFlow } from "../types";

const sampleFlow: CollectorPipelineFlow = {
  collectorId: "edge-01",
  machineName: "edge-01.corp.example",
  site: "production",
  connectivity: "online",
  lastSeenAt: "2026-11-22T07:00:00Z",
  policyHash: "sha256:abcdef0123456789",
  privacyProfileHash: "sha256:1234567890abcdef",
  eventsIn: 1000,
  eventsQueued: 120,
  eventsSuppressed: 80,
  eventsRejected: 800,
  duplicates: 0,
  bytesIn: 500000,
  bytesQueued: 60000,
  reductionPercent: 88,
  queueDepth: 4,
  deadLettered: 0,
  oldestUndeliveredAgeSeconds: 12,
  deliveryStatus: "healthy",
  lastSuccessfulDeliveryAt: "2026-11-22T06:59:45Z",
  stages: [
    { id: "collect", title: "Collect", light: "green", headline: "2 sources configured", detail: "1,000 candidate event(s) seen" },
    { id: "redact", title: "Redact", light: "green", headline: "5 finding(s) protected", detail: "Assigned privacy profile in sync" },
    { id: "select", title: "Select", light: "green", headline: "120 kept of 1,000", detail: "88% noise filtered" },
    { id: "queue", title: "Queue", light: "green", headline: "4 waiting", detail: "Oldest waiting event is 12s old" },
    { id: "deliver", title: "Deliver", light: "green", headline: "azure-logs-ingestion", detail: "Status: healthy" }
  ],
  sources: [{ id: "local-http", type: "local-http", status: "healthy", lagSeconds: null, lastEventAt: null }],
  outputs: [{ id: "azure-logs-ingestion", type: "azure-logs-ingestion", status: "healthy", lastAcknowledgedAt: null, lastErrorCode: null }],
  topSources: [{ application: "portal", environment: "production", lastSeenAt: "2026-11-22T06:59:50Z", eventCount: 120 }],
  redactions: [{ type: "au.tfn", label: "Tax file numbers", events: 5 }],
  policyBreakdown: [
    { stage: "policy", policyId: "BWR-POL-AUTH-FAILURE", action: "accept", events: 120, queued: 120, duplicates: 0, suppressed: 0, bytesIn: 60000, bytesQueued: 60000 }
  ]
};

function stubApi(roles: string[]) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://localhost").pathname;
    if (path === "/api/access/me") {
      return json({ objectId: "u1", displayName: "Alex", roles, developmentAuthentication: true });
    }
    if (path === "/api/pipelines/live") {
      return json([sampleFlow]);
    }
    if (path === "/api/pipelines/templates") {
      return json([]);
    }
    if (path === "/api/pipelines/collectors/edge-01/tap" && init?.method === "POST") {
      return json({
        collectorId: "edge-01",
        mode: "cli",
        command: "bower tap --url http://127.0.0.1:4319 --limit 10 --duration 15",
        note: "Collectors communicate outbound only.",
        frames: [],
        capturedAt: "2026-11-22T07:01:00Z"
      });
    }
    return json({ error: `Unexpected ${path}` }, 500);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

describe("PipelinesPage visual flow", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders all five stages, top sources, redactions, and operator tap", async () => {
    stubApi(["Bower.Operator"]);
    render(
      <MemoryRouter>
        <AuthenticationProvider>
          <PipelinesPage />
        </AuthenticationProvider>
      </MemoryRouter>
    );

    expect(await screen.findByText("Live pipeline flow")).toBeTruthy();
    expect(screen.getByText("88%")).toBeTruthy();
    expect(screen.getByText("portal")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /^Redact/i }));
    expect(screen.getByText(/Tax file numbers/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Sample redacted events/i }));
    expect(await screen.findByText(/bower tap --url/)).toBeTruthy();
  });

  it("hides the tap button for Viewers", async () => {
    stubApi(["Bower.Viewer"]);
    render(
      <MemoryRouter>
        <AuthenticationProvider>
          <PipelinesPage />
        </AuthenticationProvider>
      </MemoryRouter>
    );

    expect(await screen.findByText("Live pipeline flow")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Sample redacted events/i })).toBeNull();
  });
});

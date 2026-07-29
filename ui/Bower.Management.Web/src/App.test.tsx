import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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

  it("generates and previews a custom log parser", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        if (path.includes("/api/custom-logs/generate")) {
          return json({
            format: "Json",
            confidence: 1,
            rationale: ["All 1 sampled record(s) are JSON objects."],
            configuration: {
              version: "1.0",
              format: "Json",
              fields: [
                {
                  sourceName: "severity",
                  type: "Text",
                  ocsfPath: "severity",
                  asimField: "EventSeverity",
                  sensitive: false
                }
              ],
              delimiter: null,
              keyValueSeparator: null,
              pattern: null
            },
            schema: {
              version: "1.0",
              fields: [
                {
                  name: "severity",
                  type: "Text",
                  required: true,
                  ocsfPath: "severity",
                  asimField: "EventSeverity"
                }
              ]
            },
            tests: [
              {
                name: "parses representative record",
                sourceLine: 1,
                shouldParse: true,
                expectedFields: ["severity"],
                expectedOcsfMappings: ["severity"],
                expectedAsimMappings: ["EventSeverity"]
              }
            ],
            preview: {
              isValid: true,
              parsedLineCount: 1,
              rejectedLineCount: 0,
              issues: [],
              rows: [
                {
                  sourceLine: 1,
                  fields: {
                    severity: {
                      type: "Text",
                      value: "warning",
                      ocsfPath: "severity",
                      asimField: "EventSeverity",
                      redacted: false
                    }
                  }
                }
              ]
            }
          });
        }
        return json([]);
      })
    );

    renderApp("/pipelines");

    fireEvent.change(await screen.findByLabelText("Sample records"), {
      target: { value: '{"severity":"warning"}' }
    });
    fireEvent.click(screen.getByRole("button", { name: "Infer parser and schema" }));

    expect(await screen.findByText("AI-assisted custom log parser")).toBeTruthy();
    expect(await screen.findByText("Json · 100%")).toBeTruthy();
    expect(await screen.findByText("Live transformation preview")).toBeTruthy();
    expect(screen.getByText("warning")).toBeTruthy();
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

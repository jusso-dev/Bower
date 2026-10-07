import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import { describeSchedule } from "./JobsPage";

const managementJob = {
  id: "collector-staleness",
  schedule: "*/5 * * * *",
  lastRunAt: "2026-10-07T01:00:00Z",
  lastState: "Succeeded",
  nextRunAt: "2026-10-07T01:05:00Z"
};

const collector = {
  id: "finance-prod-01",
  machineName: "finance-app-01",
  environment: "production",
  version: "0.1.0",
  status: "Active",
  principalObjectId: "collector-principal",
  firstSeenAt: "2026-10-07T00:00:00Z",
  lastSeenAt: "2026-10-07T01:00:00Z",
  configurationHash: "sha256:configuration",
  policyHash: "sha256:policy",
  queueDepth: 0,
  deliveryStatus: "healthy",
  sources: [],
  outputs: [],
  jobs: [
    {
      id: "queue-retention",
      schedule: "0 * * * *",
      lastRunAt: "2026-10-07T01:00:00Z",
      lastState: "Failed",
      nextRunAt: "2026-10-07T02:00:00Z"
    }
  ]
};

function access(roles: string[]) {
  return {
    objectId: "object-1",
    displayName: "Morgan Lee",
    roles,
    developmentAuthentication: false
  };
}

describe("Background jobs page", () => {
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

  it("shows management and collector job health", async () => {
    stubApi({ jobs: [managementJob], collectors: [collector], roles: ["Bower.Viewer"] });

    renderApp("/jobs");

    expect(await screen.findByText("collector-staleness")).toBeTruthy();
    expect(screen.getByText("Every 5 minutes")).toBeTruthy();
    expect(await screen.findByText("queue-retention")).toBeTruthy();
    expect(screen.getByText("Failed")).toBeTruthy();
  });

  it("hides run controls from non-administrators", async () => {
    stubApi({ jobs: [managementJob], collectors: [], roles: ["Bower.Operator"] });

    renderApp("/jobs");

    expect(await screen.findByText("Administrator only")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Run now/ })).toBeNull();
  });

  it("lets an administrator queue a job and confirms it", async () => {
    const fetchMock = stubApi({
      jobs: [managementJob],
      collectors: [],
      roles: ["Bower.Administrator"]
    });

    renderApp("/jobs");
    fireEvent.click(await screen.findByRole("button", { name: /Run now/ }));

    expect(await screen.findByText(/Queued collector-staleness/)).toBeTruthy();
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input).endsWith("/api/jobs/collector-staleness/trigger") &&
            (init as RequestInit | undefined)?.method === "POST"
        )
      ).toBe(true)
    );
  });

  it("renders empty states without inventing data", async () => {
    stubApi({ jobs: [], collectors: [], roles: ["Bower.Viewer"] });

    renderApp("/jobs");

    expect(await screen.findByText("No recurring jobs registered")).toBeTruthy();
    expect(await screen.findByText("No collector job reports yet")).toBeTruthy();
  });

  it("reports an unauthorized response instead of stale data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        if (path.includes("/api/jobs")) {
          return new Response(JSON.stringify({ title: "Forbidden" }), { status: 403 });
        }
        if (path.includes("/api/collectors")) {
          return json([]);
        }
        return json(access(["Bower.Viewer"]));
      })
    );

    renderApp("/jobs");

    expect(await screen.findByText("Could not load this view.")).toBeTruthy();
    expect(screen.getByText("Forbidden")).toBeTruthy();
  });

  it("describes known schedules and passes others through", () => {
    expect(describeSchedule("0 * * * *")).toBe("Hourly");
    expect(describeSchedule("15 4 * * 1")).toBe("15 4 * * 1");
  });
});

function stubApi({
  jobs,
  collectors,
  roles
}: {
  jobs: unknown[];
  collectors: unknown[];
  roles: string[];
}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.includes("/trigger") && init?.method === "POST") {
      return new Response(null, { status: 202 });
    }
    if (path.includes("/api/jobs")) {
      return json(jobs);
    }
    if (path.includes("/api/collectors")) {
      return json(collectors);
    }
    return json(access(roles));
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

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

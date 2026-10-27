import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import type { Home } from "../types";

const home: Home = {
  generatedAt: "2026-10-27T09:30:00Z",
  state: "red",
  flow: {
    state: "amber",
    summary: "Partly. 4 of 5 collectors are sending events; 1 needs a look.",
    sending: 4,
    enrolled: 5,
    lastAcceptedAt: "2026-10-27T09:29:00Z",
    proof: {
      state: "not-proven",
      message: "Not proven yet: no test event has been checked in Microsoft Sentinel.",
      at: null,
      fix: { action: "Send a test event from the Setup page.", page: "/setup" }
    }
  },
  protection: {
    since: "2026-10-21T00:00:00Z",
    summary: "Bower removed these kinds of sensitive details before storing or sending events.",
    byType: [
      { type: "au.tfn", label: "Tax file numbers", events: 12 },
      { type: "secrets", label: "Passwords, keys and access tokens", events: 1 }
    ],
    collectorsReporting: 4,
    collectorsNotReporting: 1
  },
  attention: [
    {
      id: "offline",
      state: "red",
      message: "1 collector has not checked in for more than 15 minutes.",
      fix: { action: "Check that the machine is switched on and can reach Bower.", page: "/collectors" },
      count: 1
    },
    {
      id: "pending",
      state: "amber",
      message: "1 collector has asked to join.",
      fix: { action: "Review the request on the Approvals page.", page: "/approvals" },
      count: 1
    }
  ],
  groups: [
    {
      name: "production",
      state: "red",
      collectors: 2,
      healthy: 1,
      reason: "1 of 2 collectors has not checked in for more than 15 minutes.",
      fix: { action: "Check that the machine is switched on and can reach Bower.", page: "/collectors" },
      otherIssues: 1
    },
    {
      name: "staging",
      state: "green",
      collectors: 3,
      healthy: 3,
      reason: "All 3 collectors are checking in and sending events.",
      fix: null,
      otherIssues: 0
    }
  ],
  groupsTotal: 2
};

function stubHome(respond: () => Response) {
  const fetch = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(String(input), "http://localhost").pathname;
    if (path === "/api/access/me") {
      return json({
        objectId: "viewer-oid",
        displayName: "Morgan Lee",
        roles: ["Bower.Viewer"],
        developmentAuthentication: false
      });
    }
    if (path === "/api/home") {
      return respond();
    }
    return json({ error: `Unexpected ${path}` }, 500);
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("Home page", () => {
  beforeEach(() => {
    vi.stubGlobal("matchMedia", () => ({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    }));
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("answers the three questions in words with a fix for every reason", async () => {
    stubHome(() => json(home));
    renderApp("/");

    const flow = await screen.findByRole("region", { name: "Is my data flowing?" });
    expect(within(flow).getByText("Needs a look")).toBeTruthy();
    expect(within(flow).getByText(/Partly\. 4 of 5/)).toBeTruthy();
    expect(within(flow).getByText(/Acceptance alone does not prove arrival/)).toBeTruthy();
    expect(within(flow).getByText(/Not proven yet/)).toBeTruthy();
    expect(within(flow).queryByText(/Proven:/)).toBeNull();

    const protectedRegion = screen.getByRole("region", { name: "What was protected this week?" });
    const removed = within(protectedRegion).getByRole("list", {
      name: "Sensitive details removed this week"
    });
    expect(within(removed).getByText("Tax file numbers removed")).toBeTruthy();
    expect(within(removed).getByText("12")).toBeTruthy();
    expect(within(protectedRegion).getByText(/1 working collector runs an older version/)).toBeTruthy();
    expect(within(protectedRegion).getByText(/never shows the removed values/)).toBeTruthy();

    const attention = screen.getByRole("region", { name: "What needs my attention?" });
    expect(within(attention).getAllByText("Needs action now").length).toBeGreaterThan(0);
    const fixes = within(attention).getAllByText("How to fix:");
    expect(fixes).toHaveLength(home.attention.length);
    expect(
      within(attention)
        .getByRole("link", { name: /Go to Approvals for: 1 collector has asked to join/ })
        .getAttribute("href")
    ).toBe("/approvals");

    const groups = screen.getByRole("region", { name: "Collector groups" });
    const production = within(groups).getByRole("heading", { name: "production" }).closest("li")!;
    expect(within(production as HTMLElement).getByText("Needs action now")).toBeTruthy();
    expect(within(production as HTMLElement).getByText(/1 of 2 working normally, plus 1 other issue/)).toBeTruthy();
    expect(
      within(production as HTMLElement).getByRole("link", { name: /Go to Collectors/ }).getAttribute("href")
    ).toBe("/collectors");
    const staging = within(groups).getByRole("heading", { name: "staging" }).closest("li")!;
    expect(within(staging as HTMLElement).getByText("All good")).toBeTruthy();
    expect(within(staging as HTMLElement).queryByText("How to fix:")).toBeNull();

    expect(screen.getByRole("link", { name: "See the detailed overview" }).getAttribute("href")).toBe(
      "/overview"
    );
  });

  it("links glossary terms to help", async () => {
    stubHome(() => json(home));
    renderApp("/");

    const flow = await screen.findByRole("region", { name: "Is my data flowing?" });
    const collector = within(flow).getByRole("link", { name: "collectors" });
    expect(collector.getAttribute("href")).toBe("/help#collector");
    expect(within(flow).getByRole("link", { name: "test event" }).getAttribute("href")).toBe(
      "/help#test-event"
    );
    expect(within(flow).getByRole("link", { name: "Microsoft Sentinel" }).getAttribute("href")).toBe(
      "/help#sentinel"
    );

    fireEvent.click(collector);
    expect(await screen.findByRole("heading", { name: "Glossary" })).toBeTruthy();
    expect(document.activeElement?.id).toBe("collector");
  });

  it("labels a simulated test as not proof and a verified one as proven", async () => {
    stubHome(() =>
      json({
        ...home,
        flow: {
          ...home.flow,
          proof: {
            state: "simulated",
            message:
              "Simulated only: the last test event was not checked in Microsoft Sentinel, so it is not proof.",
            at: "2026-10-27T09:00:00Z",
            fix: { action: "Send a test event from the Setup page.", page: "/setup" }
          }
        }
      })
    );
    renderApp("/");

    const flow = await screen.findByRole("region", { name: "Is my data flowing?" });
    expect(within(flow).getByText(/Simulated only/)).toBeTruthy();
    expect(within(flow).queryByText(/Proven/)).toBeNull();
    expect(within(flow).getByRole("link", { name: /Go to Setup/ }).getAttribute("href")).toBe("/setup");
  });

  it("shows a calm empty state when nothing needs attention", async () => {
    stubHome(() =>
      json({
        ...home,
        state: "green",
        attention: [],
        groups: [home.groups[1]],
        groupsTotal: 1,
        flow: {
          ...home.flow,
          state: "green",
          summary: "Yes. All 3 collectors are checking in and sending events.",
          proof: {
            state: "verified",
            message: "Proven: Bower found a test event in Microsoft Sentinel.",
            at: "2026-10-26T09:00:00Z",
            fix: null
          }
        }
      })
    );
    renderApp("/");

    expect(await screen.findByText("Nothing needs your attention")).toBeTruthy();
    const flow = screen.getByRole("region", { name: "Is my data flowing?" });
    expect(within(flow).getByText("All good")).toBeTruthy();
    expect(within(flow).getByText(/Proven: Bower found/)).toBeTruthy();
    expect(within(flow).queryByText("How to fix:")).toBeNull();
  });

  it("states how many groups are shown when the list is truncated", async () => {
    stubHome(() => json({ ...home, groupsTotal: 60 }));
    renderApp("/");

    expect(await screen.findByText("2 of 60 shown, most urgent first")).toBeTruthy();
  });

  it("shows a loading state, then an explicit error for a refused request", async () => {
    stubHome(() => json({ error: "Forbidden." }, 403));
    renderApp("/");

    expect(screen.getByLabelText("Loading")).toBeTruthy();
    expect(await screen.findByText("Could not load this view.")).toBeTruthy();
    expect(screen.getByText("Forbidden.")).toBeTruthy();
  });

  it("keeps the last status with a notice when a refresh fails", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let calls = 0;
    const fetch = stubHome(() => (calls++ === 0 ? json(home) : json({ error: "Unavailable." }, 503)));
    renderApp("/");

    expect(await screen.findByRole("region", { name: "Is my data flowing?" })).toBeTruthy();
    await act(async () => {
      vi.advanceTimersByTime(60_000);
    });

    expect(await screen.findByText("Could not refresh.")).toBeTruthy();
    expect(screen.getByText(/Partly\. 4 of 5/)).toBeTruthy();
    expect(fetch.mock.calls.filter(([input]) => String(input).includes("/api/home"))).toHaveLength(2);
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

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

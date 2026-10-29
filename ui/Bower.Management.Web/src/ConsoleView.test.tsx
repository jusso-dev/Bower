import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { AuthenticationProvider } from "./auth";

const home = {
  generatedAt: "2026-10-29T00:00:00Z", state: "amber",
  flow: { state: "amber", summary: "No collectors reporting.", sending: 0, enrolled: 0, lastAcceptedAt: null,
    proof: { state: "not-proven", message: "Arrival has not been checked.", at: null, fix: null } },
  protection: { since: "2026-10-23T00:00:00Z", summary: "No protection counts reported.", byType: [], collectorsReporting: 0, collectorsNotReporting: 0 },
  attention: [{ id: "pending", state: "amber", message: "A collector needs approval.", count: 1,
    fix: { action: "Ask an approver to review it.", page: "/approvals" } }], groups: [], groupsTotal: 0
};
function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status }); }
function stub(user = "reader-a", roles = ["Bower.Viewer"]) {
  const fetch = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path.includes("/api/access/me")) return response({ objectId: user, roles, displayName: "Reader", developmentAuthentication: true });
    if (path.includes("/api/home")) return response(home);
    return response([]);
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
function show(path = "/help") {
  return render(<AuthenticationProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></AuthenticationProvider>);
}
beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("Console view preference", () => {
  it("defaults viewers to home, alerts and reports and gates direct technical links", async () => {
    const fetch = stub(); show("/approvals");
    expect(await screen.findByRole("heading", { name: "Technical details are hidden" })).toBeTruthy();
    const nav = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    expect(nav.getAllByRole("link").map(link => link.textContent)).toEqual(["Home", "Alerts", "Reports", "Help"]);
    expect(fetch.mock.calls.some(call => String(call[0]).includes("/api/approvals"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Show this technical page" }));
    expect(await screen.findByRole("heading", { name: "Enrollment approvals" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("persists the toggle for one user without changing another user's default", async () => {
    stub(); let rendered = show();
    fireEvent.click(await screen.findByRole("button", { name: "Show technical pages" }));
    expect(screen.getByRole("link", { name: "Pipelines" })).toBeTruthy();
    rendered.unmount(); rendered = show();
    expect(await screen.findByRole("button", { name: "Use simple view" })).toBeTruthy();
    rendered.unmount(); stub("reader-b"); show();
    expect(await screen.findByRole("button", { name: "Show technical pages" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Pipelines" })).toBeNull();
  });

  it("keeps operators in detailed view by default and lets them simplify it", async () => {
    stub("operator", ["Bower.Viewer", "Bower.Operator"]); show();
    fireEvent.click(await screen.findByRole("button", { name: "Use simple view" }));
    expect(screen.queryByRole("link", { name: "Pipelines" })).toBeNull();
    expect(localStorage.getItem("bower-console-view:development:operator")).toBe("simple");
  });

  it("shows real attention items on Alerts and bounded metadata on Reports", async () => {
    stub(); const rendered = show("/alerts");
    expect((await screen.findByRole("region", { name: "What needs my attention?" })).textContent).toContain("A collector needs approval.");
    expect(screen.queryByRole("heading", { name: "What was protected this week?" })).toBeNull();
    rendered.unmount(); show("/reports");
    expect(await screen.findByText("No protection counts reported.")).toBeTruthy();
    expect(screen.getByText("Arrival has not been checked.")).toBeTruthy();
    expect(screen.queryByText("Verified in Sentinel")).toBeNull();
    expect(screen.queryByRole("region", { name: "What needs my attention?" })).toBeNull();
  });

  it("fails closed on access errors and retries without trusting a stored preference", async () => {
    localStorage.setItem("bower-console-view:development:reader-a", "detailed");
    vi.stubGlobal("fetch", vi.fn(async () => response({ error: "Unavailable" }, 503)));
    show("/pipelines");
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByLabelText("Sample records")).toBeNull();
    stub(); fireEvent.click(screen.getByRole("button", { name: "Retry access check" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(await screen.findByText(/Viewing only. An operator/)).toBeTruthy();
    expect(screen.queryByLabelText("Sample records")).toBeNull();
  });
});

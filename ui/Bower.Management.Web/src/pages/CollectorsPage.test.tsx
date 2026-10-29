import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthenticationProvider } from "../auth";
import { CollectorDetailPage, CollectorsPage } from "./CollectorsPage";
import type { Fleet, FleetCollector } from "../types";

const pending: FleetCollector = {
  id: "edge-1", machineName: "Office collector", site: "Sydney", version: "0.1.0",
  state: "waiting-for-approval", label: "Waiting for approval", light: "amber",
  reason: "Has asked to join and is waiting for approval.",
  fix: { action: "Review the request on the Approvals page.", page: "/approvals" },
  otherIssues: 0, connectivity: "pending", path: null, lastSeenAt: "2026-10-29T00:00:00Z"
};
const relay: FleetCollector = {
  ...pending, id: "edge-2", machineName: "Branch collector", site: "Melbourne",
  state: "behind-relay", label: "Behind a relay", light: "green",
  reason: "Checking in and configured to send through a relay.", fix: null,
  path: "relay", connectivity: "connected"
};
const fleet: Fleet = {
  generatedAt: "2026-10-29T00:00:00Z", collectors: [pending, relay], newestVersion: "0.1.0",
  states: [pending, relay].map((item) => ({ state: item.state, label: item.label, light: item.light, collectors: 1 })),
  sites: [{ name: "Sydney", collectors: 1 }, { name: "Melbourne", collectors: 1 }]
};
function respond(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}
function stub(getFleet: () => Response) {
  const fetch = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(String(input), "http://localhost").pathname;
    if (path === "/api/access/me") return respond({ objectId: "viewer", roles: ["Bower.Viewer"], displayName: "Viewer", developmentAuthentication: false });
    if (path === "/api/fleet") return getFleet();
    if (path === "/api/fleet/edge-2") return respond(relay);
    if (path === "/api/collectors/edge-2") return respond({
      id: relay.id, machineName: relay.machineName, environment: relay.site,
      status: "Active", version: "0.1.0", queueDepth: 3, deadLettered: 0,
      deliveryStatus: "healthy", policyHash: "default", lastSeenAt: relay.lastSeenAt,
      sources: [{ id: "syslog", type: "syslog", status: "healthy", lastEventAt: null }],
      outputs: [{ id: "relay", type: "relay", status: "healthy", lastAcknowledgedAt: null }]
    });
    return respond({ error: "Collector not found." }, 404);
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
function show(path = "/collectors") {
  render(<AuthenticationProvider><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/collectors" element={<CollectorsPage />} />
    <Route path="/collectors/:id" element={<CollectorDetailPage />} />
  </Routes></MemoryRouter></AuthenticationProvider>);
}
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); });

describe("Plain-language fleet", () => {
  it("shows states, fixes, detail links and a separate Sentinel proof link", async () => {
    stub(() => respond(fleet)); show();
    const list = await screen.findByRole("list", { name: "Collectors by urgency" });
    expect(within(list).getByText("Waiting for approval")).toBeTruthy();
    expect(within(list).getByText("Behind a relay")).toBeTruthy();
    expect(within(list).getByRole("link", { name: "Open Approvals" }).getAttribute("href")).toBe("/approvals");
    expect(screen.getByRole("link", { name: "Check arrival in Microsoft Sentinel" }).getAttribute("href")).toBe("/setup");
    expect(screen.queryByRole("button", { name: /Approve|Suspend|Revoke/ })).toBeNull();
  });
  it("combines filters and clears an empty result", async () => {
    stub(() => respond(fleet)); show();
    await screen.findByText("Showing 2 of 2 collectors");
    fireEvent.change(screen.getByLabelText("State"), { target: { value: "behind-relay" } });
    expect(screen.getByText("Showing 1 of 2 collectors")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Site"), { target: { value: "Sydney" } });
    expect(screen.getByText("No matching collectors")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.change(screen.getByLabelText("Find a machine"), { target: { value: "EDGE-1" } });
    expect(screen.getByText("Showing 1 of 2 collectors")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Branch collector" })).toBeNull();
  });
  it("restores shared filters including a site that no longer exists", async () => {
    stub(() => respond(fleet)); show("/collectors?site=Old%20site&state=offline-site");
    await screen.findByText("No matching collectors");
    expect((screen.getByLabelText("Site") as HTMLSelectElement).value).toBe("Old site");
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByText("Showing 2 of 2 collectors")).toBeTruthy();
  });
  it("offers setup when no machine has registered", async () => {
    stub(() => respond({ ...fleet, collectors: [], states: [], sites: [] })); show();
    expect(await screen.findByText("No collectors yet")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open Setup" }).getAttribute("href")).toBe("/setup");
  });
  it("shows loading and denied access without inventing a healthy fleet", async () => {
    stub(() => respond({ error: "Forbidden." }, 403)); show();
    expect(screen.getByLabelText("Loading")).toBeTruthy();
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByText("Forbidden.")).toBeTruthy();
    expect(screen.queryByRole("list", { name: "Collectors by urgency" })).toBeNull();
  });
  it("keeps the last snapshot visibly stale when refresh fails and recovers", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let fails = false;
    const fetch = stub(() => fails ? respond({ error: "Unavailable." }, 503) : respond(fleet));
    show(); await screen.findByText("Showing 2 of 2 collectors");
    fails = true;
    await act(async () => { vi.advanceTimersByTime(60_000); });
    expect(await screen.findByText("Status may be out of date.")).toBeTruthy();
    expect(screen.getByText("Showing 2 of 2 collectors")).toBeTruthy();
    fails = false;
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await act(async () => {});
    expect(screen.queryByText("Status may be out of date.")).toBeNull();
    expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("/api/fleet"))).toHaveLength(3);
  });
  it("retries the initial failure", async () => {
    let fails = true;
    stub(() => fails ? respond({ error: "Unavailable." }, 503) : respond(fleet));
    show(); await screen.findByRole("alert");
    fails = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Showing 2 of 2 collectors")).toBeTruthy();
  });
  it("opens read-only details with sources and relay acceptance, without claiming proof", async () => {
    stub(() => respond(fleet)); show();
    fireEvent.click(await screen.findByRole("link", { name: "View details for Branch collector" }));
    expect(await screen.findByRole("region", { name: "Branch collector" })).toBeTruthy();
    expect(await screen.findByText("No acceptance reported yet", { exact: false })).toBeTruthy();
    expect(screen.getByText("Through a relay")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Configured sources" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Approve|Suspend|Revoke/ })).toBeNull();
  });
  it("handles a missing collector", async () => {
    stub(() => respond(fleet)); show("/collectors/missing");
    expect((await screen.findAllByText("Collector not found.")).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Back to collectors" })).toBeTruthy();
  });
});

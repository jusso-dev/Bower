import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import type { Home } from "../types";

describe("Alerts page mute controls", () => {
  beforeEach(() => {
    localStorage.setItem("bower-theme", "light");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("allows an Operator to mute and unmute an active alert with an audited reason", async () => {
    let muted = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path === "/api/access/me") {
        return new Response(
          JSON.stringify({
            objectId: "op-1",
            displayName: "Alex Operator",
            roles: ["Bower.Operator"],
            developmentAuthentication: true
          }),
          { status: 200 }
        );
      }
      if (path === "/api/alerts/mute" && init?.method === "POST") {
        muted = true;
        return new Response(JSON.stringify({ id: "0123456789abcdef0123456789abcdef" }), { status: 201 });
      }
      if (path === "/api/alerts/mutes/0123456789abcdef0123456789abcdef/unmute" && init?.method === "POST") {
        muted = false;
        return new Response(JSON.stringify({ id: "0123456789abcdef0123456789abcdef" }), { status: 200 });
      }
      if (path === "/api/home") {
        const home: Home = {
          generatedAt: "2026-11-22T00:00:00Z",
          state: "red",
          flow: {
            state: "red",
            summary: "No. Your collector is not sending events right now.",
            sending: 0,
            enrolled: 1,
            lastAcceptedAt: null,
            proof: {
              state: "verified",
              message: "Proven: Bower found a test event in Microsoft Sentinel.",
              at: "2026-11-22T00:00:00Z",
              fix: null
            }
          },
          protection: {
            since: "2026-11-16T00:00:00Z",
            summary: "Bower removed sensitive details.",
            byType: [],
            collectorsReporting: 1,
            collectorsNotReporting: 0
          },
          attention: [
            {
              id: "offline",
              state: "red",
              message: "1 collector has not checked in for more than 15 minutes.",
              fix: { action: "Check that the machine is switched on and can reach Bower.", page: "/collectors" },
              count: 1,
              muted,
              muteId: muted ? "0123456789abcdef0123456789abcdef" : null,
              mutedUntil: muted ? "2026-11-22T04:00:00Z" : null,
              muteReason: muted ? "Planned host maintenance" : null
            }
          ],
          groups: [],
          groupsTotal: 0
        };
        return new Response(JSON.stringify(home), { status: 200 });
      }
      return new Response("Not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <AuthenticationProvider>
        <MemoryRouter initialEntries={["/alerts"]}>
          <App />
        </MemoryRouter>
      </AuthenticationProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Mute alert" })).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Mute alert" }));
    fireEvent.change(screen.getByLabelText("Reason for muting (audited)"), {
      target: { value: "Planned host maintenance" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm mute" }));

    await waitFor(() => {
      expect(screen.getByText(/Mute reason: Planned host maintenance/i)).toBeTruthy();
      expect(screen.getByRole("button", { name: "Unmute notifications" })).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Unmute notifications" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Mute alert" })).toBeTruthy();
    });
  });
});

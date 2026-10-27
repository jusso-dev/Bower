import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";

const token = {
  id: "0123456789abcdef",
  environment: "production",
  collectorId: null,
  status: "active",
  reason: "New gateway",
  createdByObjectId: "object-1",
  createdByName: "Morgan Lee",
  createdAt: "2026-10-27T00:00:00Z",
  expiresAt: "2026-10-28T00:00:00Z",
  usedAt: null,
  usedByCollectorId: null,
  revokedAt: null
};

const credential = {
  id: "fedcba9876543210",
  collectorId: "edge-onprem-01",
  status: "active",
  origin: "enrolment",
  issuedAt: "2026-10-27T00:00:00Z",
  expiresAt: "2026-11-26T00:00:00Z",
  lastUsedAt: "2026-10-27T00:05:00Z",
  endedAt: null
};

const secret = "bwe1.0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("Token enrolment page", () => {
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
    localStorage.clear();
    sessionStorage.clear();
  });

  it("shows a created token once and never stores it in the browser", async () => {
    const fetchMock = stubApi({ roles: ["Bower.Administrator"], tokens: [], credentials: [] });

    renderApp("/enrolment");
    fireEvent.change(await screen.findByLabelText("Environment"), {
      target: { value: "production" }
    });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "New gateway" } });
    fireEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(await screen.findByText(secret)).toBeTruthy();
    expect(screen.getByText(/Shown once/)).toBeTruthy();
    const create = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith("/api/enrolment-tokens") &&
        (init as RequestInit | undefined)?.method === "POST"
    );
    expect(JSON.parse(String((create?.[1] as RequestInit).body))).toEqual({
      environment: "production",
      reason: "New gateway",
      collectorId: null,
      expiresInHours: 24
    });
    expect(JSON.stringify({ ...localStorage })).not.toContain(secret);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(secret);

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByText(secret)).toBeNull());
  });

  it("lists metadata read-only for viewers", async () => {
    stubApi({ roles: ["Bower.Viewer"], tokens: [token], credentials: [credential] });

    renderApp("/enrolment");

    expect(await screen.findByText("0123456789abcdef")).toBeTruthy();
    expect(await screen.findByText("fedcba9876543210")).toBeTruthy();
    expect(screen.getByText(/Viewing only/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("revokes a credential with a reason", async () => {
    const fetchMock = stubApi({
      roles: ["Bower.Administrator"],
      tokens: [],
      credentials: [credential]
    });

    renderApp("/enrolment");
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    fireEvent.change(screen.getByLabelText("Revocation reason"), {
      target: { value: "Host decommissioned" }
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Revoke" }).find(
        (button) => button.getAttribute("type") === "submit"
      )!
    );

    expect(await screen.findByText(/next heartbeat is refused/)).toBeTruthy();
    const revoke = fetchMock.mock.calls.find(([input]) =>
      String(input).endsWith("/api/collectors/edge-onprem-01/credentials/fedcba9876543210/revoke")
    );
    expect(JSON.parse(String((revoke?.[1] as RequestInit).body))).toEqual({
      reason: "Host decommissioned"
    });
  });

  it("renders empty states without inventing data", async () => {
    stubApi({ roles: ["Bower.Viewer"], tokens: [], credentials: [] });

    renderApp("/enrolment");

    expect(await screen.findByText("No enrolment tokens")).toBeTruthy();
    expect(await screen.findByText("No collector credentials")).toBeTruthy();
  });
});

function stubApi({
  roles,
  tokens,
  credentials
}: {
  roles: string[];
  tokens: unknown[];
  credentials: unknown[];
}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/revoke") && init?.method === "POST") {
      return json({ ...credential, status: "revoked" });
    }
    if (path.endsWith("/api/enrolment-tokens") && init?.method === "POST") {
      return json({ token: secret, record: token }, 201);
    }
    if (path.includes("/api/enrolment-tokens")) {
      return json(tokens);
    }
    if (path.includes("/api/collector-credentials")) {
      return json(credentials);
    }
    return json({
      objectId: "object-1",
      displayName: "Morgan Lee",
      roles,
      developmentAuthentication: false
    });
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

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

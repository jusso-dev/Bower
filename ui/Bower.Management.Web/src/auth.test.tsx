import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { PropsWithChildren } from "react";
import { afterEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  configuration: { current: null as unknown },
  initialize: vi.fn(async () => undefined),
  loginPopup: vi.fn(async () => ({ account: { username: "fixture" } })),
  logoutPopup: vi.fn(async () => undefined),
  acquireTokenSilent: vi.fn(),
  acquireTokenPopup: vi.fn(async () => ({ accessToken: "synthetic-test-token" })),
  setActiveAccount: vi.fn(),
  getActiveAccount: vi.fn(() => ({ username: "fixture", name: "Fixture" }))
}));

vi.mock("./runtimeConfig", () => ({ bowerConfig: {
  authMode: "entra", entraTenantId: "tenant", entraClientId: "client", entraApiScope: "scope"
} }));
vi.mock("@azure/msal-browser", () => ({
  InteractionRequiredAuthError: class extends Error {},
  PublicClientApplication: class {
    constructor(config: unknown) { mocks.configuration.current = config; }
    initialize = mocks.initialize;
  }
}));
vi.mock("@azure/msal-react", () => ({
  MsalProvider: ({ children }: PropsWithChildren) => children,
  useMsal: () => ({ instance: mocks, accounts: [] })
}));

import { InteractionRequiredAuthError } from "@azure/msal-browser";
import { AuthenticationProvider, initializeAuthentication, useAuth } from "./auth";

afterEach(cleanup);

function Controls() {
  const auth = useAuth();
  return <>
    <button onClick={() => void auth.signIn()}>Sign in</button>
    <button onClick={() => void auth.signOut()}>Sign out</button>
    <button onClick={() => void auth.getAccessToken()}>Acquire</button>
  </>;
}

it("keeps tokens in memory and uses popup interactions without redirect persistence", async () => {
  await initializeAuthentication();
  expect(mocks.configuration.current).toEqual(expect.objectContaining({ cache: { cacheLocation: "memoryStorage" } }));
  mocks.acquireTokenSilent.mockRejectedValueOnce(new InteractionRequiredAuthError("interaction_required", "fixture"));
  render(<AuthenticationProvider><Controls /></AuthenticationProvider>);
  fireEvent.click(screen.getByText("Sign in"));
  await waitFor(() => expect(mocks.setActiveAccount).toHaveBeenCalled());
  fireEvent.click(screen.getByText("Acquire"));
  await waitFor(() => expect(mocks.acquireTokenPopup).toHaveBeenCalled());
  fireEvent.click(screen.getByText("Sign out"));
  await waitFor(() => expect(mocks.logoutPopup).toHaveBeenCalled());
  expect(sessionStorage.getItem("synthetic-test-token")).toBeNull();
  expect(localStorage.getItem("synthetic-test-token")).toBeNull();
});

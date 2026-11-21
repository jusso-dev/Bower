import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";

describe("PoliciesPage", () => {
  beforeEach(() => {
    localStorage.setItem("bower-theme", "light");
    localStorage.setItem("bower-console-view", "detailed");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("changes a policy decision to aggregate with suppression and displays redacted preview and diff", async () => {
    const initialYaml = "apiVersion: bower.security/v1\nkind: TelemetryPolicy\n";
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
      if (path === "/api/policies/templates") {
        return new Response(
          JSON.stringify([
            {
              id: "authentication-failure",
              title: "Authentication failures",
              description: "Auth failures",
              content: initialYaml
            }
          ]),
          { status: 200 }
        );
      }
      if (path === "/api/policies/form" && init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { form: { action?: string } | null };
        const action = body.form?.action ?? "accept";
        return new Response(
          JSON.stringify({
            form: {
              id: "BWR-POL-AUTH-FAILURE",
              name: "Authentication failures",
              version: action === "aggregate" ? "1.1.0" : "1.0.0",
              owner: "Security Operations",
              eventCategories: ["authentication"],
              eventTypes: ["authentication_failure"],
              requiredFields: ["timeGenerated", "eventType", "eventResult", "application.name"],
              atLeastOne: ["actor.username"],
              recommendedFields: ["source.ipAddress"],
              action,
              minimumValueScore: 70,
              neverSample: action !== "aggregate",
              suppression: {
                enabled: action === "aggregate",
                keyFields: ["application.name", "eventType", "source.ipAddress"],
                windowSeconds: 60,
                allowPerWindow: 0
              }
            },
            content: `${initialYaml}decision:\n  action: ${action}\n`,
            valid: true,
            errors: [],
            policyHash: action === "aggregate" ? "sha256:bbbbbbbbbbbbbbbbbbbb" : "sha256:aaaaaaaaaaaaaaaaaaaa",
            diff: {
              beforeHash: "sha256:aaaaaaaaaaaaaaaaaaaa",
              afterHash: action === "aggregate" ? "sha256:bbbbbbbbbbbbbbbbbbbb" : "sha256:aaaaaaaaaaaaaaaaaaaa",
              semanticallyIdentical: action !== "aggregate",
              changes:
                action === "aggregate"
                  ? [{ change: "action-changed", detail: "Decision action changes from accept to aggregate." }]
                  : []
            },
            preview: {
              valid: true,
              beforeDecision: "accept",
              afterDecision: action,
              valueScore: 80,
              redactedEventJson: JSON.stringify({ eventType: "authentication_failure", attributes: { note: "Synthetic preview only" } }),
              findings: [{ detectorId: "au.tfn", action: "Mask", path: "attributes.tfn" }]
            }
          }),
          { status: 200 }
        );
      }
      return new Response("Not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <AuthenticationProvider>
        <MemoryRouter initialEntries={["/policies"]}>
          <App />
        </MemoryRouter>
      </AuthenticationProvider>
    );

    await waitFor(() => {
      expect(screen.getByLabelText("Decision action")).toBeTruthy();
    });

    fireEvent.change(screen.getByLabelText("Decision action"), {
      target: { value: "aggregate" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Preview & diff" }));

    await waitFor(() => {
      expect(screen.getByText(/Decision action changes from accept to aggregate/i)).toBeTruthy();
      expect(screen.getByLabelText("Redacted sample event")).toBeTruthy();
    });
  });
});

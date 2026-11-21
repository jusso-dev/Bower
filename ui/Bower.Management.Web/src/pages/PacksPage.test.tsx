import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import type { PackGalleryResponse, PackInstallRequestRecord } from "../types";

const galleryFixture: PackGalleryResponse = {
  configured: true,
  trustedKeyCount: 1,
  packs: [
    {
      trusted: true,
      fileName: "linux-ssh-gateway-1.0.0.bowerpack",
      id: "linux-ssh-gateway",
      version: "1.0.0",
      name: "Linux SSH Gateway",
      description: "Captures SSH authentication successes and failures.",
      owner: "platform-security",
      builtAtUtc: "2026-11-20T00:00:00Z",
      packHash: "abcdef0123456789abcdef0123456789",
      signedByKeyId: "key-prod-1",
      eventTypes: ["auth.ssh.failed", "auth.ssh.succeeded"],
      policies: [
        {
          id: "ssh-auth",
          version: "1.0.0",
          action: "accept",
          eventTypes: ["auth.ssh.failed", "auth.ssh.succeeded"],
          hash: "111122223333"
        }
      ],
      redactions: ["Default Australian privacy policy."],
      detectionCount: 1,
      parserCount: 1,
      sampleResults: [
        {
          name: "ssh-failed-login",
          passed: true,
          expectedDecision: "accept",
          actualDecision: "accept",
          problems: []
        }
      ],
      refusalReason: null
    },
    {
      trusted: false,
      fileName: "untrusted-evil-1.0.0.bowerpack",
      id: null,
      version: null,
      name: null,
      description: null,
      owner: null,
      builtAtUtc: null,
      packHash: null,
      signedByKeyId: null,
      eventTypes: [],
      policies: [],
      redactions: [],
      detectionCount: 0,
      parserCount: 0,
      sampleResults: [],
      refusalReason: "Pack signature is invalid or not from a trusted key."
    }
  ],
  groups: [
    {
      environment: "production",
      eligibleCollectors: 2,
      collectorIds: ["col-prod-1", "col-prod-2"]
    }
  ]
};

describe("PacksPage", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    localStorage.setItem("bower-theme", "light");
    localStorage.setItem("bower-console-view", "detailed");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    fetchMock.mockReset();
    localStorage.clear();
  });

  it("shows trusted packs, surfaces untrusted refusal reasons, and submits a group install with population diff", async () => {
    const createdRequest: PackInstallRequestRecord = {
      id: "0123456789abcdef0123456789abcdef",
      packId: "linux-ssh-gateway",
      packVersion: "1.0.0",
      packName: "Linux SSH Gateway",
      packHash: "abcdef0123456789abcdef0123456789",
      signedByKeyId: "key-prod-1",
      targetEnvironment: "production",
      targetCollectorId: null,
      status: "pending-review",
      diff: {
        packId: "linux-ssh-gateway",
        packVersion: "1.0.0",
        packHash: "abcdef0123456789abcdef0123456789",
        eventTypesAdded: ["auth.ssh.failed", "auth.ssh.succeeded"],
        policyChanges: [],
        affectedCollectors: [
          {
            collectorId: "col-prod-1",
            machineName: "prod-1",
            environment: "production",
            currentPolicyHash: "old-hash",
            currentDesiredPolicyHash: null,
            targetPolicyHash: "abcdef0123456789abcdef0123456789",
            alreadyAssigned: false
          },
          {
            collectorId: "col-prod-2",
            machineName: "prod-2",
            environment: "production",
            currentPolicyHash: "old-hash",
            currentDesiredPolicyHash: null,
            targetPolicyHash: "abcdef0123456789abcdef0123456789",
            alreadyAssigned: false
          }
        ]
      },
      reason: "Roll out SSH pack to production",
      requestedByObjectId: "op-1",
      requestedByName: "Alex Operator",
      requestedAt: "2026-11-22T00:00:00Z",
      reviewerName: null,
      reviewedAt: null,
      reviewReason: null
    };

    const installRequests: PackInstallRequestRecord[] = [];
    fetchMock.mockImplementation((input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/access/me")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              objectId: "op-1",
              displayName: "Alex Operator",
              roles: ["Bower.Operator"],
              developmentAuthentication: true
            }),
            { status: 200 }
          )
        );
      }
      if (url.endsWith("/api/packs")) {
        return Promise.resolve(new Response(JSON.stringify(galleryFixture), { status: 200 }));
      }
      if (url.endsWith("/api/packs/install-requests") && init?.method === "POST") {
        installRequests.push(createdRequest);
        return Promise.resolve(new Response(JSON.stringify(createdRequest), { status: 201 }));
      }
      if (url.endsWith("/api/packs/install-requests")) {
        return Promise.resolve(new Response(JSON.stringify(installRequests), { status: 200 }));
      }
      return Promise.resolve(new Response("Not found", { status: 404 }));
    });

    render(
      <AuthenticationProvider>
        <MemoryRouter initialEntries={["/packs"]}>
          <App />
        </MemoryRouter>
      </AuthenticationProvider>
    );

    await waitFor(() => {
      expect(screen.getByText("Linux SSH Gateway")).toBeTruthy();
    });

    // Untrusted pack is clearly refused with server reason.
    expect(screen.getByText("untrusted-evil-1.0.0.bowerpack")).toBeTruthy();
    expect(
      screen.getByText("Pack signature is invalid or not from a trusted key.")
    ).toBeTruthy();

    // Under-5-clicks install to collector group with population diff preview.
    fireEvent.click(screen.getByRole("button", { name: "Install to group" }));
    expect(screen.getByText(/Population diff preview/i)).toBeTruthy();
    expect(screen.getByText(/2 collectors in/i)).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Reason for change"), {
      target: { value: "Roll out SSH pack to production" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit for approval" }));

    await waitFor(() => {
      expect(screen.getByText(/Pack install submitted for approval/i)).toBeTruthy();
    });
  });
});

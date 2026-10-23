import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";

const approvedContent = `apiVersion: bower.security/v1
kind: PrivacyProfile
metadata:
  id: contoso-hr
  version: 1.0.0
`;

const pendingContent = `apiVersion: bower.security/v1
kind: PrivacyProfile
metadata:
  id: contoso-hr
  version: 1.1.0
customDetectors:
  - id: custom.employee-id
`;

const approvedSummary = {
  id: "a".repeat(32),
  profileId: "contoso-hr",
  version: "1.0.0",
  description: null,
  contentHash: "sha256:1111",
  changeSummary: "Initial privacy profile",
  status: "Approved",
  authorName: "Alex Author",
  createdAt: "2026-10-20T01:00:00Z",
  reviewerName: "Riley Reviewer",
  reviewedAt: "2026-10-20T02:00:00Z",
  reviewReason: "Looks right",
  assignedCollectors: 1
};

const pendingSummary = {
  ...approvedSummary,
  id: "b".repeat(32),
  version: "1.1.0",
  contentHash: "sha256:2222",
  changeSummary: "Mask employee ids",
  status: "PendingReview",
  createdAt: "2026-10-23T01:00:00Z",
  reviewerName: null,
  reviewedAt: null,
  reviewReason: null,
  assignedCollectors: 0
};

const details: Record<string, unknown> = {
  [approvedSummary.id]: {
    ...approvedSummary,
    content: approvedContent,
    authorObjectId: "author-oid",
    previousApprovedVersionId: null
  },
  [pendingSummary.id]: {
    ...pendingSummary,
    content: pendingContent,
    authorObjectId: "author-oid",
    previousApprovedVersionId: approvedSummary.id
  }
};

const baseCollector = {
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
  outputs: []
};

const desired = {
  versionId: approvedSummary.id,
  profileId: "contoso-hr",
  version: "1.0.0",
  contentHash: "sha256:1111"
};

const collectors = [
  {
    ...baseCollector,
    id: "finance-prod-01",
    desiredPrivacyProfile: desired,
    reportedPrivacyProfileHash: "sha256:1111",
    privacyProfileInSync: true
  },
  {
    ...baseCollector,
    id: "claims-prod-03",
    machineName: "claims-api-03",
    desiredPrivacyProfile: desired,
    reportedPrivacyProfileHash: "default",
    privacyProfileInSync: false
  },
  {
    ...baseCollector,
    id: "records-prod-04",
    machineName: "records-app-04",
    desiredPrivacyProfile: null,
    reportedPrivacyProfileHash: null,
    privacyProfileInSync: null
  },
  {
    ...baseCollector,
    id: "retired-01",
    machineName: "retired-app-01",
    status: "Revoked"
  }
];

const assignmentHistory = [
  {
    id: 7,
    collectorId: "finance-prod-01",
    versionId: approvedSummary.id,
    profileId: "contoso-hr",
    version: "1.0.0",
    action: "assigned",
    reason: "Roll out HR masking",
    actorName: "Ada Admin",
    occurredAt: "2026-10-21T01:00:00Z"
  }
];

type Handler = (path: string, init: RequestInit | undefined) => Response | undefined;

function stubApi({
  roles,
  objectId = "viewer-oid",
  versions = [pendingSummary, approvedSummary],
  handler
}: {
  roles: string[];
  objectId?: string;
  versions?: unknown[];
  handler?: Handler;
}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://localhost").pathname;
    const custom = handler?.(path, init);
    if (custom) {
      return custom;
    }
    const method = init?.method ?? "GET";
    if (path === "/api/access/me") {
      return json({ objectId, displayName: "Morgan Lee", roles, developmentAuthentication: false });
    }
    if (path === "/api/privacy-profiles" && method === "GET") {
      return json(versions);
    }
    if (path === "/api/privacy-profiles/assignments") {
      return json(assignmentHistory);
    }
    if (path.startsWith("/api/privacy-profiles/versions/") && method === "GET") {
      const id = path.split("/").pop() ?? "";
      return details[id] ? json(details[id]) : new Response(null, { status: 404 });
    }
    if (path === "/api/collectors") {
      return json(collectors);
    }
    return new Response(JSON.stringify({ error: `Unexpected ${method} ${path}` }), {
      status: 500
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function postsTo(fetchMock: ReturnType<typeof stubApi>, path: string) {
  return fetchMock.mock.calls
    .filter(
      ([input, init]) =>
        new URL(String(input), "http://localhost").pathname === path &&
        (init as RequestInit | undefined)?.method === "POST"
    )
    .map(([, init]) => JSON.parse(String((init as RequestInit).body)) as unknown);
}

describe("Privacy profiles page", () => {
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

  it("shows a loading state before data arrives", () => {
    stubApi({ roles: ["Bower.Viewer"] });
    renderApp("/privacy-profiles");
    expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
  });

  it("groups versions by privacy profile with status, author and assignments", async () => {
    stubApi({ roles: ["Bower.Viewer"] });
    renderApp("/privacy-profiles");

    const group = await screen.findByRole("region", { name: "contoso-hr" });
    expect(within(group).getByText("2 versions")).toBeTruthy();
    expect(within(group).getByRole("button", { name: "1.1.0" })).toBeTruthy();
    expect(within(group).getByText("Pending review")).toBeTruthy();
    expect(within(group).getByText("Approved")).toBeTruthy();
    expect(within(group).getByText("Riley Reviewer")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Privacy profiles" })).toBeTruthy();
  });

  it("renders empty states without inventing data", async () => {
    stubApi({
      roles: ["Bower.Viewer"],
      versions: [],
      handler: (path) => (path === "/api/privacy-profiles/assignments" ? json([]) : undefined)
    });
    renderApp("/privacy-profiles");

    expect(await screen.findByText("No privacy profile versions")).toBeTruthy();
    expect(await screen.findByText("No assignments recorded")).toBeTruthy();
  });

  it("reports API errors verbatim", async () => {
    stubApi({
      roles: ["Bower.Viewer"],
      handler: (path, init) =>
        path === "/api/privacy-profiles" && !init?.method
          ? new Response(JSON.stringify({ error: "Privacy profile store unavailable." }), {
              status: 500
            })
          : undefined
    });
    renderApp("/privacy-profiles");

    expect(await screen.findByText("Privacy profile store unavailable.")).toBeTruthy();
    expect(screen.getAllByText("Could not load this view.").length).toBeGreaterThan(0);
  });

  it("shows an unauthorized response instead of stale data", async () => {
    stubApi({
      roles: [],
      handler: (path) =>
        path.startsWith("/api/privacy-profiles") || path === "/api/collectors"
          ? new Response(JSON.stringify({ title: "Forbidden" }), { status: 403 })
          : undefined
    });
    renderApp("/privacy-profiles");

    expect((await screen.findAllByText("Forbidden")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "1.1.0" })).toBeNull();
  });

  it("keeps a viewer read-only for submit and review", async () => {
    stubApi({ roles: ["Bower.Viewer"] });
    renderApp(`/privacy-profiles?version=${pendingSummary.id}`);

    expect(await screen.findByText(/required to\s+submit a privacy profile version/)).toBeTruthy();
    expect(
      await screen.findByText(/required to approve or reject a privacy profile version/)
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Submit new version" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("lets an operator submit but not review or assign", async () => {
    stubApi({ roles: ["Bower.Operator"] });
    renderApp(`/privacy-profiles?version=${approvedSummary.id}`);

    expect(await screen.findByRole("button", { name: "Submit new version" })).toBeTruthy();
    expect(await screen.findByText(/required to\s+assign this version to collectors/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Assign to collectors" })).toBeNull();
  });

  it("tells the author they cannot review their own version", async () => {
    stubApi({ roles: ["Bower.Approver"], objectId: "author-oid" });
    renderApp(`/privacy-profiles?version=${pendingSummary.id}`);

    expect(
      await screen.findByText("You authored this version. Another approver must review it.")
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("validates, previews and submits a new version", async () => {
    const fetchMock = stubApi({
      roles: ["Bower.Operator"],
      handler: (path, init) => {
        if (init?.method !== "POST") return undefined;
        if (path === "/api/privacy-profiles/validate") {
          return json({
            valid: true,
            errors: [],
            profileId: "contoso-hr",
            version: "1.2.0",
            contentHash: "sha256:3333",
            customDetectors: [
              { id: "custom.employee-id", description: "Employee numbers", action: "mask" }
            ],
            secretFieldNames: 2,
            detectorOverrides: 0,
            fieldRules: 1
          });
        }
        if (path === "/api/privacy-profiles/preview") {
          return json({
            valid: true,
            errors: [],
            redacted: '{"message":"user [redacted] logged in"}',
            findings: [{ detectorId: "custom.employee-id", action: "mask", path: "message" }]
          });
        }
        if (path === "/api/privacy-profiles") {
          return json({ ...details[pendingSummary.id] as object, id: "c".repeat(32), version: "1.2.0" }, 201);
        }
        return undefined;
      }
    });
    renderApp("/privacy-profiles");

    await screen.findByRole("button", { name: "1.1.0" });
    fireEvent.click(await screen.findByRole("button", { name: "Submit new version" }));
    const editor = (await screen.findByLabelText("Privacy profile YAML")) as HTMLTextAreaElement;
    // Prefilled from the latest version.
    await waitFor(() => expect(editor.value).toBe(pendingContent));
    expect(screen.getByText("Custom detector YAML")).toBeTruthy();
    expect(screen.getByText("docs/privacy/custom-redaction-rules.md")).toBeTruthy();

    const content = pendingContent.replace("1.1.0", "1.2.0");
    fireEvent.change(editor, { target: { value: content } });
    fireEvent.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText("Validation passed")).toBeTruthy();
    expect(screen.getByText("custom.employee-id")).toBeTruthy();
    expect(postsTo(fetchMock, "/api/privacy-profiles/validate")).toEqual([{ content }]);

    const sample = '{"message":"user EMP-123456 logged in"}';
    fireEvent.change(screen.getByLabelText("Preview sample (JSON event)"), {
      target: { value: sample }
    });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    expect(await screen.findByText('{"message":"user [redacted] logged in"}')).toBeTruthy();
    expect(screen.getByText("message")).toBeTruthy();
    expect(postsTo(fetchMock, "/api/privacy-profiles/preview")).toEqual([{ content, sample }]);

    fireEvent.change(screen.getByLabelText("Change summary"), {
      target: { value: "  Add employee id masking  " }
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit for review" }));
    expect(await screen.findByText(/Submitted contoso-hr@1.2.0 for review/)).toBeTruthy();
    expect(postsTo(fetchMock, "/api/privacy-profiles")).toEqual([
      { content, changeSummary: "Add employee id masking" }
    ]);
  });

  it("shows validation errors from the API", async () => {
    stubApi({
      roles: ["Bower.Operator"],
      versions: [],
      handler: (path) =>
        path === "/api/privacy-profiles/validate"
          ? json({
              valid: false,
              errors: ["Custom detector 'custom.x' did not match tests.match[0]."],
              profileId: null,
              version: null,
              contentHash: null,
              customDetectors: [],
              secretFieldNames: 0,
              detectorOverrides: 0,
              fieldRules: 0
            })
          : undefined
    });
    renderApp("/privacy-profiles");

    await screen.findByText("No privacy profile versions");
    fireEvent.click(await screen.findByRole("button", { name: "Submit new version" }));
    fireEvent.click(await screen.findByRole("button", { name: "Validate" }));
    expect(
      await screen.findByText("Custom detector 'custom.x' did not match tests.match[0].")
    ).toBeTruthy();
  });

  it("renders a line diff against the previous approved version", async () => {
    stubApi({ roles: ["Bower.Viewer"] });
    renderApp(`/privacy-profiles?version=${pendingSummary.id}`);

    const diff = await screen.findByRole("region", { name: "Line diff" });
    expect(screen.getByText("3 lines added, 1 line removed.")).toBeTruthy();
    expect(within(diff).getByText("version: 1.0.0")).toBeTruthy();
    expect(within(diff).getByText("version: 1.1.0")).toBeTruthy();
    expect(within(diff).getAllByText("Added:").length).toBe(3);
  });

  it("records approve and reject decisions and shows 409 errors verbatim", async () => {
    const fetchMock = stubApi({
      roles: ["Bower.Approver"],
      handler: (path) => {
        if (path.endsWith("/approve")) {
          return json({ ...details[pendingSummary.id] as object, status: "Approved" });
        }
        if (path.endsWith("/reject")) {
          return new Response(
            JSON.stringify({ error: "The author of a privacy profile version cannot review it." }),
            { status: 409 }
          );
        }
        return undefined;
      }
    });
    renderApp(`/privacy-profiles?version=${pendingSummary.id}`);

    fireEvent.change(await screen.findByLabelText("Decision reason"), {
      target: { value: "Diff reviewed" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(
      await screen.findByText("The author of a privacy profile version cannot review it.")
    ).toBeTruthy();
    expect(postsTo(fetchMock, `/api/privacy-profiles/versions/${pendingSummary.id}/reject`)).toEqual([
      { reason: "Diff reviewed" }
    ]);

    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(await screen.findByText("Approved contoso-hr@1.1.0.")).toBeTruthy();
    expect(postsTo(fetchMock, `/api/privacy-profiles/versions/${pendingSummary.id}/approve`)).toEqual([
      { reason: "Diff reviewed" }
    ]);
  });

  it("assigns an approved version per collector and reports each result", async () => {
    const fetchMock = stubApi({
      roles: ["Bower.Administrator"],
      handler: (path) => {
        if (path === "/api/collectors/finance-prod-01/privacy-profile") {
          return json(collectors[0]);
        }
        if (path === "/api/collectors/claims-prod-03/privacy-profile") {
          return new Response(JSON.stringify({ error: "Collector cannot be assigned." }), {
            status: 409
          });
        }
        return undefined;
      }
    });
    renderApp(`/privacy-profiles?version=${approvedSummary.id}`);

    const form = await screen.findByRole("form", { name: "Assign to collectors" });
    expect(within(form).queryByText("retired-app-01")).toBeNull();
    fireEvent.click(within(form).getByRole("checkbox", { name: /finance-app-01/ }));
    fireEvent.click(within(form).getByRole("checkbox", { name: /claims-api-03/ }));
    fireEvent.change(within(form).getByLabelText("Assignment reason"), {
      target: { value: "Roll out" }
    });
    fireEvent.click(within(form).getByRole("button", { name: "Assign to collectors" }));

    expect(await screen.findByText(/Assigned contoso-hr@1.0.0 to 1 of 2 collectors/)).toBeTruthy();
    expect(await screen.findByText(/Collector cannot be assigned\./)).toBeTruthy();
    const body = { versionId: approvedSummary.id, reason: "Roll out" };
    expect(postsTo(fetchMock, "/api/collectors/finance-prod-01/privacy-profile")).toEqual([body]);
    expect(postsTo(fetchMock, "/api/collectors/claims-prod-03/privacy-profile")).toEqual([body]);
  });

  it("clears an assignment with a reason for administrators only", async () => {
    const fetchMock = stubApi({
      roles: ["Bower.Administrator"],
      handler: (path) =>
        path === "/api/collectors/claims-prod-03/privacy-profile/clear"
          ? json(collectors[1])
          : undefined
    });
    renderApp("/privacy-profiles");

    const form = await screen.findByRole("form", { name: "Clear assignment" });
    const select = within(form).getByLabelText("Collector");
    expect(within(select).queryByText(/records-app-04/)).toBeNull();
    fireEvent.change(select, { target: { value: "claims-prod-03" } });
    fireEvent.change(within(form).getByLabelText("Clear reason"), {
      target: { value: "Roll back" }
    });
    fireEvent.click(within(form).getByRole("button", { name: "Clear assignment" }));

    expect(await screen.findByText(/Cleared the privacy profile assignment on claims-api-03/)).toBeTruthy();
    expect(postsTo(fetchMock, "/api/collectors/claims-prod-03/privacy-profile/clear")).toEqual([
      { reason: "Roll back" }
    ]);
  });

  it("hides clear assignment from non-administrators", async () => {
    stubApi({ roles: ["Bower.Approver"] });
    renderApp("/privacy-profiles");

    expect(await screen.findByText("In sync · contoso-hr@1.0.0")).toBeTruthy();
    expect(screen.queryByRole("form", { name: "Clear assignment" })).toBeNull();
  });

  it("labels collector privacy profile sync state and assignment history", async () => {
    stubApi({ roles: ["Bower.Viewer"] });
    renderApp("/privacy-profiles");

    expect(await screen.findByText("In sync · contoso-hr@1.0.0")).toBeTruthy();
    expect(screen.getByText("Drift · contoso-hr@1.0.0 · running default")).toBeTruthy();
    expect(screen.getAllByText("Unassigned").length).toBeGreaterThan(0);
    expect(await screen.findByText("Roll out HR masking")).toBeTruthy();
    expect(screen.getByText("Ada Admin")).toBeTruthy();
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

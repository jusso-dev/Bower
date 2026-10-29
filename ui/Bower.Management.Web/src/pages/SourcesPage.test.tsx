import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { AuthenticationProvider } from "../auth";
import type {
  Collector,
  SourceSetupPlanResult,
  SourceSetupRequestDetail,
  SourceSetupStatusCheck,
  SourceTypeDefinition
} from "../types";

const types: SourceTypeDefinition[] = [
  {
    id: "syslog",
    title: "Syslog",
    summary: "Network appliances send syslog to a listener on the collector.",
    why: "Syslog carries sign-in failures from systems that cannot run an SDK.",
    needs: ["An approved collector that loads the signed pack."],
    fields: [
      {
        id: "protocol",
        label: "Protocol",
        kind: "choice",
        required: true,
        help: "TLS works across the network.",
        defaultValue: "tls",
        options: [
          { value: "tls", label: "TLS (recommended)" },
          { value: "udp", label: "UDP, this host only" }
        ],
        maximumLength: 8,
        keyVaultAllowed: false
      },
      {
        id: "allowedSenders",
        label: "Allowed senders",
        kind: "address-list",
        required: true,
        help: "IP addresses or CIDR ranges that may connect.",
        maximumLength: 4096,
        keyVaultAllowed: false
      },
      {
        id: "privateKeyFile",
        label: "Server private key file",
        kind: "secret-reference",
        required: true,
        help: "Path of the PEM private key on the collector host.",
        maximumLength: 260,
        keyVaultAllowed: false,
        shownWhenField: "protocol",
        shownWhenValues: ["tls"]
      },
      {
        id: "port",
        label: "Port",
        kind: "number",
        required: true,
        help: "1 to 65535.",
        defaultValue: "6514",
        minimum: 1,
        maximum: 65535,
        maximumLength: 5,
        keyVaultAllowed: false
      }
    ],
    checkDescription: "Bower watches the collector's heartbeat for the application.",
    guide: "docs/deployment/syslog-source.md"
  },
  {
    id: "ama",
    title: "Azure Monitor Agent",
    summary: "Switches delivery to files AMA collects.",
    why: "Some estates allow only AMA.",
    needs: ["AMA on the collector host."],
    fields: [],
    checkDescription: "Bower watches the ama-spool output.",
    guide: "docs/deployment/ama-companion.md"
  }
];

const collectors: Partial<Collector>[] = [
  { id: "edge-01", machineName: "edge-gw-01", environment: "production", status: "Active" },
  { id: "new-02", machineName: "new-02", environment: "production", status: "Pending" }
];

const plan = {
  files: [
    {
      name: "syslog.json",
      installPath: "/etc/bower/syslog.json",
      description: "The syslog listener.",
      content: '{\n  "kind": "SyslogSource"\n}\n'
    }
  ],
  variables: [{ component: "collector", name: "BOWER_SYSLOG_CONFIG", value: "/etc/bower/syslog.json" }],
  snippets: [{ title: "Sender: rsyslog", description: "Add this to the sender.", language: "rsyslog", content: "action(type=\"omfwd\")\n" }],
  verification: { kind: "source" as const, reportId: "ssh-gateway/production", description: "The heartbeat reports ssh-gateway/production." },
  contentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
};

const validPlan: SourceSetupPlanResult = {
  valid: true,
  checks: [{ id: "values", state: "pass", message: "Every setting is valid.", fix: null }],
  plan,
  preview: {
    valid: true,
    redacted: '{"actor":{"username":"[REDACTED:id.email]"}}',
    findings: [{ detectorId: "id.email", action: "mask", path: "$.actor.username" }],
    rules: "Bower's built-in privacy rules."
  }
};

function check(state: SourceSetupStatusCheck["state"], label: string): SourceSetupStatusCheck {
  return {
    state,
    label,
    checks: [
      state === "complete"
        ? { id: "report", state: "pass", message: "The collector reports events from ssh-gateway/production.", fix: null }
        : { id: "report", state: "pending", message: "The collector does not expect ssh-gateway/production yet.", fix: "Install the approved files and restart the collector." }
    ],
    lastEventAt: state === "complete" ? "2026-10-27T00:05:00Z" : null,
    collectorSeenAt: "2026-10-27T00:06:00Z",
    checkedAt: "2026-10-27T00:06:30Z"
  };
}

function detail(status: SourceSetupRequestDetail["status"], statusCheck: SourceSetupStatusCheck, requester = "other-person"): SourceSetupRequestDetail {
  return {
    id: "a".repeat(32),
    type: "syslog",
    typeTitle: "Syslog",
    collectorId: "edge-01",
    status,
    contentHash: plan.contentHash,
    reason: "SSH failures from the edge gateway",
    requestedByName: "Alex Operator",
    requestedAt: "2026-10-27T00:00:00Z",
    reviewerName: status === "pending-review" ? null : "Sam Approver",
    reviewedAt: status === "pending-review" ? null : "2026-10-27T00:02:00Z",
    reviewReason: status === "pending-review" ? null : "Matches BWR-210",
    check: statusCheck,
    requestedByObjectId: requester,
    values: { protocol: "tls" },
    plan
  };
}

let requests: { method: string; path: string; body: unknown }[] = [];

function stub({
  roles = ["Bower.Operator"],
  plans = [validPlan],
  details = [] as (SourceSetupRequestDetail | "error")[],
  typesError = false
} = {}) {
  let planIndex = 0;
  let detailIndex = 0;
  requests = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const path = url.pathname;
      const method = init?.method ?? "GET";
      requests.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/api/access/me") {
        return json({ objectId: "me", displayName: "Me", roles, developmentAuthentication: false });
      }
      if (path === "/api/sources/types") {
        return typesError ? json({ error: "Service unavailable." }, 503) : json(types);
      }
      if (path === "/api/collectors") {
        return json(collectors);
      }
      if (path === "/api/sources/plan") {
        const result = plans[Math.min(planIndex, plans.length - 1)];
        planIndex += 1;
        return json(result);
      }
      if (path === "/api/sources/requests" && method === "POST") {
        return json(details[0], 201);
      }
      if (path === "/api/sources/requests") {
        return json(details.filter((item) => item !== "error"));
      }
      if (path.startsWith("/api/sources/requests/") && path.endsWith("/approve")) {
        return json(details[0]);
      }
      if (path.startsWith("/api/sources/requests/")) {
        const item = details[Math.min(detailIndex, details.length - 1)];
        detailIndex += 1;
        return item === "error" || item === undefined ? json({ error: "Service unavailable." }, 503) : json(item);
      }
      if (path.startsWith("/api/collectors") || path === "/api/approvals") {
        return json([]);
      }
      return json({ error: `Unexpected ${method} ${path}` }, 500);
    })
  );
}

function renderAt(path: string) {
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

describe("Sources page", () => {
  beforeEach(() => {
    // These tests exercise technical-page permissions after the viewer opts in.
    localStorage.setItem("bower-console-view:development:me", "detailed");
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

  it("renders every source type's form from its definition and hides fields that do not apply", async () => {
    stub();
    renderAt("/sources");

    fireEvent.click(await screen.findByRole("radio", { name: /Syslog/ }));
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    const step = await screen.findByRole("region", { name: "Fill in the settings" });
    expect(within(step).getByText("An approved collector that loads the signed pack.")).toBeTruthy();
    expect(within(step).getByLabelText("Allowed senders").tagName).toBe("TEXTAREA");
    expect((within(step).getByLabelText("Port") as HTMLInputElement).value).toBe("6514");
    expect(within(step).getByText(/never the secret itself/)).toBeTruthy();
    expect(within(step).getByLabelText("Server private key file")).toBeTruthy();
    // Pending collectors cannot take sources, so they are not offered.
    const collector = within(step).getByLabelText("Collector");
    expect(within(collector).queryByText(/new-02/)).toBeNull();
    expect(within(collector).getByText(/edge-gw-01/)).toBeTruthy();

    fireEvent.click(within(step).getByRole("radio", { name: "UDP, this host only" }));
    expect(within(step).queryByLabelText("Server private key file")).toBeNull();
  });

  it("shows the server's field problems next to the field and sends only visible values", async () => {
    const invalid: SourceSetupPlanResult = {
      valid: false,
      checks: [
        {
          id: "allowedSenders",
          state: "fail",
          message: "Allowed senders: contains an entry that is not an IP address.",
          fix: "Enter addresses like 10.20.0.5."
        }
      ],
      plan: null,
      preview: null
    };
    stub({ plans: [invalid] });
    renderAt("/sources");

    fireEvent.click(await screen.findByRole("radio", { name: /Syslog/ }));
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const step = await screen.findByRole("region", { name: "Fill in the settings" });
    fireEvent.change(within(step).getByLabelText("Collector"), { target: { value: "edge-01" } });
    fireEvent.click(within(step).getByRole("radio", { name: "UDP, this host only" }));
    fireEvent.change(within(step).getByLabelText("Allowed senders"), { target: { value: "not-an-address" } });
    fireEvent.click(within(step).getByRole("button", { name: "Check settings" }));

    const field = await within(step).findByLabelText("Allowed senders");
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect(within(step).getByText(/Enter addresses like 10.20.0.5./)).toBeTruthy();
    expect(within(step).getByText(/Some settings need changing/)).toBeTruthy();
    const sent = requests.find((item) => item.path === "/api/sources/plan")!.body as { values: Record<string, string>; collectorId: string };
    expect(sent.collectorId).toBe("edge-01");
    expect(sent.values).toEqual({ protocol: "udp", allowedSenders: "not-an-address", port: "6514" });
  });

  it("reviews the redacted preview and generated settings, then asks for approval with a reason", async () => {
    stub({ details: [detail("pending-review", { ...check("in-progress", "Waiting for approval"), checks: [{ id: "approval", state: "pending", message: "Waiting for an approver other than the person who asked.", fix: "Ask someone with the Bower.Approver role." }] })] });
    renderAt("/sources");

    fireEvent.click(await screen.findByRole("radio", { name: /Syslog/ }));
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const settings = await screen.findByRole("region", { name: "Fill in the settings" });
    fireEvent.change(within(settings).getByLabelText("Collector"), { target: { value: "edge-01" } });
    fireEvent.click(within(settings).getByRole("button", { name: "Check settings" }));

    const review = await screen.findByRole("region", { name: "Review and preview" });
    expect(within(review).getByLabelText("Example event after redaction").textContent).toContain("[REDACTED:id.email]");
    expect(within(review).getByLabelText("Contents of syslog.json").textContent).toContain("SyslogSource");
    expect(within(review).getByLabelText("Environment variables for the collector").textContent).toBe(
      "BOWER_SYSLOG_CONFIG=/etc/bower/syslog.json"
    );
    expect(within(review).getByRole("button", { name: "Copy snippet" })).toBeTruthy();
    fireEvent.click(within(review).getByRole("button", { name: "Continue" }));

    const approval = await screen.findByRole("region", { name: "Ask for approval" });
    fireEvent.change(within(approval).getByLabelText("Why this source is needed"), { target: { value: "   " } });
    fireEvent.click(within(approval).getByRole("button", { name: "Ask for approval" }));
    expect(await within(approval).findByText("Enter a reason before asking for approval.")).toBeTruthy();
    fireEvent.change(within(approval).getByLabelText("Why this source is needed"), {
      target: { value: "SSH failures from the edge gateway" }
    });
    fireEvent.click(within(approval).getByRole("button", { name: "Ask for approval" }));

    expect(await screen.findByRole("heading", { name: "Syslog on edge-01" })).toBeTruthy();
    const submitted = requests.find((item) => item.path === "/api/sources/requests" && item.method === "POST")!;
    expect(submitted.body).toMatchObject({ type: "syslog", collectorId: "edge-01", reason: "SSH failures from the edge gateway" });
    expect((await screen.findAllByText("Waiting for approval")).length).toBeGreaterThan(0);
  });

  it("ignores a delayed plan after the operator edits the settings", async () => {
    stub();
    const original = globalThis.fetch;
    let release!: (response: Response) => void;
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/api/sources/plan")) {
        return new Promise<Response>((resolve) => { release = resolve; });
      }
      return original(input, init);
    }));
    renderAt("/sources");
    fireEvent.click(await screen.findByRole("radio", { name: /Syslog/ }));
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const settings = await screen.findByRole("region", { name: "Fill in the settings" });
    fireEvent.change(within(settings).getByLabelText("Collector"), { target: { value: "edge-01" } });
    fireEvent.click(within(settings).getByRole("button", { name: "Check settings" }));
    await act(async () => {});
    fireEvent.change(within(settings).getByLabelText("Port"), { target: { value: "6515" } });
    await act(async () => { release(json(validPlan)); });
    expect(screen.queryByRole("region", { name: "Review and preview" })).toBeNull();
    expect(within(settings).getByRole("button", { name: "Check settings" })).toBeTruthy();
    expect((within(settings).getByLabelText("Port") as HTMLInputElement).value).toBe("6515");
  });

  it("keeps viewers read-only and never asks the server for a plan", async () => {
    stub({ roles: ["Bower.Viewer"] });
    renderAt("/sources");

    expect(await screen.findByText(/Viewing only/)).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: /Syslog/ }));
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const step = await screen.findByRole("region", { name: "Fill in the settings" });
    expect((within(step).getByRole("button", { name: "Check settings" }) as HTMLButtonElement).disabled).toBe(true);
    expect((within(step).getByLabelText("Allowed senders") as HTMLTextAreaElement).disabled).toBe(true);
    expect(requests.some((item) => item.path === "/api/sources/plan")).toBe(false);
  });

  it("shows an error when source types cannot load", async () => {
    stub({ typesError: true });
    renderAt("/sources");

    expect(await screen.findByText("Could not load this view.")).toBeTruthy();
  });

  it("polls the server's check while waiting and shows when the collector receives events", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    stub({
      details: [
        detail("approved", check("in-progress", "Waiting for the collector")),
        "error",
        detail("approved", check("complete", "Receiving events"))
      ]
    });
    renderAt(`/sources?request=${"a".repeat(32)}`);

    const step = await screen.findByRole("region", { name: "Install the settings" });
    expect(within(step).getByRole("button", { name: "Download signed copy" })).toBeTruthy();
    expect(within(step).getByLabelText("Contents of syslog.json")).toBeTruthy();

    await act(() => vi.advanceTimersByTimeAsync(15000));
    expect(await screen.findByText(/Could not refresh the check/)).toBeTruthy();
    expect(screen.getAllByText("Waiting for the collector").length).toBeGreaterThan(0);

    await act(() => vi.advanceTimersByTimeAsync(15000));
    await waitFor(() => expect(screen.getAllByText("Receiving events").length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole("button", { name: /Step 3: Check it works/ }));
    const checkStep = await screen.findByRole("region", { name: "Check it works" });
    expect(within(checkStep).getByText("The collector reports events from ssh-gateway/production.")).toBeTruthy();
  });

  it("explains that a rejected request needs new settings", async () => {
    stub({
      details: [
        detail("rejected", {
          ...check("attention", "Rejected"),
          checks: [{ id: "approval", state: "fail", message: "Sam Approver rejected this request.", fix: "Read the reason, change the settings and ask for approval again." }]
        })
      ]
    });
    renderAt(`/sources?request=${"a".repeat(32)}`);

    const step = await screen.findByRole("region", { name: "Approval" });
    expect(within(step).getByText(/change the settings and ask for approval again/)).toBeTruthy();
    expect(within(step).getByText(/Matches BWR-210/)).toBeTruthy();
  });
});

describe("Source setup approvals", () => {
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

  it("lets a different approver decide with a reason", async () => {
    stub({ roles: ["Bower.Approver"], details: [detail("pending-review", check("in-progress", "Waiting for approval"))] });
    renderAt("/approvals");

    const section = await screen.findByRole("region", { name: "Source setup requests" });
    expect(await within(section).findByRole("heading", { name: "Syslog on edge-01" })).toBeTruthy();
    fireEvent.change(within(section).getByLabelText("Decision reason for this source"), { target: { value: "  " } });
    fireEvent.click(within(section).getByRole("button", { name: "Approve source" }));
    expect(await within(section).findByText("Enter a reason before recording the decision.")).toBeTruthy();
    fireEvent.change(within(section).getByLabelText("Decision reason for this source"), { target: { value: "Matches BWR-210" } });
    fireEvent.click(within(section).getByRole("button", { name: "Approve source" }));

    await waitFor(() =>
      expect(requests.some((item) => item.method === "POST" && item.path.endsWith("/approve"))).toBe(true)
    );
    const decision = requests.find((item) => item.method === "POST" && item.path.endsWith("/approve"))!;
    expect(decision.body).toEqual({ reason: "Matches BWR-210" });
  });

  it("tells the requester that someone else must decide", async () => {
    stub({ roles: ["Bower.Approver"], details: [detail("pending-review", check("in-progress", "Waiting for approval"), "me")] });
    renderAt("/approvals");

    const section = await screen.findByRole("region", { name: "Source setup requests" });
    expect(await within(section).findByText(/another approver must decide it/)).toBeTruthy();
    expect(within(section).queryByRole("button", { name: "Approve source" })).toBeNull();
  });

  it("shows viewers the request without decision controls", async () => {
    stub({ roles: ["Bower.Viewer"], details: [detail("pending-review", check("in-progress", "Waiting for approval"))] });
    renderAt("/approvals");

    const section = await screen.findByRole("region", { name: "Source setup requests" });
    expect(await within(section).findByText(/Viewing only/)).toBeTruthy();
    expect(within(section).queryByRole("button", { name: "Approve source" })).toBeNull();
  });
});

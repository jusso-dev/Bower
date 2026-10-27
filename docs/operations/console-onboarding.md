# Console onboarding (`/setup`)

The **Setup** page in the management console takes a new tenant from an empty
management database to a test event that Bower has found in Microsoft Sentinel,
without the CLI. It is part of the existing console: same sign-in, same roles, same
audit trail. Progress is computed from server state, so the wizard can be left and
resumed by anyone, and every step can be run again.

## Steps

| # | Step | Done when | What Bower checks |
|---|---|---|---|
| 1 | Sign in | You are signed in | Your name and the Bower app roles in your token. Only `Bower.Administrator` can change setup. |
| 2 | Connect Entra apps | The API trusts your tenant and a collector has registered | Production sign-in (not development mode), the tenant and audience the API validates, and that at least one collector has signed in with the `Bower.Collector` app role. Bower cannot read your app registrations; compare them with `deploy/entra/*.json`. |
| 3 | Choose where events go | A Log Analytics workspace ID is saved | Format of the workspace ID, workspace resource ID, data collection rule (DCR) resource ID and table. **Check the rule and table** reads the deployed DCR and table read-only and runs the same drift checks as `bower doctor` / `bower dcr diff`. **Download DCR template** returns the same ARM template as `bower dcr generate`. |
| 4 | Approve the first collector | At least one collector is approved or active | Pending and approved collectors. Approval stays on the **Approvals** page with a reason and approver role; the wizard never approves anything. |
| 5 | Choose what the test proves | A probe profile is saved | `generic` (the canary through `POST /v1/events`) or a signed pack parser with a repo-owned fixture (`parser:linux-ssh-gateway:0`). |
| 6 | Send a test event | The collector accepted the latest test event | The latest run's collector response. |
| 7 | See proof it arrived | The latest run is `verified` | Only a Log Analytics query that returned the exact test event. |

Each step shows a plain-English "why this matters" line, its checks, and a suggested
fix for every check that is not passing. A viewer, operator or approver sees the
same progress read-only.

## Canary proof semantics

The test event reuses `Bower.Evidence.EvidenceRunner` unchanged, exactly as
`bower evidence run` does (see [evidence bundles](evidence-bundles.md)):

- The generic profile sends the `collector_canary` envelope; parser profiles send the
  trusted synthetic fixture through the signed parser intake and record the `probe`
  object.
- **Collector acceptance is never shown as delivery.** Step 6 can be done while step 7
  is not.
- Step 7 is done only when the bundle mode is `verified`: the destination query
  returned the exact event id (and, for parser probes, the expected event type and
  the policy hash the collector reported).
- Without a verifier identity the run is `simulated`. The console labels it
  **Simulated** and says it is not proof of delivery.
- The signed bundle (metadata only) can be downloaded from step 7 and checked with
  `bower evidence verify`.

Outcome codes are the evidence outcomes (`verified`, `accepted-not-verified`,
`collector-permission-denied`, `destination-row-missing`, …) plus codes for failures
outside the bundle: `collector-unreachable`, `verifier-credential-unavailable`,
`accepted-not-checked` (the collector accepted the event, then the verifier could not sign
in, so Sentinel was never queried; the event id is kept), `canary-token-unreadable`,
`signing-key-unreadable` and `interrupted` (the service restarted mid-run). The API
maps each code to a fixed message and fix. Raw Azure or framework error text stays
on the server.

## Server configuration

The canary runs on the management API host. Configure it there (environment
variables use `__` for `:`); nothing secret is sent to or stored in the browser.

| Setting | Required | Meaning |
|---|---|---|
| `Bower:Setup:Canary:CollectorUrl` | yes | Collector base URL, `http` or `https`. |
| `Bower:Setup:Canary:IngestTokenFile` | yes | File holding an ingest token for the canary producer (at most 4 KiB). Read for each run; never returned, logged or stored. |
| `Bower:Setup:Canary:Credential` | for proof | Read-only verifier identity: `managed-identity`, `workload-identity`, `environment` or `azure-cli`. Without it every run is simulated and the DCR check is unavailable. |
| `Bower:Setup:Canary:ClientId` | no | User-assigned managed identity client ID. |
| `Bower:Setup:Canary:SigningKeyFile` | no | ECDSA P-256 private key PEM that signs bundles. Unsigned bundles say so. |
| `Bower:Setup:Canary:TimeoutMinutes` | no | How long to wait for the event in Sentinel: 1–60, default 15. |

Give the canary token its own producer ID in `BOWER_INGEST_TOKENS_FILE`, scoped
(`BOWER_PRODUCER_SCOPES_FILE`) to the application `BowerEvidence` / `production`
for the generic profile, and to the probe pack's identity for parser profiles. The
verifier identity needs only **Log Analytics Reader** on the workspace (and Reader
on the DCR and table for the rule check). Keep it separate from the ingest identity.

## Local and end-to-end testing

With development authentication (never in production) every request has all roles. The
`X-Bower-Development-Roles` header narrows a request to the listed roles (for example
`Bower.Viewer`); it can only remove roles. The Playwright journey uses it for the
read-only viewer check. With `BOWER_E2E_CANARY=1`, Playwright starts a loopback stub
collector (`e2e/stub-collector.mjs`, port 4399, token `e2e-canary-token`) and expects the
API to be started with `Bower:Setup:Canary:CollectorUrl=http://127.0.0.1:4399/` and a token
file holding that token. No verifier is configured, so the journey ends at a run labelled
**Simulated, not proof**.

## API

All endpoints are under `/api/setup` and enforced by the API (UI role checks only
guide the interface). Every state change writes a `management_audit` row.

| Method and path | Policy | Audit action |
|---|---|---|
| `GET /api/setup` | View | — |
| `POST /api/setup/destination` | Administer | `setup.destination-set` |
| `POST /api/setup/destination/check` | Administer | `setup.destination-checked` |
| `GET /api/setup/dcr-template` | View | — |
| `POST /api/setup/probe-profile` | Administer | `setup.probe-profile-set` |
| `POST /api/setup/canary` | Administer | `setup.canary-requested` (the administrator), then `setup.canary-verified`, `setup.canary-failed`, `setup.canary-simulated` or `setup.canary-interrupted` with actor `bower.setup` and the requester in `initiatedByObjectId` / `initiatedByName` |
| `GET /api/setup/canary/runs/{id}/bundle` | View | — |

The console polls every 5 seconds while a run is in progress. A failed poll keeps the last
progress on screen with a polite warning and retries with backoff (10, 20, 40, at most 60
seconds). Finished runs and step changes are announced in a polite live region. The latest
run is the last one started (insertion order), whatever its timestamp.

`POST /api/setup/canary` answers `202` with the run, or `409` with a fixed message
when a run is already in progress, a prerequisite step is missing, or the server is
not configured. One run at a time. Runs left in progress by a restart are marked
`interrupted` at start-up.

## Design note

**Scope.** Issue #97: the seven steps above, server-side progress, re-runnable steps,
validation with fixes, canary proof through the existing evidence runner. Reusable
console primitives for later guided views (#98 to #107) are described in
[`DESIGN.md`](../../DESIGN.md#guided-flows).

**Non-goals.** No Azure resource creation (the DCR template is a download you deploy
yourself). No secrets in the browser. No approvals or four-eyes bypass: the collector
step links to **Approvals**. No automatic or scheduled canaries: a run starts only
when an administrator presses **Send test event**. No raw event values: the API
returns run metadata only.

**Invariants touched.** "Never claim Sentinel delivery without destination query
validation" (step 7 depends only on `mode == verified`); "simulated evidence must say
simulated"; "never log secrets" (the token is read from a file per run; only
exception type names are logged); "use least privilege" (read-only verifier,
dedicated canary producer). Delivery, acknowledgement and queue state are untouched:
the canary is a normal producer event through the collector.

**New trust boundary.** The management API now optionally holds a canary ingest
token and a read-only Azure identity. Both are opt-in server configuration, used only
by Administrator-triggered, audited runs, and never exposed through the API. See
[threat model](../security/threat-model.md).

**Failure modes.** Collector unreachable, refused token or scope, parser inactive,
policy rejection, verifier credential missing, query permission denied, row not found
before the timeout, wrong event, configuration mismatch, restart mid-run. Each maps to
a fixed message and fix; the step shows "Needs attention".

**Bounds.** One run at a time; poll timeout 1–60 minutes; 30-second HTTP timeout per
request; token file at most 4 KiB; workspace, DCR and table identifiers validated
against strict patterns before any Azure call; at most 5 collector names listed.

**Tests.** API (`SetupApiTests`): RBAC for every endpoint, validation messages,
audit rows, prerequisites, one run at a time, verified only with a destination row,
simulated without a verifier, collector and transport failures mapped without raw
detail, parser probe outcomes, DCR checks, interrupted runs. Console (vitest): guided
primitives (stepper semantics, focus, non-colour status) and the setup page (read-only
viewers, saving, simulated versus verified). Playwright journey in
`e2e/management.spec.ts`.

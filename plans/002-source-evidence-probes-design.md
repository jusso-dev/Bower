# Design 002: Next source-specific evidence probe

**Status:** DESIGN (for review; not implemented) · **Date:** 2026-11-12 · **Commit:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [002-source-evidence-probes.md](002-source-evidence-probes.md)

## Decision

Add one opt-in parser probe, `parser:windows-security-logon:0`, with the repo-owned
synthetic fixture `windows-security-logon/security-4625/network-logon-failure@1`.
It reuses the existing runner, outcome vocabulary and bundle shape unchanged. The only
additive behaviour is one extra `untestedPaths` entry and one limitation line that name the
Windows native transport the probe does not exercise. Both appear only on bundles for this
profile.

A `verified` bundle for this profile proves one thing: one synthetic 4625-shaped JSON record
posted to `POST /v1/packs/windows-security-logon/parsers/0/events` passed that signed
parser, privacy, policy, the durable queue and the configured output, and the exact row was
then queried back from the intended workspace and table. It does **not** verify the Windows
Event Log reader, XML rendering, bookmarks, channel subscriptions, WEF/WEC forwarding, or any
real Windows event. HTTP parser intake does not verify native transport (syslog, Windows
Event Log, cloud queue, file tail or any sender).

`linux-authlog-ssh:0` is the runner-up and the recommended next increment once this one is
qualified.

## Drift check (step 1)

`HEAD` equals the planned commit `64859aa7d620cec2538aa74fed647e4076e83490`, so
`git diff --stat 64859aa7…HEAD -- src/Bower.Evidence docs/operations/evidence-bundles.md packs tests`
is empty. The plan's "Current state" matches the code as read below.

## Current behaviour (step 2)

### Probe resolution and fixtures

- `ProbeProfiles.ResolveParser` matches the profile string ordinally against
  `ParserProbeFixtures.All` and throws `ArgumentException` otherwise
  (`src/Bower.Evidence/ParserProbe.cs:21-28`). `RunAsync` resolves it before any status
  read or send (`src/Bower.Evidence/EvidenceRunner.cs:115-118`). A test asserts zero status
  reads and zero records for an unknown profile
  (`tests/Bower.UnitTests/ParserProbeEvidenceTests.cs:517-529`).
- `ParserProbeFixture` is a positional record of `Id`, `PackId`, `ParserIndex`,
  `ExpectedEventType` and `Build`. `Profile` and `Path` are derived from it
  (`src/Bower.Evidence/ParserProbe.cs:36-45`). `Render` serialises the `JsonObject` in
  insertion order, and evidence pins those bytes (`ParserProbe.cs:47-49`,
  `src/Bower.Evidence/AGENTS.md`). `Timestamp` renders UTC with seven fractional digits
  (`ParserProbe.cs:52-53`).
- There is one fixture, `LinuxSshGateway`, and `All = [LinuxSshGateway]`
  (`ParserProbe.cs:58-72`). Its golden bytes are asserted in
  `tests/Bower.UnitTests/ParserProbeEvidenceTests.cs:561-577`.
- The console's probe options enumerate `ParserProbeFixtures.All`, so a new fixture
  appears in setup step 5 automatically
  (`src/Bower.Management.Api/SetupEndpoints.cs:169-183`).

### Runner flow for a parser profile

1. A fresh `bower-probe-<uuid7 N>` id is generated (`EvidenceRunner.cs:242`).
2. `GET /v1/status`. A 401/403 gives `collector-permission-denied`, a non-200 response or a
   missing `policy` gives `collector-status-unreadable`, a non-Sentinel `output` gives
   `collector-output-not-sentinel`, and a parser state other than `active-local-json` gives
   `parser-inactive`. None of these sends the fixture (`EvidenceRunner.cs:250-278`). The
   collector reports `active-local-json` only when the parser has a runtime mapping
   (`src/Bower.Collector/CollectorApplication.cs:582`).
3. The fixture is posted and classified by `ProbeOutcomes.Classify`
   (`EvidenceRunner.cs:282-288`, `ParserProbe.cs:214-237`).
4. A simulated run (no workspace or no query client) ends as `accepted-not-verified` with a
   `SIMULATED` limitation (`EvidenceRunner.cs:311-315`).
5. Otherwise the runner polls KQL for `EventId == "<probe id>"` and projects `EventType` and
   `PolicyHash` (`EvidenceRunner.cs:368-370`). It verifies only when the row has the exact
   `EventId`, the expected `EventType` and the policy hash the collector returned for the
   probe (`EvidenceRunner.cs:399-424`). A permission error stops at once
   (`EvidenceRunner.cs:394-397`). A last answer that was incomplete or invalid fails closed
   as `destination-query-failed` (`EvidenceRunner.cs:428-439`).
6. The bundle mode is `simulated`, `verified` or `failed` (`EvidenceRunner.cs:329`). The
   `probe` record carries `testedPath` `POST <path> -> parser -> privacy -> policy -> queue
   -> output -> <table>` and the static `UntestedPaths` (`EvidenceRunner.cs:330-349`,
   `ParserProbe.cs:190-197`). The limitation names the exact intake path
   (`EvidenceRunner.cs:301`).
7. The generic canary path is separate: `bower-canary-` id, `/v1/events` and its own KQL
   without `EventType` (`EvidenceRunner.cs:120-198`, `485-517`). Generic bundles omit
   `probe` (`tests/Bower.UnitTests/ParserProbeEvidenceTests.cs:554`).

### Collector parser intake

- `POST /v1/packs/{packId}/parsers/{parserIndex:int}/events` returns 404 for an unknown or
  inactive parser, 415 for a non-JSON content type, 413 above 32 KiB, 400 for an invalid
  record or a transform quarantine, and 422 `pack-record-not-selected` when the match filter
  does not select the record (`src/Bower.Collector/PackEndpoints.cs:15-85`,
  `src/Bower.Packs/PackRuntime.cs:20`).
- Producer scopes are checked against the **mapped** envelope before processing (403)
  (`PackEndpoints.cs:87-92`). The tuple is application name, environment, tenant, instance
  and source hostname, IP address and port (`src/Bower.Core/ProducerAuthorization.cs:125-141`).
- The record is processed with `SourceAdapter = pack-http:{producer}:{pack}:{index}` and
  no generated-id redaction context (`PackEndpoints.cs:97-98`). The native Windows and file
  sources go through `PackRecordIntake` instead: a different source adapter and a
  `RedactionContext` carrying the source-computed id (`src/Bower.Collector/PackRecordIntake.cs:98-106`,
  `tests/Bower.UnitTests/WindowsEventLogCollectorTests.cs:164`). **The HTTP probe does not
  exercise that code.**
- `PackRuntime.Parse` runs the transform, applies `match`, then reads the mapped fields. It
  requires `eventId` of at most 128 characters and a timestamp in the
  `yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK` shape (`PackRuntime.cs:46-87`, `155-160`). `EventId` and
  `EventOriginalId` both come from the mapped `eventId` source field (`PackRuntime.cs:101-102`).

### Policy selection and privacy composition

- Policies are evaluated in ordinal policy-id order and the first match wins
  (`src/Bower.PolicyEngine/DeterministicPolicyEvaluator.cs:12-29`). `BWR-PACK-*` sorts
  before the default `BWR-POL-AUTH-FAILURE` (`policies/default/authentication-failure.yaml:5`),
  so a pack's `authentication_failure` policy wins over the default one.
- At most one privacy profile can be active (`src/Bower.Packs/PolicyBundle.cs:96-101`). The
  four SSH/Windows parser packs each ship `privacy.yaml`, so a collector loads at most one of
  them. In practice, two parser packs never compete for the same probe event.
- Score: 40, plus 30 when no required field is missing, plus 10 for an actor, 5 for a
  target, 5 for a source and 10 for a correlation id, plus up to 5 for recommended fields
  (`DeterministicPolicyEvaluator.cs:138-153`).

### Shipped parser runtimes

| Pack | Parsers | Runtime | Event id source |
|---|---|---|---|
| `linux-ssh-gateway` 1.1.0 | `sshd-json` (index 0) | mapping, no transform (`packs/linux-ssh-gateway/parsers/sshd-json.json:41-57`) | `id` (`:52`) |
| `linux-journald-ssh` 1.0.1 | `sshd-journald` (index 0) | transform (`packs/linux-journald-ssh/parsers/sshd-journald.json:22-30`) | `__CURSOR` (`:42`) |
| `linux-authlog-ssh` 1.3.0 | `sshd-authlog` (index 0) | transform with exact line grammar (`packs/linux-authlog-ssh/parsers/sshd-authlog.json:20-30`) | `id` (`:44`) |
| `windows-security-logon` 1.0.2 | `security-4625` (index 0) | transform (`packs/windows-security-logon/parsers/security-4625.json:27-34`) | `id` (`:56`) |
| `aws-security` 1.1.0 | none (`packs/aws-security/pack.yaml:14-25`) | n/a | n/a |

## Candidate ranking (step 2)

Criteria: operator value (is the parser on a path real deployments use?), available
repo-owned fixture, supported parser runtime, and selection/policy readiness.

| Rank | Candidate | Operator value | Fixture available | Runtime | Selection and policy readiness | Verdict |
|---|---|---|---|---|---|---|
| 1 | `windows-security-logon:0` | High. The console's Windows setup selects this parser (`docs/operations/console-sources.md:8-12`). Live Sentinel campaigns ran the native path with this pack (`docs/evidence/sentinel-native-20261030/README.md:40-41,53`, `docs/evidence/aws-native-20261030/README.md:51-53`). | Yes. A synthetic, structured JSON sample (`packs/windows-security-logon/samples/security-4625.jsonl:1`). The probe needs a minimal subset of it and no line rendering. | `active-local-json` with a transform | Five-condition selection (channel, provider, event id 4625, logon type 3, address shape) (`security-4625.json:28-29`). Policy `BWR-PACK-WIN-LOGON-FAILURE` requires source IP and username (`packs/windows-security-logon/policies/windows-logon-failure.yaml:17-27`). Fixture score is 86 against a minimum of 75. | **Selected** |
| 2 | `linux-authlog-ssh:0` | High. The file tail source routes to it (`docs/deployment/file-tail-source.md:57`). | Yes (`packs/linux-authlog-ssh/samples/authlog.jsonl:1`, `:20` for the `none` method). The probe must render a whole syslog line whose time, tag and grammar all match (`sshd-authlog.json:21-24`). | `active-local-json` with a transform | Ready. The same policy shape (`packs/linux-authlog-ssh/policies/authlog-ssh-authentication.yaml:17-27`). The time comes from the line, so the fixture must embed `sentAt` as RFC 3339 text inside `message`. That is feasible, but the fixture is more fragile to grammar changes. | Next increment |
| 3 | `linux-journald-ssh:0` | Low today. No Bower source reads the journal and the console does not offer journald (`docs/operations/console-sources.md:12-14`). Records arrive only from external HTTP producers. | Yes (`packs/linux-journald-ssh/samples/journald.jsonl:1`) | `active-local-json` with a transform | Ready. The id is `__CURSOR` and the time is `__REALTIME_TIMESTAMP` in microseconds (`sshd-journald.json:29,42`). | Deferred |
| n/a | `aws-security` | High, but not a parser path | No parser | None: AWS signal enters through `/v1/events` (`src/Bower.Forwarding/CollectorClient.cs:41`) | Not applicable | **Does not qualify** (no `parser:aws-security:N` exists) |

Why Windows over auth.log: it has the most-qualified native deployment in this repo, so a
parser regression would hit live operators first. Its record is plain JSON, which keeps the
pinned bytes simple. Its transform selection has more conditions to regress than
`linux-ssh-gateway`'s single `result` match. The probe exercises all five conditions and
the status lookup table.

## Probe specification (step 3)

### Fixture

| Property | Value |
|---|---|
| C# member | `ParserProbeFixtures.WindowsSecurityLogon` (appended after `LinuxSshGateway`; `All = [LinuxSshGateway, WindowsSecurityLogon]`) |
| Fixture id and version | `windows-security-logon/security-4625/network-logon-failure@1` |
| Profile | `parser:windows-security-logon:0` |
| Intake path | `/v1/packs/windows-security-logon/parsers/0/events` |
| Qualified against | pack `windows-security-logon` 1.0.2, parser `parsers/security-4625.json`, policy `BWR-PACK-WIN-LOGON-FAILURE` 1.0.0, privacy profile `windows-logon-pseudonymised` 1.0.0 |
| Expected event type | `authentication_failure` (`security-4625.json:24`) |

Rendered bytes for event id `bower-probe-0190aaaabbbbccccddddeeeeffff0000` and
`sentAt` `2026-10-26T01:02:03.4567891Z`, in this key order:

```json
{"id":"bower-probe-0190aaaabbbbccccddddeeeeffff0000","channel":"Security","provider":"Microsoft-Windows-Security-Auditing","eventId":"4625","timeCreated":"2026-10-26T01:02:03.4567891Z","data.TargetUserName":"bower-evidence-probe","data.Status":"0xc000006d","data.SubStatus":"0xc000006a","data.LogonType":"3","data.IpAddress":"192.0.2.10"}
```

Rules:

- The record holds only the fields the transform or mapping reads (`security-4625.json:28-33,
  55-61`). It drops computer, domain, workstation, SIDs, process, `keywords` and the rest of
  `EventData`. No real host, account or production value appears. `192.0.2.10` is TEST-NET-1
  and `bower-evidence-probe` matches the existing fixture's username
  (`ParserProbe.cs:67-68`).
- All values are JSON strings. `PackRuntime.Read` requires strings (`PackRuntime.cs:54-58`),
  and the transform compares `eventId` and `data.LogonType` as strings
  (`security-4625.json:29`).
- `timeCreated` uses `ParserProbeFixture.Timestamp(sentAt)`. The parser reads it directly as
  `timeGenerated` (`security-4625.json:57`).
- The bytes are pinned. Any change creates `@2`, keeps the `@1` documentation row and
  re-runs qualification. Never edit `@1` in place.

### Unique event identity

- `id` = `bower-probe-` + 32 hex characters (44 characters, within the 128 limit at
  `PackRuntime.cs:84`). It maps unchanged to `EventId` and `EventOriginalId`, because the
  transform never writes `.id` (`security-4625.json:27-34`).
- The native source's ids are `winevt-<32 hex>` (`src/Bower.Source.WindowsEventLog/WindowsEventRecord.cs:77-89`).
  A probe id can never collide with a real Windows event id.
- Every run uses a fresh UUIDv7, so duplicate (200) and identity-conflict (409) responses
  can only come from a fault. They classify as `probe-not-queued` and `collector-rejected`
  (`ParserProbe.cs:216-235`).

### Destination query match

The parser-probe KQL is unchanged (`EvidenceRunner.cs:368-370`). It verifies only when the
row has:

- `EventId` equal to the probe id;
- `EventType` equal to `authentication_failure`;
- `PolicyHash` equal to the `eventPolicyHash` from the intake response.

The bundle records `eventPolicyId`, which should be `BWR-PACK-WIN-LOGON-FAILURE`. Expected
but **not asserted** columns (see open question 1): `ApplicationName` `windows-security`,
`EventOutcomeReason` `InvalidCredentials` (from `0xc000006a`, `security-4625.json:32,37`),
`SourceIpAddress` `192.0.2.10`, `ActorUsername` an HMAC value.

### Redaction expectations

- `actor.username` is HMAC-pseudonymised (`packs/windows-security-logon/privacy.yaml:9-10`).
  `bower-evidence-probe` must not appear in the queued payload, the database or the bundle.
- Unmapped raw keys (`channel`, `provider`, every `data.*` key) and the raw status codes are
  never forwarded (`docs/deployment/packs.md:173-174`,
  `docs/security/pack-runtime-catalogue.md:70-72`).
- `192.0.2.10` is forwarded as `SourceIpAddress` by design. It must not appear in the
  bundle, which holds metadata only (`ParserProbeEvidenceTests.cs:555-558`,
  `docs/operations/evidence-bundles.md:190-194`).
- The bundle must not contain the ingest token, the rendered record or query response
  bodies.

### Least privilege

| Identity | Grant | Notes |
|---|---|---|
| Verifier | **Log Analytics Reader** on the workspace (Reader on the table only for the retention readout) | Separate from the ingest identity (`docs/operations/evidence-bundles.md:184-188`, `docs/operations/console-onboarding.md:72-73`) |
| Collector ingest token | A dedicated producer id (for example `bower-evidence-windows`) | Needs bearer access to `/v1/status` and one scope tuple |
| Producer scope tuple | `{"producer":"bower-evidence-windows","application":{"name":"windows-security","environment":"production"},"source":{"ipAddress":"192.0.2.10"}}` | Exact match on the mapped envelope (`ProducerAuthorization.cs:125-141`, `docs/security/producer-scopes.md:34-43`). This token can only assert `windows-security` events from the documentation address. A console canary token that also runs the generic profile needs the `BowerEvidence`/`production` tuple as well. |
| Ingest to Azure | Unchanged: Monitoring Metrics Publisher on the DCR | No new Azure role |

### Expiry and timeout

- **Run:** `--timeout-minutes` defaults to 15 and accepts 1 to 1440 on the CLI
  (`src/Bower.Cli/Commands/EvidenceAndQueueCommands.cs:85-95`) or 1 to 60 in the console
  (`docs/operations/console-onboarding.md:67`). Each HTTP request times out after 30 seconds
  (`EvidenceAndQueueCommands.cs:29`). The query looks back `ago(1d)`
  (`EvidenceRunner.cs:369`). Use 15 minutes for local runs and 30 for live qualification
  (AMA paths can be slower).
- **Evidence:** a bundle proves one probe at one time (`docs/operations/evidence-bundles.md:198-199`).
- **Fixture validity:** `@1` stays valid while the pack is 1.0.2 and the policy is 1.0.0. It
  must be re-qualified before the policy review date of 30-06-2027
  (`windows-logon-failure.yaml:9`) or on any pack, policy or privacy-profile version change,
  whichever comes first. The fixture test (below) fails CI on parse drift. The runner
  records the collector's actual `packVersion`, but does not refuse a different version (see
  open question 3).
- **Rows:** probe rows are real `authentication_failure` rows kept for the table's
  retention. Analysts exclude them with `EventId startswith "bower-probe-"`
  (`docs/operations/evidence-bundles.md:157-158`).

### HTTP intake compared with native transport

Add an init-only property `NativePathNotTested` to `ParserProbeFixture` (default `null`, so
the positional constructor and `LinuxSshGateway` stay source- and byte-compatible). For this
fixture, set it to:

> Windows Event Log reader, event XML rendering, channel subscriptions, bookmarks and WEF/WEC forwarding (native transport: the probe enters at collector HTTP intake).

When the property is non-null, the runner:

- appends it to `probe.untestedPaths` (after the five static entries, which are unchanged);
- adds the limitation `NOT NATIVE TRANSPORT: this probe entered at collector HTTP intake; it does not verify the Windows Event Log source or any sender.`

For `parser:linux-ssh-gateway:0` and generic runs, both lists stay byte-identical. The docs
row for the new profile carries the same wording. The console description built at
`SetupEndpoints.cs:180` ("so the test also proves that parser works") should become "…proves
that parser's HTTP intake works", so it does not imply the native source.

## Implementation scope (bounded)

1. `src/Bower.Evidence/ParserProbe.cs`: add the `NativePathNotTested` property, the
   `WindowsSecurityLogon` fixture and append it to `All`.
2. `src/Bower.Evidence/EvidenceRunner.cs`: append the native entry and limitation only when
   `fixture.NativePathNotTested` is non-null. Make no other change: no KQL, outcome or
   classification edits.
3. `src/Bower.Management.Api/SetupEndpoints.cs:180`: change the description wording.
4. `docs/operations/evidence-bundles.md:93-103`: add the table row and the native-transport
   statement. Also update `src/Bower.Evidence/AGENTS.md`, `docs/operations/console-onboarding.md:20`
   and `docs/operations/console-sources.md` (Windows section) to mention the profile.
5. Tests as listed below.

Out of scope: new outcomes, KQL projection changes, scheduling, native-transport probes,
console UI changes beyond the description string.

## Tests (step 4)

Parameterise `ParserProbeEvidenceTests` by profile: a `(Profile, PackSource, ParserFile,
SampleFile)` tuple in place of the `Profile` and `Source` constants
(`ParserProbeEvidenceTests.cs:27,29`) and the hard-coded `sshd-json.json`/`ssh.jsonl` in
`Start` (`:614-623`). Every existing case keeps running for `linux-ssh-gateway`.

| # | Area | Test | Expected |
|---|---|---|---|
| 1 | Trusted fixture allowlist | `All` holds exactly the two profiles. Each `PackId`/`ParserIndex` resolves to a shipped, signed pack parser with a runtime. Fixture ids and profiles are unique. | Pass. Adding an unlisted fixture fails. |
| 2 | Unknown profile before send | Extend `:517-529` with `parser:windows-security-logon:1`, `parser:Windows-security-logon:0`, `parser:windows-security-logon:0 ` and `parser:aws-security:0` | `ArgumentException` listing both profiles, `StatusReads + Records == 0` |
| 3 | Stable rendering | Golden test as at `:561-577` for the Windows fixture (bytes above). The `linux-ssh-gateway` golden test stays unchanged. Parse with the signed shipped pack and assert `EventId`, `EventType`, `EventOutcomeReason == InvalidCredentials` and `Source.IpAddress == 192.0.2.10`. Size under 32 KiB, id at most 128, no `SecretLike` match. | Pass |
| 4 | Signed pack or parser inactive | `inactive` variant (runtime removed) gives `parser-inactive`, `parserStatus` `inactive-preview-only` and `collectorStatus` 0. A collector loading only `linux-ssh-gateway`, probed with the Windows profile, gives `parser-inactive` with `parserStatus` `absent`. Neither queries the destination. Unsigned or untrusted packs are already refused at load (pack tests). | Pass |
| 5 | Selection regression | `not-selected` variant (for example, the transform condition requires logon type `"2"`) | `parser-not-selected` (422), no query |
| 6 | Policy rejection | `policy` variant (`runtime.eventType` set to `authentication_success`) | `policy-not-selected` (422), no query |
| 7 | Duplicate or suppressed | The theory at `:452-470` with the Windows profile: `queued-false`, `duplicate`, `suppressed` | `probe-not-queued`, collector status 202, no query |
| 8 | Wrong event | `wrong-event` variant (`fields.eventId` set to `channel`) gives `parser-wrong-event`. `FixedRowDestination` with a stale id gives `destination-wrong-event`. A row with the right id and `EventType` `account_lockout` gives `destination-wrong-event`. | `failed` |
| 9 | Configuration hash | The test at `:312-327` with the Windows profile | `configuration-mismatch`, `failed` |
| 10 | Permission failure | Status 401 and 403 give `collector-permission-denied` with no send (`:500-515`). Intake 403 from a **real** collector with a scopes file that lacks the Windows tuple gives `collector-permission-denied`. The same collector with the exact tuple accepts. The destination `InsufficientAccessError` gives `destination-permission-denied` after one attempt (`:143-155`). | Pass |
| 11 | Incomplete query | `answered-then-incomplete` and `answered-then-invalid` (`:152-154`) with the Windows profile | `destination-query-failed` with `query-incomplete` / `query-invalid-response` |
| 12 | Simulated mode | `:127-142` with the Windows profile | `simulated`, `accepted-not-verified`, `SIMULATED` limitation, no control `evidenced` |
| 13 | Non-Sentinel output | `:329-363` and `HttpOutputEvidenceTests.cs:15-45` with the Windows profile (`s3`, `http`, a future output, `unknown`) | `collector-output-not-sentinel`, zero records, `NOT SENTINEL` limitation |
| 14 | Exact destination match | A real collector with the signed Windows pack and `QueueDestination` (`:82-125`) | `verified`; `eventPolicyId` `BWR-PACK-WIN-LOGON-FAILURE`; workspace and table recorded; queued payload lacks `bower-evidence-probe` and every `data.` key; a different workspace gives `destination-row-missing` |
| 15 | Native-transport marking | The Windows bundle has six `untestedPaths` (the last is the native entry) and the `NOT NATIVE TRANSPORT` limitation. The `linux-ssh-gateway` bundle has exactly the five static entries and no such limitation. | Pass |
| 16 | Generic bytes unchanged | Generic bundle has no `probe`, uses the same KQL text as `EvidenceRunner.cs:487-489` and the same limitations. `linux-ssh-gateway` KQL and limitations are unchanged. | Pass |
| 17 | Bundle metadata only | `:531-559` with the Windows profile: signed, verifiable, contains none of the token, `bower-evidence-probe`, `192.0.2.10` or `"data.` | Pass |
| 18 | Console | `SetupApiTests` asserts `ProbeOptions` contains `parser:windows-security-logon:0` and that saving it is audited (pattern at `tests/Bower.UnitTests/SetupApiTests.cs:64,120-142`). | Pass |

Note for test 4 to 8: `Start` drops `raw` samples from regressed packs because they would
fail signing (`ParserProbeEvidenceTests.cs:622-625`). Every Windows sample is `raw`, so the
samples file would become empty. Confirm whether `PackArchive.Build` accepts an empty sample
file. If not, keep one envelope-form sample in the copied test pack only (never in the
shipped pack).

## Validation

### Local (no cloud, no credentials)

```bash
dotnet build --configuration Release
dotnet test --configuration Release --filter "FullyQualifiedName~ParserProbeEvidenceTests|FullyQualifiedName~HttpOutputEvidenceTests|FullyQualifiedName~SetupApiTests"
dotnet test --configuration Release
dotnet format --verify-no-changes
bower pack build packs/windows-security-logon --key <local test key> --out ./artifacts/packs
bower pack test ./artifacts/packs/windows-security-logon-1.0.2.bowerpack --trusted-key <local test pub>
```

Then a local simulated run: start a collector with the locally signed Windows pack, a test
HMAC key and the scoped producer token, then run
`bower evidence run --probe-profile parser:windows-security-logon:0 --collector-url http://127.0.0.1:4319`
with no workspace. Expected: mode `simulated`, outcome `accepted-not-verified`, exit code 2,
and the `SIMULATED` and `NOT NATIVE TRANSPORT` limitations. This runs on any OS, because the
HTTP intake is not Windows-specific.

### Authorised live (separate; requires written authorisation for the tenant)

Preconditions: a named, authorised test workspace; a collector with output
`azure-logs-ingestion` (then repeat with `ama-spool` or `ama-syslog` if those are in scope);
the signed `windows-security-logon` 1.0.2 pack from a trusted key; the dedicated producer
token and scope tuple above; a verifier identity with only Log Analytics Reader. Probe a
single replica directly (`docs/operations/evidence-bundles.md:119-125`).

1. `bower evidence run --probe-profile parser:windows-security-logon:0 --workspace-id … --workspace-resource-id … --credential … --signing-key … --timeout-minutes 30 --out …`.
   Expected: `verified`, exit code 0.
2. `bower evidence verify <bundle> --trusted-key <pub>`. Expected: valid.
3. Independent read-only KQL by the verifier: exactly one row for the probe `EventId`, with
   `ApplicationName == "windows-security"`, `EventOutcomeReason == "InvalidCredentials"`,
   `SourceIpAddress == "192.0.2.10"` and `ActorUsername != "bower-evidence-probe"`.
4. Negative checks: the verifier without its role gives `destination-permission-denied`; a
   collector without the pack gives `parser-inactive`; a token without the scope gives
   `collector-permission-denied`.
5. Record the signed bundles and a README under `docs/evidence/<run-id>/`: metadata only, no
   tokens, payloads or response bodies. State in the README that the native Windows path
   was not exercised.

No live run is part of this design.

### Fail-closed behaviour

- An unknown or malformed profile throws before any network call (CLI exit 1; console 400).
- Unreadable status, a denied status, an inactive or absent parser, or a non-Sentinel output
  means no fixture is sent and the mode is `failed` (or `simulated`).
- Any non-accepting intake response, wrong id, duplicate, suppression or `queued: false`
  means no destination query runs and the mode is `failed`.
- Only `PollProbeAsync` can return `verified`, and only for an exact id, type and hash
  match. Acceptance alone, a simulated run, a permission error, a timeout or an
  incomplete/invalid last answer never verifies.
- A fixture that stops parsing against the shipped pack fails CI (test 3). That forces a
  versioned fixture change, never a silent edit.

## Unvalidated claims and what is not proven

- No build, test or run was executed for this design. Every behavioural statement comes from
  reading code at the cited lines.
- That the Windows fixture parses and scores 86 is derived by hand from
  `security-4625.json`, `PackRuntime.Parse` and `CalculateScore`. Test 3 must confirm it.
- That content detectors leave a `bower-probe-` id unchanged under the Windows privacy profile
  is inferred from the passing `linux-ssh-gateway` probe test (`ParserProbeEvidenceTests.cs:82-111`),
  which uses the same default-plus-HMAC shape. It is not proven for this pack.
- Whether `PackArchive.Build` accepts an empty samples file (test harness note) is unknown.
- That the DCR transform carries `EventOutcomeReason` and `SourceIpAddress` for this row is
  not proven live. The schema shows the columns (`src/Bower.Dcr/SentinelSchema.cs:64,75`).
- Operator value is ranked from repo evidence and console wiring, not from customer usage
  data.
- A `verified` bundle for this profile does not prove: the Windows Event Log source,
  `winevt-` id derivation, `PackRecordIntake`'s generated-id redaction context, bookmarks,
  WEF/WEC, other 4625 status codes or logon types, other packs, `/v1/events`, upstream
  agents, relay downstream outputs, other replicas' pack builds, or delivery of any real
  event.
- `eventPolicyId` is recorded but not asserted. On a collector whose policy directory holds
  another policy that sorts before `BWR-PACK-WIN-LOGON-FAILURE` and matches
  `authentication_failure`, that other policy would select the probe and the run would still
  verify.

## STOP-condition assessment

| STOP condition | Assessment | Hit? |
|---|---|---|
| Parser cannot preserve a unique probe id | `id` maps straight to `EventId`/`EventOriginalId`, and the transform does not write it (`security-4625.json:27-34,56`; `PackRuntime.cs:82,101-102`) | No |
| Parser cannot safely accept a synthetic fixture | The shipped sample is already synthetic and accepted (`security-4625.jsonl:1`). The fixture uses TEST-NET-1 and a fixed username. | No |
| Needs production payloads | No. The fixture is a hand-built minimal subset. | No |
| Any path claims delivery without a destination query | The runner is unchanged: `verified` only from `PollProbeAsync` (`EvidenceRunner.cs:399-424`). The console wording at `SetupEndpoints.cs:180` is tightened so it does not imply the native source. | No |

No STOP condition is hit.

## Open questions

1. Should parser probes also assert `ApplicationName` and `EventOutcomeReason` at the
   destination? That would catch lookup-table and mapping regressions the type check misses.
   To keep `linux-ssh-gateway` bundle bytes, any extra projection would have to be opt-in per
   fixture and map to the existing `destination-wrong-event`.
2. Should a fixture declare its expected policy id and fail (as `policy-not-selected`) when
   another policy selected it? Today any first-matching policy verifies.
3. Should the runner refuse or flag a collector `packVersion` outside the fixture's qualified
   version? Today it is only recorded.
4. A native-transport probe (for example a synthetic event on a dedicated Windows test channel,
   or a probe line in a file-tail input) needs its own design. It is out of scope here.
5. Plan step 5 says "update the index status". This task was restricted to the design file,
   so `plans/README.md` still shows `TODO` for plan 002.

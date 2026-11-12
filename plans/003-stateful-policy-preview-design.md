# Design 003: Stateful policy rollout preview

**Status:** Design for review (not implemented). Product owner decisions on open questions 1, 4 and 8 recorded 2026-11-13. · **Date:** 2026-11-12, decisions 2026-11-13 · **Commit:** `64859aa7d620cec2538aa74fed647e4076e83490` · **Plan:** [003-stateful-policy-preview.md](003-stateful-policy-preview.md)

## Decision

Build `bower policy preview` as a **new subcommand that reuses production logic unchanged**: the real `SecurityEventProcessor` writing to a real `SqliteEventStore`, one fresh, disposable SQLite file per side, created by the preview in its own private temporary directory and deleted before any output is printed. The window clock is pinned and stepped by a strict synthetic scenario file.

Do **not** write a second, approximate suppression algorithm. Do **not** add an in-memory queue mode. The first slice needs no change to `src/Bower.Persistence`, `src/Bower.Core` or `src/Bower.PolicyEngine`: windows still open at the end are read through the existing public close API on the disposable file (see [Pinned clock and ordering](#pinned-clock-and-ordering)), not through a new queue API. `bower policy diff` and its output stay byte-for-byte unchanged.

No STOP condition is hit (see [STOP assessment](#stop-assessment)). The design depends on four requirements holding in implementation: the preview never accepts a queue path, its output is labelled `simulated`, nothing is printed until cleanup succeeds, and the work root is private (mode 0700 on Unix, a protected owner-only ACL on Windows) or the run fails before any database is written.

## Decisions (2026-11-13)

All three follow the design's recommendation or the option it described. Open questions 1, 4 and 8 are decided; the others stay open.

| ID | Question | Choice | Consequence |
|---|---|---|---|
| Q1 | Is a `dataClassification: synthetic` attestation enough? | Yes. A file-level attestation is enough | No per-event `labels.synthetic`. Input validation stays as specified (test I1). The attestation still cannot prove the input is synthetic |
| Q8 | May a report be untied from its input bytes? | Accepted for the first slice | No input digest in the output (test H2). An operator who needs to pin inputs keeps the scenario directory with the report. An HMAC input digest stays a possible later slice |
| Q4 | Sweep stale work directories? | Yes, at start: only `bower-policy-preview-*` directories owned by the same user and older than 24 h | New start-up step and tests (see [Cleanup](#cleanup), tests C4 to C6). A directory whose `preview.lock` another run still holds is never swept. Residue after `SIGKILL` is now bounded to about 24 h, if the preview runs again |

## Drift check (plan step 1)

`git diff --stat 64859aa7d620cec2538aa74fed647e4076e83490..HEAD -- src/Bower.Cli src/Bower.Core src/Bower.Persistence docs/operations/suppression-archive-and-source-silence.md tests` printed nothing (exit 0). HEAD is the planned commit. The plan's premises hold: `docs/operations/suppression-archive-and-source-silence.md:46-48` says diff reports the policy decision only and lists suppression under `notExercisedOffline`, and `src/Bower.Cli/Commands/PolicyCommands.cs:125-133` loads both bundles and compares them at one fixed time.

## Current behaviour (plan step 2)

### Policy bundle loading

- `PolicyBundle.Load` reads the policy directory (ordinal file order, `src/Bower.PolicyEngine/PolicyLoader.cs:23-27`), verifies signed packs, rejects duplicate policy ids, then calls `PolicyLoader.ValidateSet` (`src/Bower.Packs/PolicyBundle.cs:62-94`). The bundle hash covers policy id, version and hash, pack identity and the privacy profile hash (`src/Bower.Packs/PolicyBundle.cs:119-125`).
- `ValidateSet` refuses a set that suppresses unless some policy accepts `telemetry_aggregation_summary` (`src/Bower.PolicyEngine/PolicyLoader.cs:205-222`).
- Per policy, suppression is refused for `neverSample`, for non-accepting actions, for the summary type itself, for invalid key fields (1–5 distinct allow-listed paths), for `windowSeconds` outside 1–86400, and for `allowPerWindow` outside 1–100000 (or not 0 for `aggregate`) (`src/Bower.PolicyEngine/PolicyLoader.cs:155-199`). An `aggregate` policy without a `suppression` section fails to load (`src/Bower.PolicyEngine/PolicyLoader.cs:146-150`).
- `policy diff` bundle mode loads both sides before any sample runs (`src/Bower.Cli/Commands/PolicyCommands.cs:127-129`) and runs each sample alone at a `FixedClock` (`src/Bower.Cli/Commands/PolicyCommands.cs:256`, `:461-464`).

### Policy decision and suppression directive

- Policies are evaluated first match in ordinal id order (`src/Bower.PolicyEngine/DeterministicPolicyEvaluator.cs:12-14`, `:24-31`); no match is `BWR-POL-DEFAULT-DENY` (`:32-42`).
- `aggregate` becomes `accept` with a directive (`src/Bower.PolicyEngine/DeterministicPolicyEvaluator.cs:94-101`). A directive is attached only to an accepting decision, with key values read from the envelope (`:103-111`). An absent key value is the empty string (`src/Bower.PolicyEngine/EventFieldReader.cs:88-117`), so events missing a key field share one window.
- The envelope the evaluator sees is the **redacted** one: the processor redacts (`src/Bower.Core/SecurityEventProcessor.cs:233-241`), deserialises `redaction.RedactedJson` (`:274`), validates (`:310-311`, `:688-726`) and only then evaluates policy (`:337`). Key values are therefore post-redaction (`src/Bower.Abstractions/PipelineAbstractions.cs:294-297`).
- `Suppression.CreateRequest` derives the key hash from a length-framed SHA-256 of the policy id, application, environment, tenant, event type and each key field and value (`src/Bower.Core/Suppression.cs:19-57`, `:182-187`).

### Suppression transaction and duplicate handling

- The processor builds a `QueuedEvent` carrying the `SuppressionRequest` and calls `EnqueueAsync` (`src/Bower.Core/SecurityEventProcessor.cs:387-402`). An identity conflict is quarantined as `event-identity-conflict` (`:404-411`); a capacity refusal is rethrown with nothing committed (`:412-417`).
- `EnqueueCoreAsync` opens a `BEGIN IMMEDIATE` write transaction and commits only when the event was enqueued or suppressed (`src/Bower.Persistence/SqliteEventQueue.cs:289-300`).
- Inside it, `EnqueueInTransactionAsync` checks duplicates **first** (`src/Bower.Persistence/SqliteEventQueue.cs:338-343`), so a re-sent stored event never consumes allowance. Then, for a suppressible event, it checks physical storage (`:349-352`) and calls `AdmitAsync` (`:353-356`). Only admitted events reach `InsertAsync` (`:359`), which applies the logical and page capacity checks (`:383-399`).
- `ExistsAsync` matches on event id **or** fingerprint and throws `EventIdentityConflictException` when the stored fingerprint or normalised payload differs (`src/Bower.Persistence/SqliteEventQueue.cs:468-494`; normalisation ignores `collector`, `security` and `timeObserved`, `src/Bower.Persistence/ReplayContent.cs:42-46`). The fingerprint includes collector id and source adapter (`src/Bower.Persistence/EventIdentity.cs:14-26`).
- `AdmitAsync` computes an epoch-aligned window from whole Unix seconds (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:73-74`), inserts the window row if absent (`:79-104`), reads `admitted < allow_per_window` (`:107-117`) and increments either `admitted` or `suppressed` with first and last suppressed times (`:119-134`). `aggregate` has `allow_per_window` 0, so every match is counted.
- A suppressed event is never stored, so its retry is counted again; a retry of a stored event is a duplicate (`docs/operations/suppression-archive-and-source-silence.md:22-31`).

### Window closure

- `SuppressionWindowWorker` calls `CloseSuppressionWindowsAsync` every 5 seconds and logs failures as `EventId 1302`, keeping windows (`src/Bower.Collector/SuppressionWindowWorker.cs:16-50`, `:58-62`). It is registered as a hosted loop, not a scheduled job (`src/Bower.Collector/CollectorApplication.cs:113`).
- The processor takes `now` once, builds each summary, evaluates it with the same policy set and throws `SuppressionSummaryRejectedException` unless it is accepted (`src/Bower.Core/SecurityEventProcessor.cs:139-175`).
- `CloseExpiredSuppressionWindowsAsync` selects windows with `window_end <= now`, ordered by `window_end, policy_id, key_hash`, at most 1,000 per call (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:59`, `:152-164`). For each window with `suppressed > 0` it builds the summary, skips it if it already exists, inserts it, then deletes the window, all in one transaction (`:193-221`). A thrown callback aborts the whole close, so no count is lost (`src/Bower.Abstractions/PipelineAbstractions.cs:246-254`).
- The summary id derives from policy id, key hash, window start and first suppressed time, never from close time (`src/Bower.Core/Suppression.cs:72-78`); its `timeGenerated` is the window end (`:84`) and its attributes include the redacted key values (`:146-151`).

### Why `policy diff` cannot show any of this

Each sample runs through a fresh `RequestEventBuffer` (`src/Bower.Cli/Commands/PolicyCommands.cs:427-435`). That buffer ignores `QueuedEvent.Suppression` and stages a suppressing policy's event as accepted (`src/Bower.Core/RequestEventBuffer.cs:9-13`, `:25-42`), and throws on window closure (`:89-91`). Diff therefore reports `accept` for an event production would suppress.

## Parity assessment

| Option | Reuses | Parity | Verdict |
|---|---|---|---|
| A. Real processor + real `SqliteEventStore` on a fresh temp file per side | Redaction, validation, policy, `CreateRequest`, duplicate check, `AdmitAsync`, close transaction, summary policy, privacy alerts | Exact for admission, duplicates, conflicts, summaries and restart, because it is the same code | **Recommended** |
| B. In-memory SQLite inside `SqliteEventStore` | Same as A | Exact, but needs queue changes: the constructor resolves a file path (`src/Bower.Persistence/SqliteEventQueue.cs:70-86`), each operation opens a new pooled private-cache connection (`:77-84`, `:1237-1240`) that would see an empty in-memory database, and capacity checks read file lengths (`:1301-1307`) | Rejected: a real queue change for no parity gain |
| C. New in-memory `IDurableEventStore` that re-implements windows | Policy and redaction only | Approximate: would duplicate window maths, duplicate-then-admit ordering, id-or-fingerprint matching, conflict normalisation, the 1,000-window close batch and abort-on-refusal | Rejected: the second algorithm the plan forbids |

Option A needs only public APIs: `SqliteEventStore(path, maximumBytes, clock)` and `InitializeAsync` (`src/Bower.Persistence/SqliteEventQueue.cs:51-54`, `:118-148`), `SecurityEventProcessor.ProcessAsync` and `CloseSuppressionWindowsAsync` (`src/Bower.Core/SecurityEventProcessor.cs:11-23`, `:139-175`), and, for the end-of-run drain only, `IDurableEventStore.CloseExpiredSuppressionWindowsAsync` (`src/Bower.Abstractions/PipelineAbstractions.cs:251-254`), `Suppression.CreateSummary` (`src/Bower.Core/Suppression.cs:63-66`) and `EventFingerprint.Create` (`src/Bower.Core/EventFingerprint.cs:8`). The CLI already constructs a `SqliteEventStore` under AOT (`src/Bower.Cli/Program.cs:122`, `src/Bower.Cli/Bower.Cli.csproj:7`). The existing tests already drive exactly this pairing with a fake clock and restarts (`tests/Bower.UnitTests/SuppressionTests.cs:73-130`, `:380-395`).

The redactor stack copies `ProcessEachAsync` (`src/Bower.Cli/Commands/PolicyCommands.cs:421-431`), which is documented as the collector's composition (`src/Bower.Collector/CollectorApplication.cs:86-88`).

To see windows, the preview wraps the store in a read-only `ObservingEventStore : IDurableEventStore` that delegates every call (like `RecordingRedactor`, `src/Bower.Cli/Commands/PolicyCommands.cs:441-446`). It records:

- `QueuedEvent.Suppression` (policy id, key hash, key fields) on `EnqueueAsync`, for the key limit and aliases;
- each `SuppressionWindow` passed to the close callback, committed to the report only when the close call returns, or marked `refused` when the callback throws;
- each `SuppressionWindow` passed to the end-of-run drain callback, reported as `open-at-end` with its persisted counts.

No existing read path lists open windows: the only `SELECT` on `suppression_windows` outside admission is inside the close (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:152-164`), and `GetSnapshotAsync` returns queue counts only (`src/Bower.Abstractions/PipelineAbstractions.cs:372-380`). The drain reuses the close instead of adding a listing API.

The wrapper only affects `QueueEnqueueBatch`, whose ambient checks require a `SqliteEventStore` (`src/Bower.Persistence/QueueEnqueueBatch.cs:168-177`). The preview never opens a batch, so this is the same path as single HTTP intake.

## Specification (plan step 3)

### Command

```bash
bower policy preview --scenario scenario.json \
  --baseline policies/current --candidate policies/proposed \
  [--baseline-pack ... --baseline-trusted-key ... --candidate-* ...] [--fail-on-change]
```

- A new subcommand next to `policy test` and `policy diff` (`src/Bower.Cli/Program.cs:42-43`). Side options are the same as diff bundle mode (`docs/operations/suppression-archive-and-source-silence.md:104-111`), parsed by `BundleSources` (`src/Bower.Cli/Commands/PolicyCommands.cs:217-243`), so bundle hashes match those diff prints.
- There is no `--at`: time comes from the scenario. There is no `--database`, `--queue` or work-directory option. Any unknown option is exit 1.
- Exit codes match diff: 0 complete, 3 with `--fail-on-change` and any change, 1 for invalid arguments or scenario, bundle load or trust failure, limit exceeded, preview capacity exceeded, or cleanup failure. On exit 1 nothing is printed to stdout.

### Synthetic input format

One strict JSON file (new schema `schemas/configuration/policy-preview-scenario.schema.json`, additive):

```json
{
  "apiVersion": "bower.security/v1",
  "kind": "PolicyPreviewScenario",
  "dataClassification": "synthetic",
  "start": "2026-11-12T00:00:00Z",
  "end": "2026-11-12T00:10:00Z",
  "steps": [
    {"id": "login-1", "at": "2026-11-12T00:00:01Z", "event": "events/auth-failure-1.json"},
    {"id": "login-1-retry", "at": "2026-11-12T00:00:02Z", "event": "events/auth-failure-1.json"},
    {"id": "restart-1", "at": "2026-11-12T00:00:30Z", "action": "restart"}
  ]
}
```

- Unknown properties, duplicate property names, nulls, and numbers or booleans where strings are expected are refused.
- `dataClassification` must be `synthetic`. This is an attestation, not a check. The product owner accepted that it is enough (decision Q1, 2026-11-13).
- `start`, `end` and each `at` use the strict `--at` format (`src/Bower.Cli/Commands/CliOptions.cs:16-27`). Requirements: `start <= at[0]`, `at` non-decreasing, `at[last] <= end`.
- A step has `id` (`^[a-z0-9][a-z0-9-]{0,63}$`, unique) and exactly one of `event` or `action`. The only action is `restart`.
- `event` is a relative path under the scenario's directory: no absolute paths, no `..`, and no symbolic links in any component. Reusing a file is how a retry or duplicate is expressed.
- Event JSON is used as written. The preview does not rewrite `timeGenerated`, so the production 5-minute and 5-year bounds apply (`src/Bower.Core/SecurityEventProcessor.cs:685-686`, `:720-723`). An out-of-range event is quarantined, as it would be in production.

### Pinned clock and ordering

- Each side has its own `SteppedClock : TimeProvider`, set to each step's `at`. Nothing reads the wall clock. The processor, store and summary builder all take time from the injected provider (`src/Bower.Core/SecurityEventProcessor.cs:144`, `:310`, `:545`; `src/Bower.Persistence/SqliteEventQueue.cs:89`).
- Steps run strictly in file order. For each step, the preview sets the clock, calls `CloseSuppressionWindowsAsync`, then processes the event or restarts. After the last step it sets the clock to `end` and closes once more.
- End-of-run drain: after that close, and only for a side with no `summaryRefused`, the preview calls the store's `CloseExpiredSuppressionWindowsAsync` once with `now = end + 86,400 s` (the maximum `windowSeconds`, so every open window qualifies). Its callback records the window and returns a summary built with `Suppression.CreateSummary` and `EventFingerprint.Create`, without policy evaluation. The drain changes only the disposable side file after the scenario has ended, and that file is deleted next. Its summaries are not counted in `summaries queued` and never appear as step outcomes. One call suffices: with the key limit and a close before every step, each key has at most one open window at `end`, so at most 1,000. Windows that only admitted are deleted without a callback (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:193-196`), as in open question 7. A capacity failure during the drain is `preview-capacity-exceeded`.
- Closing before every step gives the same admitted and suppressed counts and summary ids as the 5-second worker. Admission depends only on the received time (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:73-74`), and summary ids do not depend on close time (`src/Bower.Core/Suppression.cs:72-78`). Only the summary's `collector.receivedAt` is idealised; the report states this.
- `restart` drops the processor and store and opens a new `SqliteEventStore` on the same side file, as `tests/Bower.UnitTests/SuppressionTests.cs:90-92` does. This is a clean restart, not a crash.
- The collector identity is fixed: `("bower-cli", <version>, "policy-preview", "policy-preview")`, on the pattern of `src/Bower.Cli/Commands/PolicyCommands.cs:22`.

### Independent baseline and candidate state

- Both bundles load before any step runs. A load failure is exit 1 with nothing on stdout, as in diff (`docs/operations/suppression-archive-and-source-silence.md:123-125`).
- One work root per run: `Directory.CreateTempSubdirectory("bower-policy-preview-")` on Unix, and an equivalent `bower-policy-preview-*` directory created with a private ACL on Windows (see [Redaction before persistence](#redaction-before-persistence)). It holds `baseline/queue.db`, `candidate/queue.db` and an empty `preview.lock` that the run holds open until cleanup (see [Cleanup](#cleanup)). Each side has its own store, processor, evaluator, redactor, clock and observer.
- The sides run one after the other (baseline, then candidate). The two sides share no state other than the read-only scenario bytes. A test that swaps the run order must give identical output.

### Limits

| Limit | Value | Basis |
|---|---|---|
| Scenario file | ≤ 1 MiB | Same scale as policy files (`src/Bower.PolicyEngine/PolicyLoader.cs:12`) |
| Steps | 1–10,000 | Bounded run time; see open question 3 |
| Distinct event files | 1–1,000 | `PolicyCommands.MaximumEventFiles` (`src/Bower.Cli/Commands/PolicyCommands.cs:18`) |
| Event file | ≤ 1,048,576 bytes | `JsonEventRedactor.MaximumPayloadBytes` (`src/Bower.Redaction/Privacy/PrivacyEngine.cs:16`) |
| Distinct event bytes | ≤ 16 MiB | Bounds stored rows |
| Processed bytes per side (sum over steps) | ≤ 256 MiB | Bounds redaction CPU |
| `restart` steps | ≤ 100 | |
| `end - start` | ≤ 7 days | Covers the 86,400 s maximum window several times |
| Distinct suppression keys per side | ≤ 1,000 | Keeps every close within one 1,000-window batch (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:59`). With a close before every step and non-decreasing time, each key has at most one open window at a close, unless a summary was refused (see below) |
| Queue cap per side | `maximumBytes` 64 MiB | Fixed safety bound, not a model of production capacity |

Static limits are checked before any bundle loads. The key limit is checked by the observer during the run. Exceeding a limit is exit 1 with nothing on stdout.

### Capacity

The preview does **not** model queue capacity or backpressure. Its cap is a safety bound. A `QueueCapacityExceededException` (from the cap, the page limit or `SQLITE_FULL` on the temporary volume, `src/Bower.Persistence/SqliteEventQueue.cs:248-272`, `:1340-1372`) ends the run as `preview-capacity-exceeded` with exit 1. It is never reported as a step outcome.

### Summary refusal

When a side's summary policy refuses a summary, the close throws and every window stays open (`src/Bower.Core/SecurityEventProcessor.cs:150-154`). The preview:

- records `summaryRefused` with the step id, policy id and action;
- keeps processing later steps (production keeps collecting);
- stops reporting per-window closes for that side, and skips its end-of-run drain, because the same refusal repeats and windows can build up beyond one close batch.

Step outcomes after the refusal stay exact.

### Deterministic output

Output is indented JSON from the CLI's source-generated context (`src/Bower.Cli/Commands/CliJson.cs:245`), with invariant culture and fixed ordering: steps in file order, and windows by `windowStart`, `policyId`, key alias. Top-level fields:

- `kind: "PolicyPreview"`, `simulated: true`, `start`, `end`, `steps`.
- `baselineBundleHash`, `candidateBundleHash`, and `baselineBundle` and `candidateBundle` provenance (the same shape as diff, `src/Bower.Cli/Commands/PolicyCommands.cs:366-374`).
- `baseline` and `candidate`. Each has `totals` (queued, duplicate, suppressed, rejected, quarantined by stage, privacy alerts, summaries queued, windows open at end), `windows` (policy id, event type, key alias, key fields, window start and end, admitted, suppressed, first and last suppressed, `summary: queued | refused | open-at-end`) and optional `summaryRefused`.
- `changes`, with three parts:
  - `steps`: per step whose outcome differs, with `step` (the id), the outcome on each side (`queued | duplicate | suppressed | rejected | quarantined | identity-conflict | restart`), the policy id, the failure stage and reasons for non-accepted outcomes, and `changedFields`;
  - `windows`: windows matched by policy id, key alias, window start and window end. A window on one side only, or with a different admitted count, suppressed count, first or last suppressed time or `summary` status, is one entry with both sides' values;
  - `summary`: present when `summaryRefused` is on one side only, or differs in step id, policy id or action.
- `changed` is the number of step entries plus window entries, plus 1 when `summary` is present. A summary-only or window-only difference therefore gives `changed > 0` and exit 3 with `--fail-on-change`.
- `notExercised` (see [What preview does not model](#what-preview-does-not-model)).

The output carries no hash or digest of the scenario or event bytes. An unkeyed hash of raw inputs lets a report recipient test guesses of a low-entropy value (a user name or IP address) when the other input bytes are known, and the `synthetic` attestation does not prevent that. A per-run key would break byte-identical repeated runs (test H3), and an operator-held key adds key handling to a first slice. The cost: a report alone cannot show which inputs produced it, or that two reports used the same inputs. The bundle hashes still identify both sides, and the scenario's step ids, `start` and `end` are printed. An operator who needs to pin inputs keeps the scenario directory with the report. The product owner accepted this for the first slice (decision Q8, 2026-11-13).

The output carries no ledger heads, no signatures and no queue paths, so it cannot be mistaken for queue evidence.

Known determinism hazards, all outside the output or unreachable today:

- `schema_history.applied_at` uses SQLite `now` (`src/Bower.Persistence/SqliteEventQueue.cs:142-143`). It is stored only and never read.
- The `Encrypt` privacy action uses a random nonce (`src/Bower.Redaction/Privacy/PolicyApplicator.cs:99-117`). It is inert because no code sets `PrivacyPolicy.EncryptionKey` (`src/Bower.Redaction/Privacy/PrivacyPolicy.cs:71-72`). If that ever changes, both preview determinism and production replay equivalence change; test H3 catches it.
- `EventTap` generates random ids (`src/Bower.Core/EventTap.cs:296`). The preview passes no tap.

### Privacy-safe identifiers

- Steps are named by their scenario `id`, never by event id or payload value.
- Suppression keys are shown as aliases `key-1`, `key-2`, and so on. Aliases are assigned by first appearance in step order across both sides (baseline first on a tie) and keyed by key fields plus key values. Two sides keying on different fields therefore get different aliases and are compared at policy and window level only. Key values and key hashes are never printed: an unsalted SHA-256 of an IP address or user name can be reversed by brute force (`src/Bower.Core/Suppression.cs:182-187`).
- Reasons come from `ProcessingResult.Reasons`, which must not carry payload content (`src/Bower.Core/AGENTS.md`). Lines the preview builds itself that include an id (for example "Emitted privacy alert event ...", `src/Bower.Core/SecurityEventProcessor.cs:460-463`) are dropped. Only failure reasons for non-accepted outcomes are kept, as diff does (`src/Bower.Cli/Commands/PolicyCommands.cs:297-298`).

### Redaction before persistence

- The only data written to disk is what the production processor writes after redaction. Payloads are serialised from the arranged, redacted envelope (`src/Bower.Core/SecurityEventProcessor.cs:360-387`). Window key values come from that envelope. A redaction exception or failure returns before any enqueue (`:233-256`). A redaction that alters the event id is quarantined (`:261-265`). The preview adds no write path for event content. The end-of-run drain writes only summaries that `Suppression.CreateSummary` builds from stored window rows, whose key values are already redacted, to a file deleted before output.
- HMAC key files are read into memory by `PolicyBundle.Load` (`src/Bower.Packs/PolicyBundle.cs:110`). They are never written to the work root and never printed.
- On Unix the work root is created mode 0700 and the queue files are set to 0600 (`src/Bower.Persistence/SqliteEventQueue.cs:1411-1427`).
- On Windows that method does nothing (`src/Bower.Persistence/SqliteEventQueue.cs:1413-1416`), and `Directory.CreateTempSubdirectory` would inherit the temp directory ACL, which may grant other users read access to redacted rows and window key values. The preview therefore creates the root itself, fail-closed: a new randomly named directory under the temp path, created with a protected ACL (inheritance off; full control for SYSTEM, Administrators and the current user only, inherited by child files), following `QueueBackup.CreatePrivateDirectory` and `ApplyPrivateRules` (`src/Bower.Persistence/QueueBackup.cs:516-549`). That helper is `internal` to `Bower.Persistence`, so the preview carries its own copy in `Bower.Cli` rather than widening the queue's API. Before any database is opened it reads the ACL back and exits 1, removing the root, if the directory already existed, the ACL is not protected, or any rule grants another identity. Test W1 covers this.

### Cleanup

- `try`/`finally` around both sides: dispose the stores, call `SqliteConnection.ClearAllPools()` (pooled handles keep files open; tests do the same, for example `tests/Bower.UnitTests/QueueBackupTests.cs:216`), close `preview.lock` (see the sweep below), delete the work root recursively, then confirm it no longer exists.
- Output is written to stdout **only after** cleanup succeeds. A failed delete prints the path on stderr and exits 1.
- Ctrl+C cancels through the command's cancellation token and runs the same `finally`. A `SIGKILL` or power loss leaves a `bower-policy-preview-*` directory holding redacted synthetic rows. The preview never deletes anything outside its own root and the sweep below.
- Start-up sweep (decision Q4, 2026-11-13). Before it creates its own root, the preview lists the top level of the temp path and deletes a directory only when all of these hold: the name matches `bower-policy-preview-*`; it is a real directory, not a symbolic link or junction (checked without following links); its owner is the current user (Unix uid, Windows owner SID); its last write time is more than 24 h before now; and no preview is still using it. Age alone cannot show that: writes to `baseline/queue.db` and `candidate/queue.db` do not update the root's last write time, and a run can last, or be suspended for, more than 24 h. So each run, straight after creating its root and before any database is opened, creates `preview.lock` in the root and holds it open with an exclusive lock (`FileShare.None`) until cleanup. The operating system releases the lock when the process exits, including after `SIGKILL`. The sweep opens `preview.lock` with `FileShare.None` and leaves the directory alone if that open fails because the file is in use. A directory without `preview.lock` is judged on the other checks only. Deletion is recursive but does not follow links inside the directory. A directory that fails any check is left alone. A failed delete is a warning on stderr and does not stop the run. Apart from trying the lock, the sweep never reads the contents.

### What preview does not model

The output's `notExercised` list and the documentation must state these:

- Actual traffic: arrival rates, concurrency, interleaving within one tick, and the noisy-neighbour effects of real producers.
- Producer retries: only retries written as explicit repeated steps are run. Retry timing, lost responses and back-off are not modelled.
- Destination delivery, acknowledgement, retention, archive and Sentinel validation: nothing is leased or sent.
- Production capacity, backpressure and free-space watermarks: the cap is a safety bound and `StorageGuard` is absent.
- Worker close lag (up to 5 s), crash during a transaction, host clock stepping back, multiple producers or source adapters, multiple collectors, pack parsers (inputs are semantic events), source silence, and management privacy assignment.
- The Azure Functions collector, which never suppresses (`docs/operations/suppression-archive-and-source-silence.md:48-49`).

## Tests (plan step 4)

Unit tests drive an internal entry point that takes loaded bundles, parsed scenario and a test-supplied work root, so the test can inspect the side databases before cleanup. CLI tests cover argument handling, exit codes and stdout. Pinned outputs go in `tests/fixtures/policy-preview/`.

| # | Area | Test |
|---|---|---|
| B1 | Boundary times | Event at `window_end - 100ns` counts in the old window. Event at exactly `window_end` opens the next window (`src/Bower.Persistence/SqliteEventStore.Suppression.cs:73-74`) |
| B2 | Boundary times | A close at `window_end - 1s` closes nothing. A close at exactly `window_end` closes (`<=`, `src/Bower.Persistence/SqliteEventStore.Suppression.cs:159`) |
| B3 | Boundary times | Steps with equal `at` run in file order. A decreasing `at` is exit 1 |
| B4 | Boundary times | `timeGenerated` 6 minutes after `at` is quarantined at validation, on both sides |
| K1 | Per-key windows | Two users get separate allowances (as `tests/Bower.UnitTests/SuppressionTests.cs:132-156`) |
| K2 | Per-key windows | A missing key field gives an empty value, so those events share a window |
| K3 | Per-key windows | `labels.<key>` as a key field |
| K4 | Per-key windows | A candidate privacy profile that masks the key field merges keys; the change is shown as more suppression |
| K5 | Per-key windows | 1,001 distinct keys is exit 1, the work root is removed and stdout is empty |
| A1 | Aggregate vs suppress | The same steps under `accept` with `allowPerWindow: 2` and under `aggregate`: steps change from queued to suppressed, and the summary shows `admittedCount` 0 |
| A2 | Aggregate vs suppress | An `aggregate` policy without `suppression`, or with `allowPerWindow` other than 0, fails to load: exit 1 |
| D1 | Duplicates | A repeat of an admitted event after the allowance is spent is a duplicate and is not counted (`src/Bower.Persistence/SqliteEventQueue.cs:338-343`) |
| D2 | Duplicates | A repeat of the first event before any suppression is a duplicate and does not change the allowance |
| D3 | Duplicates | A repeat of a suppressed event is counted again (`docs/operations/suppression-archive-and-source-silence.md:28-31`) |
| D4 | Duplicates | A repeat of an aggregated event is counted again |
| D5 | Duplicates | The same event id with different content is `identity-conflict` (`src/Bower.Core/SecurityEventProcessor.cs:404-411`) |
| R1 | Restart and closure | A restart mid-window continues the counts (as `tests/Bower.UnitTests/SuppressionTests.cs:90-104`) |
| R2 | Restart and closure | A restart after `window_end` and before the next close summarises once, with the same summary id as without the restart |
| R3 | Restart and closure | Repeated closes queue no second summary (`tests/Bower.UnitTests/SuppressionTests.cs:106-114`) |
| R4 | Restart and closure | A window still open at `end` is reported as `open-at-end` with its persisted admitted and suppressed counts and first and last suppressed times, and is not counted in `summaries queued`. A side with `summaryRefused` runs no drain |
| R5 | Restart and closure | 1,000 keys each with a suppressed window open at `end`: one drain call reports all 1,000 as `open-at-end` |
| S1 | Summary policy denial | Candidate summary policy requires a field the summary lacks: `summaryRefused` is reported, windows stay open, later steps are still processed, and exit is 0, or 3 with `--fail-on-change` |
| S2 | Summary policy denial | A suppressing bundle with no summary policy fails to load: exit 1, nothing on stdout (`src/Bower.PolicyEngine/PolicyLoader.cs:205-222`) |
| Q1 | Queue pressure | A scenario that fills the 64 MiB side cap exits 1 with `preview-capacity-exceeded`, nothing on stdout, and the root removed |
| Q2 | Queue pressure | Each static limit plus one is refused before any bundle loads |
| Q3 | Queue pressure | The production tests for counters at capacity stay unchanged: `tests/Bower.UnitTests/DurabilityAdversarialTests.cs:236-307` and `tests/Bower.UnitTests/QueueEnqueueBatchTests.cs:244-290` |
| P1 | Redaction failure | An injected redactor that throws: the step is quarantined at redaction, and the side database has zero `queue_events_v5` rows and zero `suppression_windows` rows |
| P2 | Redaction failure | A redaction that changes the event id is quarantined and nothing is stored |
| P3 | Redaction | A secret-shaped canary in a key label is masked in the stored `key_values` and in the summary. The canary bytes do not occur in any side file before cleanup, nor in stdout or stderr |
| P4 | Privacy | Canary strings in every string field of every event: none occurs in stdout or stderr. No event id, key value or key hash is printed |
| H1 | Comparable hashes | Bundle hashes equal those `policy diff` prints for the same side options |
| H2 | Comparable hashes | Stdout contains no `scenarioHash` field and no SHA-256 of the scenario bytes or of any event file's bytes |
| H3 | Determinism | Two runs of the same inputs give byte-identical stdout, using different work roots |
| H4 | Determinism | Runs under a different `TZ`, `LANG` and `CultureInfo` give identical stdout |
| H5 | Determinism | The same bundle on both sides gives `changed: 0` |
| H7 | Change count | Identical step outcomes but `summaryRefused` on the candidate only: `changes.summary` is present, `changed` is 1 and `--fail-on-change` exits 3. Identical step outcomes but a different window count or `summary` status: `changes.windows` has the entry, `changed > 0` and exit 3 |
| H6 | Determinism | Running candidate first, then baseline, gives identical output |
| U1 | Unchanged diff | Existing pinned outputs `tests/fixtures/bundle-diff/expected-*.json` pass unchanged (`tests/Bower.UnitTests/PolicyBundleDiffTests.cs:155-168`) |
| U2 | Unchanged diff | Directory-mode diff output and `NotExercisedOffline` are unchanged (`src/Bower.Cli/Commands/PolicyCommands.cs:187-196`, `tests/Bower.UnitTests/PolicyBundleDiffTests.cs:231`) |
| C1 | Cleanup | The work root is gone after success, scenario error, bundle load failure, limit failure, capacity failure and cancellation |
| C2 | Cleanup | `--database`, `--queue` and any unknown option are exit 1. No file is created outside the work root (the working directory listing is unchanged) |
| C3 | Cleanup | On Unix, the root is 0700 and the queue files are 0600 |
| C4 | Stale sweep | Matching directories older than 24 h owned by the current user are removed. Ones 23 h old, owned by another user (or with a different owner SID on Windows), with another prefix, or that are symbolic links, or junctions on Windows, are kept. A link inside a stale directory, or a junction on Windows, is removed without touching its target |
| C5 | Stale sweep | A delete failure (for example a read-only file) is a stderr warning, the run continues, and stdout is unchanged |
| C6 | Stale sweep | Two concurrent previews: the first holds `preview.lock` and its root's last write time is set more than 24 h back. The second preview's sweep keeps that root, and the first completes with unchanged stdout. After the first process is killed, its lock is released and the next sweep removes the root |
| W1 | Windows private root | On the `windows-latest` CI job, with a `BOWER_REQUIRE_*` variable so a skip fails there (pattern `tests/Bower.UnitTests/WindowsSettingsFileTests.cs:15-20`): the root's ACL is protected, grants only SYSTEM, Administrators and the current user, and each side database inherits it. A forced ACL check failure (test seam) is exit 1 before any database file exists, with the root removed and stdout empty |
| I1 | Input strictness | Unknown property, duplicate property, null, absolute path, `..`, symbolic link component, bad time format, `dataClassification` other than `synthetic`, duplicate step id: each is exit 1 |
| L1 | Labelling | Output has `simulated: true` and `kind: PolicyPreview`, and no ledger, signature or path fields |
| X1 | Parity | Run the same scenario through the collector host with a fixed clock (pattern `tests/Bower.UnitTests/CollectorHostTests.cs:631-679`). Per-step queued, duplicate and suppressed outcomes, summary ids and counts must equal the preview's |
| X2 | Parity | `SuppressionParityVectorTests` (`tests/fixtures/core-vectors/suppression-vectors.json`) still pass. Any later suppression change updates X1, the pinned preview fixtures and the population-diff documentation, as the plan's maintenance rule requires |

### Adversarial and crash tests before any real queue change

The recommended design makes no change to `src/Bower.Persistence`. If implementation finds it needs one (an in-memory mode, a window-listing API, a pool or disposal API, or different pragmas), the following must be written and passing **before** that change merges, as `AGENTS.md` ("Queue or redaction changes require crash/recovery or adversarial tests") and `src/Bower.Persistence/AGENTS.md` require:

- a process kill between summary insert and window delete, then restart: exactly one summary, and the counts are preserved;
- `SQLITE_FULL` and a pinned WAL reader during `AdmitAsync`: the counters are unchanged and the event is not counted (extending `tests/Bower.UnitTests/DurabilityAdversarialTests.cs:236-307`);
- concurrent suppressible enqueues under the write lock: no allowance overshoot;
- batch rollback of a suppression write (extending `tests/Bower.UnitTests/QueueEnqueueBatchTests.cs:244-290`);
- for any schema touch: upgrade, restart and corruption-path tests;
- proof that the collector's queue path cannot reach the new code path.

## Not exercised / not proven

- **Nothing in this design is implemented or run.** No code, tests or measurements exist. Every behaviour above is cited from source and existing tests, not observed in a preview run.
- Parity test X1 does not exist yet. Parity is argued from shared code, not shown.
- Run time is not measured. Each step commits with `synchronous = FULL` (`src/Bower.Persistence/SqliteEventQueue.cs:1246`), so 10,000 steps per side means up to about 20,000 fsyncs.
- That `Directory.CreateTempSubdirectory` gives 0700 on every supported Unix is not verified here (test C3).
- Behaviour on Windows (file handles kept open after `ClearAllPools`, and whether SQLite's `-wal` and `-shm` files inherit the root's protected ACL) is not verified (test W1).
- That one drain call at `end + 86,400 s` reports every suppressed open window is argued from the close query and the key limit, not run (test R5).
- Whether `System.Text.Json` in this target framework can refuse duplicate properties under the CLI's source-generated context is not confirmed. If it cannot, the scenario reader needs a pre-scan with `Utf8JsonReader`.
- Residue after `SIGKILL` cannot be prevented, only bounded (redacted synthetic data in an owner-only directory, removed by the next run's sweep once older than 24 h). If the preview never runs again, the residue stays.
- That last write time and owner checks behave the same on every supported file system (including network home directories and Windows junctions) is not verified (tests C4 and C5).
- That `FileShare.None` gives an exclusive lock that another process sees on every supported Unix file system is not verified (.NET uses advisory locks there, which some network file systems do not honour). Test C6 covers local file systems only.
- The `dataClassification` attestation cannot prove the input is synthetic.
- A preview result is not evidence of production behaviour under real traffic, capacity or delivery. It shows what the production code does for the given ordered synthetic steps.

## STOP assessment

| STOP condition (plan) | Assessment |
|---|---|
| Premises changed since the planned commit | Not hit: drift diff is empty |
| Reuse of queue logic requires access to an existing queue | Not hit: each side gets a new file in a private root the preview creates (fail-closed on Windows, test W1). No option accepts a path to a queue, and test C2 enforces this. Open windows are read by draining that disposable file through the existing close API, not by a new queue API |
| Preview cannot keep redaction before persistence | Not hit: the only write path for event content is the production processor, which redacts first (`src/Bower.Core/SecurityEventProcessor.cs:233-256`, `:360-402`). The end-of-run drain writes only summaries built from already redacted window rows. Tests P1–P3 enforce this |
| Simulation cannot be distinguished from production evidence | Not hit, provided the preview uses a separate subcommand, prints `simulated: true` and `kind: PolicyPreview`, prints no ledger heads, signatures or paths, and is documented as such. Test L1 enforces this |
| Second approximate algorithm without parity assessment | Avoided: option C rejected above |

## Open questions

Questions 1, 4 and 8 are decided. See [Decisions (2026-11-13)](#decisions-2026-11-13).

1. **Decided (Q1):** the attestation is enough. Is a `dataClassification: synthetic` attestation enough, or should the product owner require something stronger (for example a required `labels.synthetic` on every event)?
2. Is a process-wide `SqliteConnection.ClearAllPools()` acceptable in the CLI? The preview is the only SQLite user in that process. The alternative is a store disposal API, which would be a queue change.
3. Is 10,000 steps per side the right ceiling once the fsync cost is measured?
4. **Decided (Q4):** sweep at start, same user, older than 24 h. Should the preview sweep its own stale `bower-policy-preview-*` directories (same user, older than 24 hours) at start, or leave them for the operator?
5. Should a later slice model several producers (source adapters) or clock step-back (`tests/Bower.UnitTests/SuppressionTests.cs:182-209`)? Both are excluded from the first slice.
6. Resolved: on Windows the root gets a protected owner-only ACL, checked before any database is written, or the run fails (test W1). Open: should the queue itself later set an ACL on Windows? That would be a queue change.
7. Should windows that only admitted events (no suppression, so no close callback) appear in `windows`? The first slice reports them through step outcomes only. Reporting them would need a read-only window-listing API in `Bower.Persistence`, a scoped queue change that needs the adversarial and crash tests above first.
8. **Decided (Q8):** accepted for the first slice. Is it acceptable that a report cannot be tied to its input bytes? If not, a later slice could add an operator-supplied HMAC key for an input digest, at the cost of key handling and of reports with different keys not being comparable.

## Delivery notes

- When implemented, add a "Stateful preview" section to `docs/operations/suppression-archive-and-source-silence.md`. Keep lines 46–48 true for `policy diff`. Add the scenario schema, update the command catalogue, and add a scoped note to `src/Bower.Cli` if one is introduced.
- The plan's index status (`plans/README.md`) has not been updated in this task, as instructed.

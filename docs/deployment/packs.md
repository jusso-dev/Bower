# Bower Packs

A pack bundles everything Bower needs for one application type, versioned and
signed:

| Content | Purpose |
|---|---|
| `policies/*.yaml` | Default-deny selection for the app's event types |
| `privacy.yaml` (optional) | Privacy profile: detector actions, HMAC field rules, length limits |
| `parsers/*.json` | Custom log parser configurations, optionally with a signed [transform program](../developer-integration/transform-language.md) |
| `detections/*.yml` | Sigma-compatible detections |
| `samples/*.jsonl` | Expected decisions and values that must never survive redaction |
| `dcr/bower-dcr.json` | Generated table and DCR template (`dcr: true`) |

Examples: [`packs/linux-ssh-gateway`](../../packs/linux-ssh-gateway) and
[`packs/linux-journald-ssh`](../../packs/linux-journald-ssh) (uses transforms).

## Build, sign, verify

```bash
bower keys generate --out-dir ./keys
bower pack build packs/linux-ssh-gateway --key ./keys/bower-signing.key.pem --out ./artifacts/packs
bower pack verify ./artifacts/packs/linux-ssh-gateway-1.1.0.bowerpack --trusted-key ./keys/bower-signing.pub.pem
bower pack test   ./artifacts/packs/linux-ssh-gateway-1.1.0.bowerpack --trusted-key ./keys/bower-signing.pub.pem
bower pack diff   old.bowerpack new.bowerpack --trusted-key ./keys/bower-signing.pub.pem
```

`build` parses and validates every file **and runs every sample**; a pack whose
samples fail cannot be signed. Sample lines:

```json
{"name":"TFN never leaves the host","expect":"accept","mustNotContain":["123456782"],"event":{ … "timeGenerated":"{{now}}" … }}
```

`expect` is one of the policy decisions (`accept`, `reject`, `sample`, `aggregate`,
`redact-and-accept`, `quarantine`, `dead-letter`; default `accept`). `accept` means
"selected locally": it also passes when the Privacy & Secret Protection Engine redacted something
(`redact-and-accept`), so prove the redaction with `mustNotContain`. Write
`redact-and-accept` to require that redaction happened; it fails for an event that
was accepted unchanged. Every other expectation must match exactly.

Sample lines follow [`schemas/packs/pack-sample.schema.json`](../../schemas/packs/pack-sample.schema.json)
(version 2: adds `expectFields` and parser names; every version 1 line is still valid).
Members other than `name`, `expect`, `event`, `raw`, `parser`, `mustNotContain`,
`expectedDetections` and `expectFields`, and repeated members, fail the build, so a
mistyped assertion cannot pass silently.

### Field assertions (`expectFields`)

`expectFields` asserts the shape of the event **after redaction**, the value that would
leave the host. Keys are dotted paths into the redacted event (`source.ipAddress`,
`attributes.bowerDetections.0.ruleId`); values are `"present"`, `"absent"` (missing or
null) or an exact string, number or boolean:

```json
{"name":"failed password","parser":"sshd-journald","raw":{ … },"expect":"accept",
 "expectFields":{"eventOutcomeReason":"InvalidCredentials","source.ipAddress":"203.0.113.5","actor.username":"present","labels":"absent"}}
```

- Path segments are 1–128 of `A-Z a-z 0-9 _ $ @ -`; a numeric segment indexes an array.
  At most 64 paths per sample, 16 segments and 256 characters per path.
- Types are strict: `5` does not match `"5"`. Numbers compare by value.
- An expectation can only hold a post-redaction value. A string that equals a
  pre-redaction value missing from the redacted event (a pseudonymised username, a raw
  field the mapping never forwards) or that contains a `mustNotContain` entry fails the
  sample, and the value is not printed. Use `"present"` for pseudonymised fields: test
  HMAC keys are random.
- Assertions need a redacted event: on a sample that is rejected before redaction (no
  mapping match) or quarantined they fail with `Field assertions need a redacted event`.
- There is no snapshot mode: expectations are only ever written by the pack author.

Failures name the path and show only redacted values:

```text
FAIL  failed password (expected accept, got redactandaccept)
      Field 'eventOutcomeReason': expected "PublicKeyRejected", got "InvalidCredentials".
      Field 'source.ipAddress': type mismatch, expected number 5, got string "203.0.113.5".
      Field 'request.correlationId': expected present, but it is absent.
      Field 'actor.username': the expected value does not survive redaction; expect only post-redaction values.
```

`bower pack build` refuses to sign on any failure and prints the same lines.

### Parser tests and CI reports

```bash
bower pack test ./artifacts/packs/linux-journald-ssh-1.0.1.bowerpack --trusted-key ./keys/bower-signing.pub.pem \
  --parser sshd-journald --report ./pack-test.xml --report-format junit
```

`--parser` runs only the raw samples of one parser, named by file name without
extension (`sshd-journald`) or pack path (`parsers/sshd-journald.json`); it exits 1 if
that parser has no samples. A raw sample's `parser` may also be that name instead of a
zero-based index. Indexes count parsers in manifest (ordinal path) order, at build and at
load. `--report FILE` writes a JSON report (`--report-format json`, the default) or JUnit
XML (`junit`) with each sample's name, decisions and problems; it never contains raw
values. CI builds every pack under `packs/` with an ephemeral key, runs `pack test` with a
JUnit report in both the C# and Rust CLIs, and uploads the reports.

`diff` is the policy population diff: event types added or removed, required fields,
actions and score thresholds, and policies changed without a version bump (exit 1).

## Format

A `.bowerpack` is a zip with `manifest.json` (canonical JSON listing every file with
its SHA-256 and role, the policy ids/versions/hashes and a pack hash),
`manifest.sig` (ECDSA P-256 over the manifest) and `content/…`. Verification fails
on a bad signature, an untrusted key, a modified, missing or unlisted file, path
traversal, more than 500 entries, a file over 1 MiB or an archive over 50 MiB.
Nothing is loaded from an unverified pack.

## Using packs on a collector

```text
BOWER_PACKS=/etc/bower/packs/linux-ssh-gateway-1.1.0.bowerpack
BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/bower-signing.pub.pem
BOWER_PRIVACY_HMAC_KEY_FILE=/run/secrets/bower-hmac      # if the profile uses hmac
BOWER_PRIVACY_HMAC_KEY_ID=k2026
```

Pack policies are added to the policy directory's; duplicate policy ids fail start-up.
Only one privacy profile may be active (from a pack, `BOWER_PRIVACY_PROFILE` or management; see [managed privacy profiles](../privacy/managed-privacy-profiles.md)). The
collector reports a **policy bundle hash** (policies, packs and profile) to management,
which compares it with the policy an administrator assigned.


## Local parser and detection activation

Both collector runtimes retain verified pack components. Authenticated `/v1/status`
reports `parserStatuses` in manifest parser order, `detectionStatus`, and `dcrStatus`:

- `active-local-json`: an explicit signed JSON `runtime` mapping is installed.
- `inactive-preview-only`: parser has no runtime mapping. CSV, key/value and regex
  configurations remain preview tooling; they do not expose raw ingestion.
- Detections: `active-local` when present, otherwise `absent`. Evaluation runs on
  selected, privacy-redacted semantic events, including `/v1/events` submissions.
- DCR: `packaged-only` when present, otherwise `absent`. Loading never deploys a DCR,
  installs Sentinel analytics rules, or establishes destination delivery.

Duplicate pack IDs or detection IDs fail startup. The combined bundle permits at
most 64 parsers and 64 detections. New runtime mappings must be signed and validated;
there is no unsigned activation endpoint or fallback parser.

`POST /v1/packs/{packId}/parsers/{zeroBasedIndex}/events` accepts **one JSON object**.
The SSH gateway 1.1.0 mapping expects an upstream SSH/PAM normalizer's JSON record:

```json
{"id":"host-a:sshd:12345","timestamp":"2026-10-23T10:00:00Z","user":"synthetic-user","source_ip":"203.0.113.5","result":"failure"}
```

Send a current timestamp and an original ID stable across retries. This is an
explicit normalized JSON adapter, not a parser for arbitrary `sshd` text, a file
tailer, or a generic raw-log endpoint. Only `result: failure` maps to
`authentication_failure`. The signed mapping fixes application `ssh-gateway`,
environment `production`, action `authentication.attempt`, and result `failure`.
Policy still decides whether the mapped event is accepted. Unmapped fields are
never copied to labels, attributes or persistence.

Authentication and the shared ingest rate limit run before reading the body.
Producer scopes apply to the mapped application and source identity before
processing. The raw body limit is 32 KiB, including whitespace and ignored fields;
JSON depth is 16, root fields at most 64, mapped strings at most 2048 UTF-16 units,
and original IDs at most 128. Duplicate JSON keys, missing/mistyped mapped fields,
invalid timestamps/IPs, unknown targets and unbounded mappings fail closed.
Runtime mapping targets are restricted to identity/time, actor, source IP,
correlation ID and outcome reason. Secrets and unrestricted bodies cannot be
forwarded through arbitrary field mappings.

A parser may carry a signed transform program (`runtime.transforms`, optional
`runtime.tables`) that reshapes the parsed record before `match` and `fields` apply:
parse, transform, map, redact, select, queue. The program is validated at build and
load, is bounded (steps, sizes, depth) and cannot set the security decision, write
reserved or credential-like fields, or move sensitive values into non-sensitive fields.
A run-time failure (`transform-type-error`, `transform-budget-exceeded`,
`transform-size-exceeded`) returns HTTP 400 with decision `quarantine` and the code as
the only reason; nothing is persisted and `/v1/status` counts it under stage
`transform`. Collectors that predate transforms refuse to load such a parser. See the
[transform language reference](../developer-integration/transform-language.md).

Responses: 202 durable local acceptance, 200 duplicate, 400 invalid input or
transform quarantine, 401
missing/invalid credential, 403 scope denied, 404 inactive/unknown parser, 409
event identity conflict, 413 oversize, 415 wrong content type, 422 unmatched or
policy rejected, 429 rate limit,
503 queue capacity. Cancellation while reading persists nothing. Once processing
has reached durable enqueue, a disconnected client may miss its response; retry
the identical event. Existing queue identity/conflict and retention semantics apply.
No response from this endpoint proves Sentinel arrival.

Local detections enrich that same durable semantic row with
`attributes.bowerDetections`: sorted rule ID, version, SHA-256 rule hash and MITRE
technique IDs. A fresh engine per event avoids retry-dependent alert suppression.
Random alert IDs, wall-clock detection times, raw values and matched values never
enter this metadata. Producer-supplied `bowerDetections` is removed even when no
rules are installed. There is no second detection queue or independent acknowledgement.

Raw pack samples use `raw`, `parser` and `expectedDetections` instead of `event`:

```json
{"name":"raw failure","parser":0,"expect":"accept","raw":{"id":"sample-raw","timestamp":"{{now}}","user":"synthetic-user","source_ip":"203.0.113.5","result":"failure"},"expectedDetections":["bower-pack-ssh-auth-failure-001"],"mustNotContain":["synthetic-user"]}
```

Raw samples run the parser's transforms with the `{{now}}` time as evaluation time; a
transform failure is decision `quarantine`, so an adversarial record can be pinned with
`"expect":"quarantine"`. Build executes mapping, privacy, selection and detection
expectations before signing. Actual host tests separately establish queue, authentication, scope,
rate, replay, restart, cancellation and backpressure behavior. These tests use
synthetic local input; they are not destination query evidence.

## Supported Sigma subset and upgrade impact

Conditions support selection identifiers, parentheses and case-insensitive `not`,
`and`, `or`, with precedence **not, then and, then or**. Selections are mappings:
fields combine with AND; a field's alternative list combines with OR. Field names
match exactly (case-insensitive), never by suffix. Standard envelope fields and
labels are strings; scalar attributes use the explicit `attributes.<name>` namespace.
Labels cannot override envelope fields or the attributes namespace. Ambiguous
case-duplicate labels/attributes fail evaluation. Events also fail evaluation if
either collection exceeds 256 entries, or an evaluated field name exceeds 128
UTF-16 units (including the `attributes.` prefix) or its string value exceeds
65,536 UTF-16 units. These failures are never successful empty detection results:
selected events with active rules return HTTP 400, decision `quarantine`, reason
`pack-detection-failed`, without persisting the source payload or consuming a
detection fingerprint. Privacy redaction runs first, so values truncated into
bounds can still be evaluated. Reserved `bowerDetections` attributes in any casing
are stripped before these checks and regenerated only from local rule matches;
the generated evidence does not count against the source attribute limit.

The C# engine throws `InvalidDataException` for these failures; the Rust engine's
`evaluate` and `evaluate_json` return `Err(DetectionError::InvalidData)`. Callers
must handle evaluation failure separately from a successful result with no alerts.

Unmodified scalar strings use whole-value, case-insensitive equality. Explicit
`contains`, `startswith`, `endswith` work only on strings. YAML booleans and signed
64-bit integers compare only with the corresponding JSON scalar type, never with
strings such as `"true"` or `"42"`. Numeric attributes must use integral JSON tokens;
fractions/exponents, null matching, regex, wildcard values, payload searches,
selection wildcards (`1 of ...`), aggregation/correlation syntax, unknown selections,
unknown/chained modifiers and nested selections are unsupported and rejected at
load/build time. Rules are bounded to 256 KiB, 64 selections, 64 clauses per
selection, 64 alternatives per clause, 4096 UTF-16 units per value, 256 condition
tokens and depth 32. YAML expansion is bounded to 8192 nodes and depth 32.

Previously signed packs still require verification and semantic validation; packs
using formerly tolerated unsupported grammar now fail startup and must be corrected
and re-signed. `DetectionFields` is a structured internal encoding, not the old
flattened matching string. Consumers constructing rules manually must use the loader.
Exact equality intentionally removes accidental substring matches. The GCP pack
1.1.1 explicitly lists qualified IAM service-account-key methods in detection
version 1.1.0. Policies are unchanged by this correction.

Raw parser IDs must be globally unique across producers and stable on replay.
On 409, preserve upstream events pending repair; see
[event identity conflict recovery](../operations/event-identity-conflicts.md).

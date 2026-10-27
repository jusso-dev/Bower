# Threat model

## Assets

Security event integrity, secrets and personal data, policy/configuration
integrity, SQLite durability, Azure identity, destination routing and assessment
evidence.

## Threats and current controls

- Malicious JSON, log/newline injection and oversized records: strict JSON object
  parsing, depth 32, 1 MiB ingress limit, structured serialization and JSONL
  records written from parsed envelopes. Enum fields (`eventResult`,
  `eventSeverity`, `actor.type`, `security.decision`) accept a declared member name
  (any case) or a declared ordinal only; undefined ordinals, numeric strings and
  comma-joined names are schema-invalid, never fingerprinted or queued. Pipeline
  document node kinds follow the same rule in both runtimes.
- Poison records at delivery: a queued payload the Azure output can never upload
  (invalid JSON, a repeated top-level property, invalid escapes) dead-letters alone
  as `payload-invalid-json`; it never fails or blocks the rest of the batch.
- Secret leakage: secret field-name removal (exact names and fragments), value
  detectors over strings, numbers and key names, fail-closed HMAC, and
  quarantine on any redaction error, all before persistence; payload-free
  operational logs; no token persistence.
- Replay and duplicate delivery: unique stable fingerprint and event ID, leased
  delivery transitions and acknowledgement records. Generated privacy alerts,
  EC2 host events and AWS records use deterministic ids so retries and re-reads
  deduplicate. Acknowledged rows are kept for the retention window
  (`BOWER_QUEUE_RETENTION_HOURS`, default 7 days) to preserve deduplication.
  Deduplication is checked before backpressure, so a resend to a full queue is
  acknowledged as a duplicate rather than retried. Malformed queue input is an
  error, never a silent duplicate.
- Queue/disk exhaustion: the byte cap counts undelivered rows only, a recurring
  retention job purges acknowledged rows, capacity returns HTTP 503 for producer
  back-off, and ingest is rate limited (HTTP 429). Poison events dead-letter
  individually or after `BOWER_MAX_DELIVERY_ATTEMPTS`. Filesystem quota and
  disk-free health enforcement remain required.
- Hiding activity behind suppression: suppression is opt-in per policy, refused for
  `neverSample` policies, counted durably in the enqueue transaction and reported
  by a policy-approved summary event per window with the key values; a policy set
  that suppresses must accept the summary or it does not load, and a refused summary
  keeps the window open rather than dropping counts. Poorly chosen key fields can
  still merge distinct actors, so review keys like any policy change.
- Silent loss of a source: optional source expectations degrade `/health` and the
  heartbeat when an application stops delivering accepted events.
- Archive tampering or loss after retention: archive segments carry file digests and
  continue the queue ledger chain; `bower archive verify --anchor` recomputes every
  link and proves it reaches a management-witnessed head. Retention purges only events
  covered by a verified archive of the same queue (segments present and intact,
  contiguous from at or below the oldest stored event, chain equal to the queue
  ledger) and otherwise purges nothing. Archive writers hold an exclusive lock and never
  replace a committed segment. Write-once storage for the archive directory remains an
  operator control.
- Policy tampering: loaded policy is validated and hashed. Signed bundles and file
  permission checks remain required.
- Parser exploitation: no arbitrary code execution. YAML documents are size-limited.
  XML parsers are not present. Signed pack parsers may carry a transform program
  (new trust boundary: signed pack content operating on raw, pre-redaction records
  inside the collector). Controls: only signed packs from trusted keys load; a fixed
  allow-list of 20 pure functions, no loops, recursion, I/O, environment, randomness or
  clock (evaluation time is an explicit input); static limits and a 1,000,000-step
  per-record budget with string, array, record and output size limits; Bower's own
  linear-time regex engine (Pike VM, no backtracking); static sensitivity flow checks;
  reserved targets (`security*`, `bower*`, credential-like names). Failures quarantine
  the record before redaction and persist nothing; errors carry only a statement
  number, column and code, never statement text or values. Transform output reaches
  persistence only through the allowlisted semantic mapping and the privacy engine.
  Management preview validates but never runs transforms.
- Pack test output leaking raw values: `bower pack build` error text, `bower pack test`
  output and its JSON/JUnit CI reports (new output: report files and CI artifacts)
  carry sample names, decisions and `expectFields` diffs only. Field assertions are
  checked against the redacted event; an expected string that equals a pre-redaction
  value missing from the redacted event, or that contains a `mustNotContain` entry,
  fails the sample without being printed, so a pack cannot be signed with, or report,
  a raw sensitive expectation. Unknown sample members fail, so a mistyped assertion
  cannot pass silently. CI signs with an ephemeral key and never publishes the packs.
- Credential theft and overprivilege: one explicit Azure credential source
  (`BOWER_AZURE_CREDENTIAL`: managed identity by default, workload identity,
  environment or Azure CLI) instead of `DefaultAzureCredential` probing.
  The management heartbeat refuses non-HTTPS remote endpoints. Credentials and
  access tokens are never logged or stored by Bower.
- Destination redirection: endpoint/DCR values are explicit and endpoint requires
  HTTPS. Signed configuration and Azure resource validation remain required.
- Syslog listeners (new network trust boundary, `BOWER_SYSLOG_CONFIG`): bind loopback
  by default and refuse a non-loopback address unless the protocol is TLS (optionally
  with client certificates) or `allowInsecureNonLoopback` is set; a per-listener
  sender allow-list; strict UTF-8 RFC 5424/3164 parsing with stable failure codes;
  64 KiB frames, connection caps, a per-frame idle timeout against slow loris, bounded
  submissions and a bounded UDP buffer. Accepting a sender never accepts its events:
  only a route to an active signed pack parser that selects the record, then
  redaction and policy, can queue one. Counters only; no frame content is logged or
  exposed. See [syslog source](../deployment/syslog-source.md).
- Event injection: the collector requires a shared bearer token
  (`BOWER_INGEST_TOKEN`, compared in constant time) whenever it listens beyond
  loopback and refuses to start without one. Kubernetes manifests add a
  NetworkPolicy limiting ingress to labelled producer pods. `/health` exposes
  status only; queue and job metadata need the token.
- Destination overload and throttling: the Logs Ingestion output adapts request
  concurrency (bounded 1 to `MaximumConcurrency`) and stops starting batches after
  a `Retry-After`. Back-pressure waits for a request slot over the already-leased
  batch; queue byte caps and producer 503s still apply. The `delivery` status block
  is counters, limits and a deadline only, behind the token. No new trust boundary.
- Management command channel (heartbeat v2): commands travel outbound only, in the
  heartbeat response, and come from a closed set. That set is `fetch-bundle`,
  `run-canary`, `reload` and `rotate-credential` (token-enrolled collectors only). No
  command carries code, paths or arguments.
  - Signing: each command is signed with a dedicated P-256 key and bound to one
    collector id, a 128-bit nonce and an expiry of at most 1 hour. The signed `kind`
    keeps a command signature from verifying as any other Bower document.
  - Collector checks: the collector verifies against its own trusted keys, so a TLS
    inspection proxy or a network attacker that alters the response cannot forge or
    replay a command.
  - At most once: a durable ledger written before execution makes each command run at
    most once across restarts.
  - Refusals: unknown, expired, replayed and forged commands are refused, reported and
    audited.
  - Blast radius of a compromised management plane or signing key: it can only issue
    the enumerated commands. That means fetching the currently assigned (already
    two-person approved) privacy profile, queuing synthetic canaries (bounded by
    lifetime, 8 per heartbeat and 16 outstanding), and restarting the collector at most
    once every 10 minutes. It cannot read events, change policy or privacy content,
    approve anything or run code.
- Token enrolment (new trust boundary: an anonymous endpoint, and a credential the
  collector holds on disk). See [collector enrolment](../architecture/collector-enrolment.md).
  - Token theft or guessing: tokens carry 256 random bits, are single use, expire (24
    hours by default, 7 days at most), are bound to an environment and optionally a
    collector id, and are stored only as SHA-256 hashes. They are shown once, never
    logged and never returned again. A stolen unused token enrols at most one collector,
    which still waits in `Pending` for a reasoned approver decision, so it buys no
    access to events, policy or commands. Every refusal is audited with its reason.
  - Anonymous endpoint abuse: `POST /api/collectors/enrol` is the only anonymous write.
    It has a 16 KiB body limit, 10 requests per minute per address, one generic refusal
    message (the reason is only in the audit) and a constant-time hash comparison.
  - Take-over: a token cannot enrol over a collector id bound to an Entra principal, and
    cannot re-enrol a suspended or revoked collector. An enrolled principal
    (`enrolled:<collectorId>`, never a GUID) has only `Bower.Collector` and can act only
    for its own collector id.
  - Credential theft: the credential is the collector's own P-256 key; management holds
    only the public key, so a management database leak yields nothing that can
    authenticate. The private key sits in an owner-only file next to the queue; anyone
    who can read it can already read the queue. Each request carries a 5-minute signed
    assertion whose exact canonical bytes, signed `kind`, lifetime and clock skew are
    checked, so an assertion cannot be reused as any other Bower signature or kept for
    long. TLS-inspection proxies see assertions as they see Entra tokens.
  - Revocation and rotation: every request re-reads the credential, so revocation takes
    effect on the next heartbeat. Credentials expire after 30 days; collectors rotate
    when 10 days remain, and the old key is retired on the first use of the new one.
- Native installers (new trust boundaries: the package or MSI an administrator runs as
  root or SYSTEM, and the offline bundle that carries a pre-seeded token to the host).
  See [installers](../deployment/installers.md).
  - Tampered package: packages are built in CI from the `publish` artefacts and signed
    (rpm/deb GPG, Authenticode) only when the signing secrets are configured; until
    then they are unsigned, the bundle says so (`UNSIGNED.txt`), and the Windows
    installer warns or, with `-RequireSignature`, refuses. The bundle installers check
    `SHA256SUMS` before installing; verify the archive itself out of band.
  - Over-privileged service: Linux runs as the `bower` system account (no shell, no
    capabilities, `ProtectSystem=strict`, writes only to `/var/lib/bower` and
    `/var/spool/bower`). Windows runs as the virtual account `NT SERVICE\Bower`;
    `%ProgramData%\Bower` does not inherit the ProgramData ACL, only SYSTEM and
    Administrators control it, and the service can write only its state, enrolment
    and spool folders. CI asserts both, including that no other principal has access.
  - Pre-seeded token exposure: the token is never a package or MSI property (MSI logs
    properties) or a command-line argument. The installer moves it into an owner-only
    location and deletes the seed copy; the collector deletes its copy as soon as
    management has consumed or refused it (`BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE`).
    The token stays single use and expiring, so a copied bundle enrols at most one
    collector, which still waits in `Pending`.
  - Secrets left after uninstall: removal (not upgrade) deletes the management
    credential, any unused token and the operator secrets folder (`/etc/bower/secrets`
    and `bower.env` on Linux, `%ProgramData%\Bower\secrets` on Windows). CI proves it
    on Ubuntu, Rocky Linux 9 and Windows. The queue is kept until purge because it may
    hold events the destination has not acknowledged.
  - Configuration tampering: settings files, trusted keys and packs are writable only by
    root or Administrators. A trusted pack or command key planted by someone with that
    access is outside Bower's control, as is any change such a user can make.
- Management proxies: the management channel honours the standard proxy variables or
  an explicit proxy. A CA bundle adds roots for TLS-inspection proxies. Verification and
  host name checks are never disabled. Proxy URLs carrying credentials are refused, and
  the password comes from a file that is never logged, hashed or reported. An inspecting
  proxy can read heartbeat metadata and the bearer token in transit, so trust it as you
  would the management host. It cannot forge commands.
- Management API abuse: Entra-only endpoints (except token enrolment and the
  enrolled-collector credential, above), per-principal rate limiting, HSTS on
  HTTPS, restricted CORS headers and methods, and fixed error messages that never
  echo framework exception detail or server paths.
- Onboarding canary (`/setup`, optional): the management API can hold a canary
  ingest token (a file read per run, at most 4 KiB, never returned, logged or stored)
  and a read-only verifier identity. Only `Bower.Administrator` starts a run, one at a
  time, each audited. The token should be a dedicated producer ID scoped to the canary
  identity. Workspace, DCR and table identifiers are validated against strict patterns
  before any Azure call (no `..` path segments). Results are metadata only; errors map
  to fixed messages and only exception type names are logged. Proof is shown only for a
  destination-query-verified run. See [console onboarding](../operations/console-onboarding.md).
- Console home view (`/api/home`, any interactive role): computed on the server from
  management state; it changes nothing and links to the pages that do. Collectors now
  report redaction counts by detector type on the heartbeat (at most 64 type ids and
  counts; an honest collector never sends values, paths or event ids). Type ids are
  untrusted metadata: management checks only their characters and length, so a
  compromised collector could encode data in one. Management stores the ids as sent in
  its own database (to compute increases) but `/api/home` returns only allowlisted group
  names and labels; any id it does not recognise shows as "Other sensitive details". A
  compromised collector can also inflate or hide its own counts; the home view shows them
  as counts, not proof. Sentinel
  delivery is shown as proven only for a destination-query-verified setup run. See
  [console home](../operations/console-home.md).
- Local management exposure: HTTP listener defaults to loopback and has body limit.
  Named pipe and Unix socket transports remain required.
- Supply chain: central pinned packages, restore vulnerability audit, warnings as
  errors. SBOM, CodeQL, container scanning, signing and provenance remain required.

## Residual risks

Name-based redaction cannot prove arbitrary free-text values contain no secret.
The custom-log sample reader re-checks for symbolic links after opening, but a
swap and swap-back between checks remains possible; keep sample roots writable
only by trusted operators. Custom-log previews enforce a server-owned masking
floor and show no values for an operator-authored regex. The pattern still decides,
for each line, whether the line matches (any non-matching line fails the whole
preview) and whether its captures pass type validation (rejected counts and which
source lines produce rows). That line-level match oracle lets an authorised operator
infer undetected text in a server sample one request at a time. For JSON and
key/value samples, naming a key in the configuration also shows whether that key
exists. Keep sample roots to logs operators may already read. SQL Server incrementing cursors hold back rows newer
than `CommitSettleDelay`; transactions open longer than that can still be skipped.
Applications must use typed contracts and avoid unrestricted attributes. Local DB
encryption is deployment responsibility. Current collector does not verify
configuration ownership/mode. Current Azure path is not tenant-tested here.

Command expiry relies on the collector clock (5 minutes of skew tolerated), so keep
collectors time-synchronised. A collector whose command ledger cannot be read refuses
every command until an operator removes or repairs the file. A `reload` restarts the
process: delivery resumes from the durable queue, but the restart briefly interrupts
ingest.

A signed transform can still select the wrong substring of a free-text field into an
allowlisted target (for example a password typed as a username); the privacy engine
redacts the mapped envelope, but review transform programs like policy changes.

Enrolment tokens are bearer secrets until used: deliver them over a channel you trust
and prefer short lifetimes and a collector id scope. An assertion captured in transit
(for example by a trusted TLS-inspection proxy) can be replayed for up to 5 minutes; it
is bound to one collector and grants only that collector's heartbeat role. The
credential file is protected by file permissions only (owner-only on Unix, the
directory ACL on Windows); there is no hardware-backed key storage yet. A collector
offline past its credential's 30 days needs a new token and a new approval.

UDP syslog senders can be spoofed (the allow-list checks only the source address) and
UDP is best effort. Syslog hostname and app-name are sender-claimed: without a
per-route `allowedSenders`, any allowed sender can reach any route. Syslog TLS
certificates are read at start-up, so rotation needs a restart. Plain syslog has no
application acknowledgement, so frames in flight when the collector stops are lost
unless the sender retransmits.

The installers delete files with `shred -u` (Linux, where available) or a plain delete
(Windows). Neither guarantees the token bytes are gone from journaling, copy-on-write or
SSD storage; the token's single use and short expiry are the control that matters. A
token that management never sees (the host never reaches it) stays on disk in the
owner-only enrolment folder until it is used, the package is removed or an operator
deletes it. Any local user can create folders in `%ProgramData%`: `Install-BowerCollector.ps1`
refuses a `%ProgramData%\Bower` not owned by SYSTEM or Administrators, but a plain
`msiexec` install re-permissions an existing folder without changing its owner, so check
the owner first when you install the MSI directly on a shared host.

Treat pseudonymised identifiers as potentially personal information.

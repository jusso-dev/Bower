# Threat model

## Assets

Security event integrity, secrets and personal data, policy/configuration
integrity, SQLite durability, Azure identity, destination routing and assessment
evidence.

## Threats and current controls

- Malicious JSON, log/newline injection and oversized records: strict JSON object
  parsing, depth 32, 1 MiB ingress limit, structured serialization and JSONL
  records written from parsed envelopes.
- Secret leakage: secret field-name removal (exact names and fragments), value
  detectors over strings, numbers and key names, fail-closed HMAC, and
  quarantine on any redaction error, all before persistence; payload-free
  operational logs; no token persistence.
- Replay and duplicate delivery: unique stable fingerprint and event ID, leased
  delivery transitions and acknowledgement records. Generated privacy alerts,
  EC2 host events and AWS records use deterministic ids so retries and re-reads
  deduplicate. Acknowledged rows are kept for the retention window
  (`BOWER_QUEUE_RETENTION_HOURS`, default 7 days) to preserve deduplication.
- Queue/disk exhaustion: the byte cap counts undelivered rows only, a Hangfire
  retention job purges acknowledged rows, capacity returns HTTP 503 for producer
  back-off, and ingest is rate limited (HTTP 429). Poison events dead-letter
  individually or after `BOWER_MAX_DELIVERY_ATTEMPTS`. Filesystem quota and
  disk-free health enforcement remain required.
- Policy tampering: loaded policy is validated and hashed. Signed bundles and file
  permission checks remain required.
- Parser exploitation: no arbitrary expressions or code execution. YAML documents
  are size-limited. Regex/XML parsers are not present.
- Credential theft and overprivilege: one explicit Azure credential source
  (`BOWER_AZURE_CREDENTIAL`: managed identity by default, workload identity,
  environment or Azure CLI) instead of `DefaultAzureCredential` probing.
  The management heartbeat refuses non-HTTPS remote endpoints. Credentials and
  access tokens are never logged or stored by Bower.
- Destination redirection: endpoint/DCR values are explicit and endpoint requires
  HTTPS. Signed configuration and Azure resource validation remain required.
- Event injection: the collector requires a shared bearer token
  (`BOWER_INGEST_TOKEN`, compared in constant time) whenever it listens beyond
  loopback and refuses to start without one. Kubernetes manifests add a
  NetworkPolicy limiting ingress to labelled producer pods. `/health` exposes
  status only; queue and job metadata need the token.
- Management API abuse: Entra-only endpoints, per-principal rate limiting, HSTS on
  HTTPS, restricted CORS headers and methods, and fixed error messages that never
  echo framework exception detail or server paths.
- Local management exposure: HTTP listener defaults to loopback and has body limit.
  Named pipe and Unix socket transports remain required.
- Supply chain: central pinned packages, restore vulnerability audit, warnings as
  errors. SBOM, CodeQL, container scanning, signing and provenance remain required.

## Residual risks

Name-based redaction cannot prove arbitrary free-text values contain no secret.
The custom-log sample reader re-checks for symbolic links after opening, but a
swap and swap-back between checks remains possible; keep sample roots writable
only by trusted operators. SQL Server incrementing cursors hold back rows newer
than `CommitSettleDelay`; transactions open longer than that can still be skipped.
Applications must use typed contracts and avoid unrestricted attributes. Local DB
encryption is deployment responsibility. Current collector does not verify
configuration ownership/mode. Current Azure path is not tenant-tested here.

Treat pseudonymised identifiers as potentially personal information.

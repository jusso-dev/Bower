# Threat model

## Assets

Security event integrity, secrets and personal data, policy/configuration
integrity, SQLite durability, Azure identity, destination routing and assessment
evidence.

## Threats and current controls

- Malicious JSON, log/newline injection and oversized records: strict JSON object
  parsing, depth 32, 1 MiB ingress limit, structured serialization and JSONL
  records written from parsed envelopes.
- Secret leakage: dangerous property removal and email masking before persistence;
  payload-free operational logs; no token persistence.
- Replay and duplicate delivery: unique stable fingerprint and event ID, leased
  delivery transitions and acknowledgement records.
- Queue/disk exhaustion: configured logical queue byte cap and explicit capacity
  failure. Filesystem quota and disk-free health enforcement remain required.
- Policy tampering: loaded policy is validated and hashed. Signed bundles and file
  permission checks remain required.
- Parser exploitation: no arbitrary expressions or code execution. YAML documents
  are size-limited. Regex/XML parsers are not present.
- Credential theft and overprivilege: Azure uses `TokenCredential`; managed or
  workload identity recommended. Credentials and access tokens are never logged
  or stored by Bower.
- Destination redirection: endpoint/DCR values are explicit and endpoint requires
  HTTPS. Signed configuration and Azure resource validation remain required.
- Local management exposure: HTTP listener defaults to loopback and has body limit.
  Local authentication, named pipe and Unix socket transports remain required.
- Supply chain: central pinned packages, restore vulnerability audit, warnings as
  errors. SBOM, CodeQL, container scanning, signing and provenance remain required.

## Residual risks

Name-based redaction cannot prove arbitrary free-text values contain no secret.
Applications must use typed contracts and avoid unrestricted attributes. Local DB
encryption is deployment responsibility. Current collector does not verify
configuration ownership/mode. Current Azure path is not tenant-tested here.

Treat pseudonymised identifiers as potentially personal information.

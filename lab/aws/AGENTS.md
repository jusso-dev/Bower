# Disposable AWS lab

- Use only synthetic events; never production telemetry or real identifiers.
- Every mutable resource must belong to the current `Project=bower-lab` and `RunId`.
- Verify the expected AWS account before apply, commands and teardown. Use explicit instance IDs after checking tags; never target a broad Role tag alone.
- No public instance addresses, SSH keys, inbound SSH/RDP, or external inbound rules.
- SSM commands must not contain secrets. Fetch lab secrets on the host, suppress their output and keep local files owner-only.
- Never turn off certificate validation. Keep development management administration on loopback.
- Retain only redacted reports. Never upload queue contents, seed manifests or credential files as diagnostic artifacts.
- Record missing or unimplemented phases as blocked, not passed. Sentinel delivery requires a real destination query.
- Review generated infrastructure before apply. Teardown only the run's stack; retain expiring report storage. Include an independent expiry guard for abandoned runs.

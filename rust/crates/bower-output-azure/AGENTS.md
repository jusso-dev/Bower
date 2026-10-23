# bower-output-azure instructions

Rust port of `src/Bower.Output.AzureLogsIngestion` and the credential sources of
`src/Bower.Collector/AzureCredentialFactory.cs` (the specification), with
`Azure.Monitor.Ingestion` 1.2 / Azure.Core wire behaviour.

- Supported Logs Ingestion REST API only: gzip JSON-array bodies, 1 MiB batches
  (hard uncompressed JSON-array limit including brackets and commas), owned response
  attribution, bounded concurrency and isolation, Azure.Core retry rules and final
  durable `Retry-After`. No redirects. Ambiguous HTTP errors preserve records as
  destination faults; only local validation proves permanent payload failure.
- Poison records (unparseable, id mismatch, preflight issue) fail alone and are
  never retryable. Unattributable failures never count as delivered.
- Bodies keep payload number text and property order (`compact_from_str`); do not
  re-serialize through `serde_json::Value`.
- Tokens stay in memory (`CachedTokenProvider`); never log, persist or put tokens,
  secrets or response bodies in errors. Authority hosts must be HTTPS.
- `tests/fixtures/csharp-vectors.json` came from the C# adapter; keep it passing.
- Credentials follow Azure.Identity 1.21 / MSAL.NET 4.83 (`src/credential/`): MSAL
  managed identity source order and api-versions, Azure.Core's managed identity
  retry policy, Azure Arc challenge files confined to the agent token directory
  (4096-byte limit, no symlinks), Service Fabric thumbprint-pinned TLS, MSAL
  client assertions (`PS256`, `x5t#S256`). `tests/fixtures/credentials` keys are
  test-only.

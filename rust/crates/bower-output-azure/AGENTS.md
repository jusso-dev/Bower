# bower-output-azure instructions

Rust port of `src/Bower.Output.AzureLogsIngestion` and the credential sources of
`src/Bower.Collector/AzureCredentialFactory.cs` (the specification), with
`Azure.Monitor.Ingestion` 1.2 / Azure.Core wire behaviour.

- Supported Logs Ingestion REST API only: gzip JSON-array bodies, 1 MiB batches
  (`body + entry + 1 >= 1 MiB` closes a batch, measured against the C# SDK), bounded
  concurrency, Azure.Core retry rules and `Retry-After`. No redirects.
- Poison records (unparseable, id mismatch, preflight issue) fail alone and are
  never retryable. Unattributable failures never count as delivered.
- Bodies keep payload number text and property order (`compact_from_str`); do not
  re-serialize through `serde_json::Value`.
- Tokens stay in memory (`CachedTokenProvider`); never log, persist or put tokens,
  secrets or response bodies in errors. Authority hosts must be HTTPS.
- `tests/fixtures/csharp-vectors.json` came from the C# adapter; keep it passing.

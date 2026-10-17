# Dependency decisions

`AGENTS.md` requires written justification for new dependencies.

| Package | Used by | Why | Alternatives considered |
|---|---|---|---|
| `AWSSDK.SQS`, `AWSSDK.S3` 4.0 | `Bower.Agent.Cloud` | SigV4-signed SQS receive/delete/visibility and bounded S3 `GetObject` with `ExpectedBucketOwner`, using the AWS default credential chain (EC2 instance profile with IMDSv2, ECS task role, EKS IRSA). Apache-2.0, first-party. Only these two service clients are referenced. | Hand-written SigV4 over `HttpClient` (security-sensitive code to own and audit); AWS CLI sidecar (shell, extra image surface). |
| `AWSSDK.SecurityToken` 4.0 | `Bower.Agent.Cloud` | Loaded by AWSSDK.Core to exchange an IRSA or Workload Identity web token for temporary credentials (`AssumeRoleWithWebIdentity`). Without it IRSA silently fails. | None for IRSA in .NET. |
| `Google.Apis.Auth` 1.77 | `Bower.Agent.Cloud` | Application Default Credentials including GKE Workload Identity, the metadata server and Workload Identity Federation (`external_account`, including AWS-sourced tokens), with token caching and refresh. Lets Bower detect and refuse service account key files. Apache-2.0, first-party. Pub/Sub itself is called over REST with `HttpClient`, so the gRPC stack is not pulled in. Brings `Google.Apis`, `Google.Apis.Core`, `Newtonsoft.Json` 13.0.4 (its own floor; patched for GHSA-5crp-9r3c-p9vr, so no direct pin is needed) and `System.Management` (Windows-only code paths, unused on Linux). Blocks Native AOT for `bower-cloud`; see below. | `Google.Cloud.PubSub.V1` (gRPC, much larger dependency tree); hand-written STS token exchange for each credential type. |
| `Vecc.YamlDotNet.Analyzers.StaticGenerator` 18.1 (build-time only, `PrivateAssets=all`) | `Bower.PolicyEngine`, `Bower.Redaction`, `Bower.Pipeline`, `Bower.Packs` | Roslyn source generator that emits YamlDotNet's `StaticContext` for policy, privacy profile, pipeline and pack YAML, so YAML binding needs no reflection under Native AOT. Published by the YamlDotNet maintainers at the same version as `YamlDotNet`. Nothing ships at run time. | Hand-written YAML-to-model mapping over YamlDotNet's parser (more code to keep in step with the models); YamlDotNet reflection deserializer (IL2026/IL3050 under AOT). |
| `Microsoft.AspNetCore.TestHost` | Tests only | Runs the collector and management API in-process for HTTP, authentication and rate-limit tests. | `Microsoft.AspNetCore.Mvc.Testing` (needs a single `Program` entry point per test assembly). |

| `nginxinc/nginx-unprivileged` (container base image) | `Dockerfile.web` | Serves the static console as a non-root user on a read-only filesystem, with runtime config. Official NGINX image. | Serving from the management API only (still supported); Caddy (no official unprivileged image). |

`Bower.Agent.Docker` uses the ASP.NET Core shared framework (`FrameworkReference`)
for the generic host, logging and `IHttpClientFactory`, so it adds no NuGet packages.
`Bower.Agent.Cloud` does the same; its only packages are the cloud SDKs above.
`Bower.Source.Gcp` and the AWS queue parser in `Bower.Source.Aws` have no dependencies:
parsing stays pure and testable without cloud access.

Review these when upgrading: AWS SDK for .NET 5.x, Google.Apis.Auth major versions
(credential-type changes affect the key-file refusal, and a release that drops
Newtonsoft.Json would unblock Native AOT for `bower-cloud`).

## Removed for Native AOT

| Package | Replaced by | Notes |
|---|---|---|
| `Hangfire.Core`, `Hangfire.NetCore`, `Hangfire.InMemory` | `Bower.Jobs` in-process cron scheduler (`RecurringJobRegistry`, `PeriodicTimer`) | Hangfire serializes jobs with reflection-based Newtonsoft.Json and builds calls from expression trees. Same job ids, UTC cron schedules, retry counts and no-overlap rule; state stays in memory. See [background jobs](../operations/background-jobs.md). |
| `Newtonsoft.Json` (direct pin) | — | Only pinned for Hangfire. Still present transitively under `Google.Apis.Auth` in `Bower.Agent.Cloud`. |
| `Microsoft.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Sqlite` (`Bower.Persistence`) | `Microsoft.Data.Sqlite` (already referenced) | EF Core's runtime model building needs reflection and dynamic code. `EfSourceCursorStore` keeps the exact table, column order (`SourceId`, `Value`, `Version`, `UpdatedAt`) and timestamp text EF Core created, so existing cursor files keep working. `Bower.Source.SqlServer` still uses EF Core (SQL Server) by design and is not referenced by any AOT executable. |

## Native AOT status

All product libraries set `IsAotCompatible` (trim, AOT and single-file analysers run on
every build; warnings are errors). `bower`, the collector, the management API and the
Docker sidecar publish as Native AOT with zero IL2xxx/IL3xxx warnings. JSON uses
System.Text.Json source generation with the same options as before, so wire bytes,
policy hashes and pack signatures are unchanged.

| Dependency | Status |
|---|---|
| `Microsoft.AspNetCore.Authentication.JwtBearer` / `Microsoft.IdentityModel.*` | AOT clean. |
| `Azure.Identity`, `Azure.Core` | AOT clean. |
| `Azure.Monitor.Ingestion` | `LogsIngestionClient.UploadAsync<T>` carries `RequiresUnreferencedCode`/`RequiresDynamicCode` because its default serializer is reflection-based. `AzureLogsIngestionOutput` always passes `JsonRecordSerializer` (writes `JsonObject` nodes directly), behind a guard, and suppresses IL2026/IL3050 on that one call with a written justification. Uploaded bytes are unchanged (pinned by `AzureLogsIngestionOutputTests`). |
| `AWSSDK.Core`, `AWSSDK.SQS`, `AWSSDK.S3`, `AWSSDK.SecurityToken` 4.0 | AOT clean (no warnings under ILC). |
| `Google.Apis.Auth` 1.77 (`Google.Apis.Core`, `Newtonsoft.Json`) | **Blocker.** `Google.Apis.Json.NewtonsoftJsonSerializer`/`NewtonsoftJsonContractResolver` call `Newtonsoft.Json.JsonSerializer.Create` and `DefaultContractResolver()` (IL2026/IL3050), `Google.Apis.Util.RequestParameterDescriptorProvider` reflects over request types (IL2070), and Newtonsoft's `JToken`/`JObject`/`JValue` dynamic and `ToObject(Type)` paths are not AOT safe (IL2026/IL3050, surfaced as IL2104/IL3053). ADC credential files and token responses are read through that serializer, so the warnings guard real reflection. `bower-cloud` therefore publishes self-contained on the .NET runtime (`PublishAot=false`); Bower's own code in it is still AOT analysed. Unblocking needs an AOT-safe Google auth library or an in-house ADC implementation (metadata server, `external_account` STS exchange including AWS-sourced SigV4 subject tokens, impersonation, and the service-account key refusal). |


## Rust data plane (`rust/`)

| Crate | Used by | Why | Alternatives considered |
|---|---|---|---|
| `getrandom` 0.3 | `bower-cli` (`bower token generate`) | 32 bytes from the operating system CSPRNG for ingest tokens, matching C# `RandomNumberGenerator.GetBytes`. Already in the lock file through `uuid`, so it adds no new code. | `rand` (larger API surface for one call); deriving tokens from UUID v4 bytes (not a full 256-bit random value). |
| `hyper` 1, `hyper-util` 0.1, `http-body-util` 0.1 | `bower-collector` | Already in the lock file through `axum`, so they add no new code. Used directly because `axum::serve` sets no timer: the collector needs Kestrel's 30 s request-header timeout (slow-header connections), HTTP/1.1 only, bounded graceful drain on SIGTERM, and frame-by-frame body reads to enforce the 1 MiB limit and Kestrel's 240 B/s minimum body data rate. | `axum::serve` (no header timeout, unbounded idle slow-loris connections); `tower-http` timeouts (time whole requests, not header reads, and add a crate). |
| `rusqlite` 0.40 (`bundled`) | `bower-persistence` | SQLite queue, ledger and cursor store that must stay on-disk compatible with `Microsoft.Data.Sqlite` (same DDL, PRAGMAs, WAL, `BEGIN IMMEDIATE`). `bundled` compiles a pinned SQLite like `SQLitePCLRaw.bundle_e_sqlite3`, so behaviour does not depend on the host library. | `sqlx` (async, larger, compile-time query macros not needed for a synchronous store); `sqlite` crate (thinner, no transaction-behaviour API); system `libsqlite3` (version drift across hosts). |
| `aes-gcm` 0.11 (`aes` only), `hmac` 0.13 | `bower-redaction` | The privacy engine's `Encrypt` action (AES-256-GCM, random 96-bit nonce from `getrandom`, `enc:aesgcm:<nonce>:<tag>:<ciphertext>` like C# `AesGcm`) and `Hmac` action / `KeyedFieldHasher` (HMAC-SHA256 like `HMACSHA256.HashData`). Pure-Rust RustCrypto crates built on the workspace `sha2`; only the `aes` backend feature is enabled. | `ring` (C/assembly build, different API for detached tags); hand-rolled HMAC over `sha2` (security-sensitive code without review). |
| `flate2` 1 | `bower-output-azure` | Gzip request bodies for the Azure Monitor Logs Ingestion API, as `Azure.Monitor.Ingestion` sends every batch with `Content-Encoding: gzip`. Pure-Rust `miniz_oxide` backend by default, no system zlib. | Uncompressed uploads (diverges from the C# wire behaviour and costs up to 1 MB per request); reqwest's `gzip` feature (only decompresses responses). |
| `serde` 1, `serde_json` 1 (`preserve_order`, `arbitrary_precision`, `raw_value`) | all crates | Serialization foundation. `bower_contracts::json` adds a formatter matching `JavaScriptEncoder.Default`; `raw_value` and `arbitrary_precision` keep number text and `DateTimeOffset` bytes identical to System.Text.Json. | Hand-written JSON (large, error-prone); `simd-json` (no custom escaping hook). |
| `indexmap` 2 | contracts, policy, redaction | Insertion-ordered maps so `labels`, privacy actions and YAML mappings serialize in the same order as C# dictionaries. | `BTreeMap` (sorted order changes payload bytes). |
| `chrono` 0.4 (no default features) | contracts and every time-aware crate | `DateTimeOffset` equivalent with fixed offsets, truncated to 100 ns ticks for round-trip and hash parity. | `time` (equivalent; `chrono` already pulled in by dependencies). |
| `thiserror` 2 | all library crates | Typed errors whose `Display` reproduces C# exception messages. Compile-time only. | Manual `Display` impls. |
| `regex` 1 | redaction, detection, AMA spool | Privacy and secret detectors, Sigma-style matching. Linear-time engine: no catastrophic backtracking, so no regex timeouts are needed (C# uses 50 ms timeouts). | `fancy-regex` (backtracking; not needed, no lookaround is used). |
| `serde_yaml_ng` 0.10 | policy, redaction, pipeline, packs | YAML policies, privacy profiles, pipelines and pack content, like YamlDotNet. Maintained fork of the archived `serde_yaml`. | `serde_yaml` (unmaintained); `yaml-rust2` directly (no serde). |
| `p256` 0.14, `hex` 0.4, `base64` 0.23 | integrity, packs, evidence | ECDSA P-256 detached signatures (P1363) interoperable with C# `ECDsa`, plus hex and base64 encodings. Pure-Rust RustCrypto. | `ring` (C/assembly build; no PKCS#8/SEC1 PEM parity helpers); `openssl` (system dependency). |
| `tokio` 1, `axum` 0.8, `tower` 0.5, `http` 1, `reqwest` 0.13 (`rustls`) | collector, outputs, evidence, CLI | Async runtime, collector HTTP server and outbound HTTPS (Logs Ingestion, Entra token, ARM and Logs query). rustls avoids a system OpenSSL dependency and keeps the container static. | `actix-web` (heavier); `hyper` alone (more code); `native-tls` (system library). |
| `tracing` 0.1, `tracing-subscriber` 0.3 | collector | Structured logs with metadata only (no payloads or secrets). | `log` + `env_logger` (no structured fields). |
| `clap` 4 | CLI | Renders `--help`; argument semantics are parsed by hand to match the C# CLI. | Hand-written help text. |
| `uuid` 1 | core, collector, evidence | Event, batch and canary identifiers. | `getrandom` + manual formatting. |
| `tempfile` 3 | tests only | Scratch directories for queue, spool and pack tests. | Manual temp paths (cleanup leaks). |

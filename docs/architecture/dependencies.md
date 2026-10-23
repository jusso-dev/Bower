# Dependency decisions

`AGENTS.md` requires written justification for new dependencies.

| Package | Used by | Why | Alternatives considered |
|---|---|---|---|
| `AWSSDK.SQS`, `AWSSDK.S3` 4.0 | `Bower.Agent.Cloud` | SigV4-signed SQS receive/delete/visibility and bounded S3 `GetObject` with `ExpectedBucketOwner`, using the AWS default credential chain (EC2 instance profile with IMDSv2, ECS task role, EKS IRSA). Apache-2.0, first-party. Only these two service clients are referenced. | Hand-written SigV4 over `HttpClient` (security-sensitive code to own and audit); AWS CLI sidecar (shell, extra image surface). |
| `AWSSDK.SecurityToken` 4.0 | `Bower.Agent.Cloud` | Loaded by AWSSDK.Core to exchange an IRSA or Workload Identity web token for temporary credentials (`AssumeRoleWithWebIdentity`). Without it IRSA silently fails. | None for IRSA in .NET. |
| `Vecc.YamlDotNet.Analyzers.StaticGenerator` 18.1 (build-time only, `PrivateAssets=all`) | `Bower.PolicyEngine`, `Bower.Redaction`, `Bower.Pipeline`, `Bower.Packs` | Roslyn source generator that emits YamlDotNet's `StaticContext` for policy, privacy profile, pipeline and pack YAML, so YAML binding needs no reflection under Native AOT. Published by the YamlDotNet maintainers at the same version as `YamlDotNet`. Nothing ships at run time. | Hand-written YAML-to-model mapping over YamlDotNet's parser (more code to keep in step with the models); YamlDotNet reflection deserializer (IL2026/IL3050 under AOT). |
| `Microsoft.AspNetCore.TestHost` | Tests only | Runs the collector and management API in-process for HTTP, authentication and rate-limit tests. | `Microsoft.AspNetCore.Mvc.Testing` (needs a single `Program` entry point per test assembly). |

| `nginxinc/nginx-unprivileged` (container base image) | `Dockerfile.web` | Serves the static console as a non-root user on a read-only filesystem, with runtime config. Official NGINX image. | Serving from the management API only (still supported); Caddy (no official unprivileged image). |

`Bower.Agent.Docker` uses the ASP.NET Core shared framework (`FrameworkReference`)
for the generic host, logging and `IHttpClientFactory`, so it adds no NuGet packages.
`Bower.Agent.Cloud` does the same; its only packages are the AWS SDKs above. Google
credentials are handled in-house (see "Removed for Native AOT" below), so no Google
package is referenced.
`Bower.Source.Gcp` and the AWS queue parser in `Bower.Source.Aws` have no dependencies:
parsing stays pure and testable without cloud access.

Review these when upgrading: AWS SDK for .NET 5.x. Review `Bower.Agent.Cloud/Gcp/Auth`
when Google changes AIP-4110/4117 (new `external_account` credential sources, a new
`aws` environment version or new credential file types).

## Removed for Native AOT

| Package | Replaced by | Notes |
|---|---|---|
| `Hangfire.Core`, `Hangfire.NetCore`, `Hangfire.InMemory` | `Bower.Jobs` in-process cron scheduler (`RecurringJobRegistry`, `PeriodicTimer`) | Hangfire serializes jobs with reflection-based Newtonsoft.Json and builds calls from expression trees. Same job ids, UTC cron schedules, retry counts and no-overlap rule; state stays in memory. See [background jobs](../operations/background-jobs.md). |
| `Newtonsoft.Json` (direct pin) | — | Only pinned for Hangfire. Its last transitive use (`Google.Apis.Auth`) is removed too, so no Bower project resolves Newtonsoft.Json. |
| `Google.Apis.Auth` (`Google.Apis`, `Google.Apis.Core`, `Newtonsoft.Json`, `System.Management`, `System.CodeDom`) | `Bower.Agent.Cloud/Gcp/Auth`: in-house Application Default Credentials with System.Text.Json source generation | Google.Apis.Core reads credential files and token responses with reflection-based Newtonsoft.Json (IL2026/IL3050/IL2070). The replacement covers exactly what the agent used: ADC discovery (`GOOGLE_APPLICATION_CREDENTIALS`, the gcloud well-known file, then the metadata server), metadata server tokens (`Metadata-Flavor: Google`, probe on 169.254.169.254, tokens from `metadata.google.internal`, `GCE_METADATA_HOST`/`GCE_METADATA_IP`), and Workload Identity Federation per AIP-4117: file- and URL-sourced subject tokens (text or JSON), AWS-sourced tokens (SigV4-signed GetCallerIdentity, IMDSv2 session token, region and role credentials from IMDS or the AWS environment variables), the RFC 8693 STS exchange (optional client authentication, workforce `userProject`) and service account impersonation through IAM Credentials `generateAccessToken` (`token_lifetime_seconds` 600–43200). Tokens are cached in memory until five minutes before expiry. The key-file refusal is unchanged; gcloud user credentials (`authorized_user`, a long-lived refresh token) now need `BOWER_GCP_ALLOW_KEY_FILE=true` too. Executable-sourced credentials are refused (configuration must not run code), as are X.509 workload certificates, `impersonated_service_account` and other credential types. Hardening beyond the AIP: token and IAM endpoints must be HTTPS on the universe domain (`googleapis.com`), AWS metadata URLs must be 169.254.169.254 or fd00:ec2::254 (as AIP-4117 requires), plain HTTP only to metadata or loopback hosts, no redirects, metadata calls bypass proxies, responses capped at 64 KiB (subject tokens 256 KiB), and error bodies are never surfaced beyond the OAuth `error` code. SigV4 is pinned by AWS's published SigV4 test suite. |
| `Microsoft.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Sqlite` (`Bower.Persistence`) | `Microsoft.Data.Sqlite` (already referenced) | EF Core's runtime model building needs reflection and dynamic code. `EfSourceCursorStore` keeps the exact table, column order (`SourceId`, `Value`, `Version`, `UpdatedAt`) and timestamp text EF Core created, so existing cursor files keep working. `Bower.Source.SqlServer` still uses EF Core (SQL Server) by design and is not referenced by any AOT executable. |

## Native AOT status

All product libraries set `IsAotCompatible` (trim, AOT and single-file analysers run on
every build; warnings are errors). `bower`, the collector, the management API, the
Docker sidecar and the cloud agent publish as Native AOT with zero IL2xxx/IL3xxx warnings. JSON uses
System.Text.Json source generation with the same options as before, so wire bytes,
policy hashes and pack signatures are unchanged.

| Dependency | Status |
|---|---|
| `Microsoft.AspNetCore.Authentication.JwtBearer` / `Microsoft.IdentityModel.*` | AOT clean. |
| `Azure.Identity`, `Azure.Core` | AOT clean. |
| `Azure.Monitor.Ingestion` | `LogsIngestionClient.UploadAsync<T>` carries `RequiresUnreferencedCode`/`RequiresDynamicCode` because its default serializer is reflection-based. `AzureLogsIngestionOutput` always passes `JsonRecordSerializer` (writes `JsonObject` nodes directly), behind a guard, and suppresses IL2026/IL3050 on that one call with a written justification. Uploaded bytes are unchanged (pinned by `AzureLogsIngestionOutputTests`). |
| `AWSSDK.Core`, `AWSSDK.SQS`, `AWSSDK.S3`, `AWSSDK.SecurityToken` 4.0 | AOT clean (no warnings under ILC). |


## Rust data plane (`rust/`)

| Crate | Used by | Why | Alternatives considered |
|---|---|---|---|
| `getrandom` 0.3 | `bower-cli` (`bower token generate`) | 32 bytes from the operating system CSPRNG for ingest tokens, matching C# `RandomNumberGenerator.GetBytes`. Already in the lock file through `uuid`, so it adds no new code. | `rand` (larger API surface for one call); deriving tokens from UUID v4 bytes (not a full 256-bit random value). |
| `hyper` 1, `hyper-util` 0.1, `http-body-util` 0.1 | `bower-collector` | Already in the lock file through `axum`, so they add no new code. Used directly because `axum::serve` sets no timer: the collector needs Kestrel's 30 s request-header timeout (slow-header connections), HTTP/1.1 only, bounded graceful drain on SIGTERM, and frame-by-frame body reads to enforce the 1 MiB limit and Kestrel's 240 B/s minimum body data rate. | `axum::serve` (no header timeout, unbounded idle slow-loris connections); `tower-http` timeouts (time whole requests, not header reads, and add a crate). |
| `rusqlite` 0.40 (`bundled`) | `bower-persistence` | SQLite queue, ledger and cursor store that must stay on-disk compatible with `Microsoft.Data.Sqlite` (same DDL, PRAGMAs, WAL, `BEGIN IMMEDIATE`). `bundled` compiles a pinned SQLite like `SQLitePCLRaw.bundle_e_sqlite3`, so behaviour does not depend on the host library. | `sqlx` (async, larger, compile-time query macros not needed for a synchronous store); `sqlite` crate (thinner, no transaction-behaviour API); system `libsqlite3` (version drift across hosts). |
| `aes-gcm` 0.11 (`aes` only), `hmac` 0.13 | `bower-redaction` | The privacy engine's `Encrypt` action (AES-256-GCM, random 96-bit nonce from `getrandom`, `enc:aesgcm:<nonce>:<tag>:<ciphertext>` like C# `AesGcm`) and `Hmac` action / `KeyedFieldHasher` (HMAC-SHA256 like `HMACSHA256.HashData`). Pure-Rust RustCrypto crates built on the workspace `sha2`; only the `aes` backend feature is enabled. | `ring` (C/assembly build, different API for detached tags); hand-rolled HMAC over `sha2` (security-sensitive code without review). |
| `flate2` 1 | `bower-output-azure`; `bower-redaction` (dev) | Gzip request bodies for the Azure Monitor Logs Ingestion API, as `Azure.Monitor.Ingestion` sends every batch with `Content-Encoding: gzip`. Pure-Rust `miniz_oxide` backend by default, no system zlib. The redaction parity vectors are stored gzipped so synthetic fuzzed credentials do not trip secret scanning. | Uncompressed uploads (diverges from the C# wire behaviour and costs up to 1 MB per request); reqwest's `gzip` feature (only decompresses responses). |
| `rsa` =0.10.0-rc.19 (`std`, `encoding`, `sha2`), `x509-cert` 0.3 | `bower-output-azure` | Certificate credentials (`AZURE_CLIENT_CERTIFICATE_PATH`): RSASSA-PSS/SHA-256 client assertions like MSAL (`PS256`, `x5t#S256`), PKCS#1/PKCS#8 key decoding, and the certificate-key match check `CopyWithPrivateKey` performs. Pure-Rust RustCrypto on the workspace's `sha2` 0.11, `pkcs8` 0.11, `der` 0.8 and `crypto-bigint` 0.7 generation (already in the lock file through `p256`). Pinned exactly because 0.10 is still a release candidate; the stable 0.9 line is affected by RUSTSEC-2023-0071 (Marvin timing side channel, fixed by 0.10's constant-time `crypto-bigint`) and would duplicate the older digest/pkcs8 stack. Signing uses `BlindedSigningKey` and the OS CSPRNG via `getrandom`. Move to 0.10.0 stable when released. | `rsa` 0.9 (advisory, duplicate crypto stack); `aws-lc-rs` directly (already linked by rustls, but C/assembly, against the pure-Rust preference); `openssl` (system dependency). |
| `p12-keystore` 0.4 (default `pbes1`) | `bower-output-azure` | `.pfx` certificate files as `X509Certificate2` loads them: MAC verification (SHA-1/SHA-2), PBES2 (PBKDF2 + AES-CBC, current Windows and OpenSSL 3 exports) and the legacy PKCS#12 PBE schemes (3DES and RC2-40, OpenSSL 1.x and older Windows exports, which `pbes1` enables). Pure Rust on RustCrypto (`pkcs12`, `pkcs5`, `cms`, `des`, `rc2`, `cbc`, `sha1`, `hmac` 0.13), with iteration caps on MAC and KDF parameters. Pulls `x509-parser` (nom, `asn1-rs`, `der-parser`, `oid-registry`, `time`) and pre-release `cms`/`pkcs12` from the same RustCrypto release train. | Hand-written PKCS#12 parsing (security-sensitive ASN.1 and legacy KDF code to own); `p12` 0.6 (unmaintained since 2022, older RustCrypto); `openssl` (system dependency). |
| `sha1` 0.11 | `bower-output-azure` | Service Fabric managed identity pins the endpoint certificate by `IDENTITY_SERVER_THUMBPRINT`, a SHA-1 thumbprint (`X509Certificate2.GetCertHashString`). Used only to compare thumbprints, never for signatures. Already in the lock file through `p12-keystore`. | `aws-lc-rs` digest (C library). |
| `rustls` 0.23 (`std`, `tls12`, `aws_lc_rs`), `rustls-platform-verifier` 0.7; `tokio-rustls` 0.26 (tests only) | `bower-output-azure` | The Service Fabric endpoint uses the cluster's self-signed certificate; MSAL accepts it when its thumbprint matches, otherwise normal validation applies. A custom `ServerCertVerifier` does the same (handshake signatures still verified) and is handed to reqwest with `tls_backend_preconfigured`. These are the exact crates and features reqwest's `rustls` feature already compiles, so no new code is linked. `tokio-rustls` serves the HTTPS mock in tests. | `danger_accept_invalid_certs` (accepts any certificate); native-tls (system library). |
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
| `tempfile` 3 | tests only | Scratch directories for queue, spool, pack and credential tests. | Manual temp paths (cleanup leaks). |

### Collector adversarial privacy tests

The Rust collector test target reuses workspace `flate2` and `rusqlite` as dev-only
dependencies. `flate2` decodes captured Azure gzip request bodies so privacy assertions
inspect actual outbound content; `rusqlite` holds a read transaction open so SQLite
WAL bytes remain available for inspection. Neither adds a production dependency.

## Queue v5 identity and regression tests (2026-10-23)

`bower-core` now references the existing workspace `bower-persistence` crate,
matching the C# Core-to-Persistence dependency. Core fingerprinting and persisted
queue migration must call the same identity implementation; this prevents drift
when existing databases are re-keyed. No new third-party runtime package or version
is introduced. Its tests use the existing workspace `tempfile` dev dependency for
real durable-store replay/conflict regression tests rather than an in-memory double.


### Signed pack runtime activation

`Bower.Packs` reuses its existing Detection, Pipeline, PolicyEngine and Redaction
references for bounded raw mapping and post-redaction detection enrichment. The
collector composes that wrapper around its existing redactor; no external runtime
package is added. Detection's internal scalar/condition encoding uses a generated
System.Text.Json context (`DetectionJsonContext`) and evidence uses
`DetectionEvidenceJson`, preserving Native AOT analysis without suppressions.

Rust collector tests add the internal workspace `bower-integrity` dev reference to
build genuine signed packs before exercising the real host. This is test-only;
production pack verification already depends on the same library through
`bower-packs`. No new external Rust dependency is introduced.

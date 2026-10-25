# Dependency decisions

`AGENTS.md` requires written justification for new dependencies.

The offline `tools/queue-migration-check` project references `Bower.Persistence`
to reuse canonical `EventIdentity` and the existing SQLite/contract dependencies;
it adds no NuGet packages. Unit tests reference the tool to exercise the exact
command and read-only checker without duplicating identity logic in a script or
adding a native CLI command in either runtime.

| Package | Used by | Why | Alternatives considered |
|---|---|---|---|
| `AWSSDK.SQS`, `AWSSDK.S3` 4.0 | `Bower.Agent.Cloud` | SigV4-signed SQS receive/delete/visibility and bounded S3 `GetObject` with `ExpectedBucketOwner`, using the AWS default credential chain (EC2 instance profile with IMDSv2, ECS task role, EKS IRSA). Apache-2.0, first-party. Only these two service clients are referenced. | Hand-written SigV4 over `HttpClient` (security-sensitive code to own and audit); AWS CLI sidecar (shell, extra image surface). |
| `AWSSDK.SecurityToken` 4.0 | `Bower.Agent.Cloud` | Loaded by AWSSDK.Core to exchange an IRSA or Workload Identity web token for temporary credentials (`AssumeRoleWithWebIdentity`). Without it IRSA silently fails. | None for IRSA in .NET. |
| `Vecc.YamlDotNet.Analyzers.StaticGenerator` 18.1 (build-time only, `PrivateAssets=all`) | `Bower.PolicyEngine`, `Bower.Redaction`, `Bower.Pipeline`, `Bower.Packs` | Roslyn source generator that emits YamlDotNet's `StaticContext` for policy, privacy profile, pipeline and pack YAML, so YAML binding needs no reflection under Native AOT. Published by the YamlDotNet maintainers at the same version as `YamlDotNet`. Nothing ships at run time. | Hand-written YAML-to-model mapping over YamlDotNet's parser (more code to keep in step with the models); YamlDotNet reflection deserializer (IL2026/IL3050 under AOT). |
| `Microsoft.Azure.Functions.Worker` 2.52, `Microsoft.Azure.Functions.Worker.Extensions.Http` 3.3, `Microsoft.Azure.Functions.Worker.Sdk` 2.1 (build-time) | `Bower.Functions.Collector` | The supported Azure Functions isolated worker model for .NET 10 (the in-process model ends in November 2026 and does not support .NET 10). Worker hosts the HTTP triggers over the host's gRPC channel (pulls `Grpc.Net.Client`, `Google.Protobuf`, `Microsoft.Extensions.Hosting`); Extensions.Http provides `HttpRequestData`; the Sdk generates function metadata and the host extension bundle at build time. MIT, first-party. Only the plain HTTP extension is used, not ASP.NET Core integration, Application Insights worker packages or storage bindings. | Custom handler with the Rust collector or a minimal ASP.NET app (custom handlers lose the native .NET worker model and its tooling); ASP.NET Core integration (`Worker.Extensions.Http.AspNetCore`, more surface for three routes). |
| `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.19.2 | `Bower.Functions.Collector` | In-code Entra v2 token validation (RS256 signature against OIDC signing keys with refresh on rollover, issuer, audience, lifetime) with the Microsoft-maintained validator. Same versions `Microsoft.AspNetCore.Authentication.JwtBearer` already resolves for the management API. Central pins also align `Bower.Source.SqlServer` (Microsoft.Data.SqlClient's IdentityModel 8.16.0 → 8.19.2, `Microsoft.Bcl.Cryptography` 9.0.18 → 10.0.2); no API change. | `JwtBearer` (needs the ASP.NET Core pipeline, which the plain HTTP worker does not have); Functions Easy Auth alone (configuration outside the code, no role/tenant checks testable offline). |
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
| `Microsoft.Azure.Functions.Worker*` | Not published as Native AOT. The Azure Functions host starts the isolated worker as a framework-dependent .NET app; `Bower.Functions.Collector` keeps the trim/AOT analysers on for its own code and the Bower libraries it reuses. |
| `Azure.Monitor.Ingestion` | `LogsIngestionClient.UploadAsync<T>` carries `RequiresUnreferencedCode`/`RequiresDynamicCode` because its default serializer is reflection-based. `AzureLogsIngestionOutput` always passes `JsonRecordSerializer` (writes `JsonObject` nodes directly), behind a guard, and suppresses IL2026/IL3050 on that one call with a written justification. Uploaded bytes are unchanged (pinned by `AzureLogsIngestionOutputTests`). |
| `AWSSDK.Core`, `AWSSDK.SQS`, `AWSSDK.S3`, `AWSSDK.SecurityToken` 4.0 | AOT clean (no warnings under ILC). |


## Rust data plane (`rust/`)

| Crate | Used by | Why | Alternatives considered |
|---|---|---|---|
| `getrandom` 0.3 | `bower-cli` (`bower token generate`) | 32 bytes from the operating system CSPRNG for ingest tokens, matching C# `RandomNumberGenerator.GetBytes`. Already in the lock file through `uuid`, so it adds no new code. | `rand` (larger API surface for one call); deriving tokens from UUID v4 bytes (not a full 256-bit random value). |
| `hyper` 1, `hyper-util` 0.1, `http-body-util` 0.1 | `bower-collector` | Already in the lock file through `axum`, so they add no new code. Used directly because `axum::serve` sets no timer: the collector needs Kestrel's 30 s request-header timeout (slow-header connections), HTTP/1.1 only, bounded graceful drain on SIGTERM, and frame-by-frame body reads to enforce the 1 MiB limit and Kestrel's 240 B/s minimum body data rate. | `axum::serve` (no header timeout, unbounded idle slow-loris connections); `tower-http` timeouts (time whole requests, not header reads, and add a crate). |
| `rusqlite` 0.40 (`bundled`) | `bower-persistence` | SQLite queue, ledger and cursor store that must stay on-disk compatible with `Microsoft.Data.Sqlite` (same DDL, PRAGMAs, WAL, `BEGIN IMMEDIATE`). `bundled` compiles a pinned SQLite like `SQLitePCLRaw.bundle_e_sqlite3`, so behaviour does not depend on the host library. | `sqlx` (async, larger, compile-time query macros not needed for a synchronous store); `sqlite` crate (thinner, no transaction-behaviour API); system `libsqlite3` (version drift across hosts). |
| `aes-gcm` 0.11 (`aes` only), `hmac` 0.13 | `bower-redaction` | The privacy engine's `Encrypt` action (AES-256-GCM, random 96-bit nonce from `getrandom`, `enc:aesgcm:<nonce>:<tag>:<ciphertext>` like C# `AesGcm`) and `Hmac` action / `KeyedFieldHasher` (HMAC-SHA256 like `HMACSHA256.HashData`). Pure-Rust RustCrypto crates built on the workspace `sha2`; only the `aes` backend feature is enabled. | `ring` (C/assembly build, different API for detached tags); hand-rolled HMAC over `sha2` (security-sensitive code without review). |
| `flate2` 1 | `bower-output-azure`; `bower-persistence`; `bower-redaction` (dev) | Gzip request bodies for the Azure Monitor Logs Ingestion API, as `Azure.Monitor.Ingestion` sends every batch with `Content-Encoding: gzip`. Pure-Rust `miniz_oxide` backend by default, no system zlib. `bower-persistence` writes and reads the gzip JSON Lines archive segments the C# `QueueArchive` produces (`System.IO.Compression.GZipStream`). The redaction parity vectors are stored gzipped so synthetic fuzzed credentials do not trip secret scanning. | Uncompressed uploads (diverges from the C# wire behaviour and costs up to 1 MB per request); reqwest's `gzip` feature (only decompresses responses). |
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

### AWS Lambda host (`bower-lambda`, 2026-10-24)

`bower-lambda` is a separate binary (`bootstrap`, `provided.al2023`); none of these
crates are linked into `bower-collector` or `bower` (the collector image still builds
`-p bower-collector` only). Internally it reuses `bower-collector` (bundle loader,
producer scopes, `/v1/events` body parsing), `bower-core`, `bower-packs`,
`bower-redaction` and `bower-persistence` (`replay_content` for in-invocation identity
checks) instead of copying their rules.

| Crate | Used by | Why | Alternatives considered |
|---|---|---|---|
| `lambda_runtime` 1.5 (`tracing` only) | `bower-lambda` | AWS-maintained client for the Lambda Runtime API (`/next`, `/response`, `/error`, init errors) on the workspace `tokio`, `hyper` and `serde_json`. The payload is taken as `Box<RawValue>` so the handler sees the exact request bytes (duplicate keys, number text) like the collector. `lambda_http` and `aws_lambda_events` are not used: the Function URL request fields the handler needs are a few serde structs. | Hand-written Runtime API loop (re-implements error and deadline handling); `lambda_http` (pulls all API Gateway/ALB event types, normalises the body). |
| `aws-config` 1.13 (default features off; `rt-tokio`, `default-https-client`, `behavior-version-latest`, so no SSO or credential-process providers) | `bower-lambda` | Region and credentials from the Lambda environment (the execution role's session variables) through the standard provider chain, so no key is configured or stored. Timeouts are set explicitly (3 s connect, 8 s attempt, 20 s operation). | Reading `AWS_ACCESS_KEY_ID`/`AWS_SESSION_TOKEN` and signing by hand (SigV4 is security-sensitive code to own). |
| `aws-sdk-cloudtraildata` 1.118 | `bower-lambda` | `PutAuditEvents`, the only supported ingestion API for CloudTrail Lake custom integrations, with SigV4, retries for throttling and typed `successful`/`failed` results. | Raw HTTPS with `reqwest` plus hand-written SigV4 (more security-sensitive code, no retry classifier). |
| `aws-sdk-cloudwatchlogs` 1.160 | `bower-lambda` | `CreateLogStream` and `PutLogEvents` for the default `cloudwatch-logs` destination (CloudTrail Lake is closed to new customers since 31 May 2026), with SigV4, throttling retries and typed `rejectedLogEventsInfo`. It adds `aws-smithy-eventstream` (used by the SDK's Live Tail API, not by Bower). | Raw HTTPS with hand-written SigV4; the Lambda runtime's stdout (would mix Bower events with operational logs in one group and lose the per-event accept/reject result). |
| `aws-sdk-secretsmanager` 1.123 | `bower-lambda` | Optional `GetSecretValue` for the privacy HMAC key by ARN with the execution role, once at cold start, held in memory only. Packaging a key file would put the secret in the code artefact. | The Parameters and Secrets Lambda extension (an extra layer and a localhost HTTP hop); not supporting HMAC profiles in Lambda. |

These SDK crates (before `aws-sdk-cloudwatchlogs`, which adds 2 more) add 47 packages to `Cargo.lock` (the `aws-smithy-*` runtime, `aws-sigv4`,
`aws-sdk-sts` for the credential chain, `h2`, `futures`, `tokio-util`, `xmlparser`,
`base64` 0.22 next to the workspace's 0.23, and small helpers). TLS stays on rustls
with `aws-lc-rs`, which the workspace already links through reqwest. The minimum Rust
version of every added crate is at most 1.94.1, below the workspace's 1.97.

## PowerShell modules (`powershell/`)

The Bower PowerShell modules bundle no third-party code and declare no
`RequiredModules`. Optional modules are imported only by the commands that need them,
with a clear error when absent:

| Module / tool | Used by | Why | Alternatives considered |
|---|---|---|---|
| `Az.Accounts` (optional) | `Connect-BowerManagement`, `Send-BowerSecurityEvent -Target AzureFunction -Audience` | First-party Entra token acquisition (`Get-AzAccessToken`, SecureString tokens) reusing the operator's existing Azure sign-in. `-AccessToken` and `-TokenProvider` work without it. | Bundling MSAL.PS (third-party, unmaintained); device-code flow in-module (token handling code to own). |
| `AWS.Tools.Common` (optional) | `Send-BowerSecurityEvent -Target Lambda` | First-party AWS credential resolution (profiles, SSO, default chain). SigV4 signing itself is ~100 lines in `Private/Lambda/AwsSigV4.ps1`, pinned by the AWS documentation test vector. | Reading `~/.aws` files in-module (re-implements the credential chain); requiring the AWS CLI. |
| `Microsoft.Graph.Applications` (optional) | `New-BowerEntraApplication -Apply` | First-party Graph cmdlets for app registrations and service principals. | Raw Graph REST calls (token handling and paging to own). |
| `az`, `aws`, `terraform`, `bower` CLIs (optional) | `Bower.Deployment`, `Test-BowerPrivacyProfile`, `Bower.Policy` | The deployment commands wrap the existing templates with the tools those templates already require. Invoked with argument arrays through one mockable function. | Re-implementing what-if, change sets or plans. |
| `Pester` 5.9, `PSScriptAnalyzer` 1.25 (development only) | `powershell/build.ps1`, CI | Standard PowerShell test framework and linter, both Microsoft/PowerShell-community maintained. Pinned in CI. | None comparable. |

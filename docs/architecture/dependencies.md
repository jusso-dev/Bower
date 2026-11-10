# Dependency decisions

`AGENTS.md` requires written justification for new dependencies.

The disposable `lab/aws` harness uses Python 3.9+ standard library, AWS CLI v2,
OpenSSL and nginx on the Amazon Linux control host, and the AWS-provided
AWSPowerShell module on Windows Server 2022. These are lab-only tools: AWS CLI and
AWSPowerShell use instance roles to fetch ephemeral secrets without embedding
credentials in command text; OpenSSL creates the isolated TLS/signing material;
nginx restricts development administration to loopback while collectors use TLS.
The resolved AMI IDs and artifact hashes are recorded for each run. No product
runtime or Python package dependency is added. The wecfix profiler report
(`lab/aws/wecfix/etlstacks`, lab-only, never shipped or run in CI) uses
`Microsoft.Diagnostics.Tracing.TraceEvent` 3.1.23 (MIT, Microsoft) to read the in-box Windows
Performance Recorder trace and resolve frames against the build's PDBs; the alternative
(Windows Performance Analyzer) is not on Windows Server and has no scriptable report. CI reuses its existing pinned
`cfn-lint` for generated infrastructure. Alternatives are custom SigV4 clients,
hand-written TLS provisioning or exposing development admin remotely, each with
more security-sensitive code or weaker isolation.

The offline `tools/queue-migration-check` project references `Bower.Persistence`
to reuse canonical `EventIdentity` and the existing SQLite/contract dependencies;
it adds no NuGet packages. Unit tests reference the tool to exercise the exact
command and read-only checker without duplicating identity logic in a script or
adding a native CLI command.

`Bower.Pipeline` references `Bower.Redaction` so the custom-log parser preview
reuses the built-in privacy detectors for its server-owned masking floor rather
than duplicating detector patterns. It adds no NuGet packages.

`Bower.Management.Api` references `Bower.Evidence` and `Bower.Dcr` so the onboarding
wizard runs the unchanged evidence runner and DCR drift checks instead of duplicating
proof semantics. This brings `Azure.Identity` (already pinned and AOT clean for the CLI)
into the management API for the optional read-only verifier identity; no new package is
added to the repository.

The parser transform language (`Bower.Pipeline.Transforms`) adds no packages. Its regex
engine is Bower's own, so captures and step counts are deterministic; see the
[decision record](transform-language.md).

| Package | Used by | Why | Alternatives considered |
|---|---|---|---|
| `AWSSDK.SQS`, `AWSSDK.S3` 4.0 | `Bower.Agent.Cloud`; `Bower.Output.S3` (S3 only, so also `Bower.Collector`) | SigV4-signed SQS receive/delete/visibility and bounded S3 `GetObject` with `ExpectedBucketOwner`, using the AWS default credential chain (EC2 instance profile with IMDSv2, ECS task role, EKS IRSA). Apache-2.0, first-party. Only these two service clients are referenced. The S3 output reuses the already-pinned `AWSSDK.S3` for conditional `PutObject` (`If-None-Match`, `x-amz-checksum-sha256`, SSE, `ExpectedBucketOwner`) with the same chain; it adds no package to the central pins, but the collector now ships `AWSSDK.Core` and `AWSSDK.S3`. | Hand-written SigV4 over `HttpClient` (security-sensitive code to own and audit); AWS CLI sidecar (shell, extra image surface); a presigned-URL or HTTP output (needs a separate signer anyway). |
| `AWSSDK.SecurityToken` 4.0 | `Bower.Agent.Cloud`; `Bower.Output.S3` | Loaded by AWSSDK.Core to exchange an IRSA or Workload Identity web token for temporary credentials (`AssumeRoleWithWebIdentity`). Without it IRSA silently fails. | None for IRSA in .NET. |
| `Vecc.YamlDotNet.Analyzers.StaticGenerator` 18.1 (build-time only, `PrivateAssets=all`) | `Bower.PolicyEngine`, `Bower.Redaction`, `Bower.Pipeline`, `Bower.Packs` | Roslyn source generator that emits YamlDotNet's `StaticContext` for policy, privacy profile, pipeline and pack YAML, so YAML binding needs no reflection under Native AOT. Published by the YamlDotNet maintainers at the same version as `YamlDotNet`. Nothing ships at run time. | Hand-written YAML-to-model mapping over YamlDotNet's parser (more code to keep in step with the models); YamlDotNet reflection deserializer (IL2026/IL3050 under AOT). |
| `Microsoft.Azure.Functions.Worker` 2.52, `Microsoft.Azure.Functions.Worker.Extensions.Http` 3.3, `Microsoft.Azure.Functions.Worker.Sdk` 2.1 (build-time) | `Bower.Functions.Collector` | The supported Azure Functions isolated worker model for .NET 10 (the in-process model ends in November 2026 and does not support .NET 10). Worker hosts the HTTP triggers over the host's gRPC channel (pulls `Grpc.Net.Client`, `Google.Protobuf`, `Microsoft.Extensions.Hosting`); Extensions.Http provides `HttpRequestData`; the Sdk generates function metadata and the host extension bundle at build time. MIT, first-party. Only the plain HTTP extension is used, not ASP.NET Core integration, Application Insights worker packages or storage bindings. | Custom handler hosting a native binary or a minimal ASP.NET app (custom handlers lose the native .NET worker model and its tooling); ASP.NET Core integration (`Worker.Extensions.Http.AspNetCore`, more surface for three routes). |
| `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.23.0 | `Bower.Functions.Collector` | In-code Entra v2 token validation (RS256 signature against OIDC signing keys with refresh on rollover, issuer, audience, lifetime) with the Microsoft-maintained validator. The central pin also lifts `Microsoft.AspNetCore.Authentication.JwtBearer` (which needs 8.19.2 or later) to the same version for the management API. Central pins also align `Bower.Source.SqlServer` (Microsoft.Data.SqlClient's IdentityModel 8.16.0 → 8.23.0, `Microsoft.Bcl.Cryptography` 9.0.18 → 10.0.2); no API change. | `JwtBearer` (needs the ASP.NET Core pipeline, which the plain HTTP worker does not have); Functions Easy Auth alone (configuration outside the code, no role/tenant checks testable offline). |
| `Microsoft.Extensions.Hosting.WindowsServices` 10.0.14 | `Bower.Collector` | Runs the collector under the Windows service control manager for the MSI (#112): start, stop and shutdown reporting, and warnings and errors to the Application event log. Microsoft-owned, same release train as the shared framework, AOT clean, and a no-op unless the process is a Windows service (Linux, containers and tests are unchanged). Pulls `System.ServiceProcess.ServiceController` and `Microsoft.Extensions.Logging.EventLog` (Windows-only code paths). | A third-party service wrapper (WinSW, NSSM: another binary to ship, sign and trust); hand-written `StartServiceCtrlDispatcher` P/Invoke (security-relevant lifecycle code to own); a scheduled task at boot (no SCM recovery, no service SID for the folder ACLs). |
| `Microsoft.AspNetCore.TestHost` | Tests only | Runs the collector and management API in-process for HTTP, authentication and rate-limit tests. | `Microsoft.AspNetCore.Mvc.Testing` (needs a single `Program` entry point per test assembly). |

| `nginxinc/nginx-unprivileged` (container base image) | `Dockerfile.web` | Serves the static console as a non-root user on a read-only filesystem, with runtime config. Official NGINX image. | Serving from the management API only (still supported); Caddy (no official unprivileged image). |

### Build and test tools for the native installers (#112)

The build tools do not run on collector hosts. The WiX Util extension embeds a native
custom action in the MSI that runs only during installation, repair or upgrade.

| Tool | Used by | Why | Alternatives considered |
|---|---|---|---|
| [nfpm](https://github.com/goreleaser/nfpm) 2.48.0 (MIT), static binary downloaded in CI and checked against a pinned SHA-256 | `package-linux` job | Builds the deb and the rpm from one manifest (`deploy/installers/linux/nfpm.yaml`) with the same files, modes and maintainer scripts, and signs both with one GPG key when configured. | `dpkg-deb` plus `rpmbuild` (preinstalled and installable on the runner, but two manifests to keep in step, and an rpm spec that rebuilds nothing); fpm (Ruby gem tree). |
| WiX Toolset 5.0.2 (`wix` .NET tool from nuget.org, MS-RL) | `package-windows` job | Authors the MSI declaratively: service install as a virtual account, folder ACLs from SDDL, remembered properties, upgrade rules. Pinned to v5 deliberately: WiX v6 and later are under the Open Source Maintenance Fee EULA, which v7 enforces and which a person, not CI, must accept for the organisation. Upgrading needs that decision first. | WiX v3 (.NET Framework, end of life); msitools `wixl` (subset of WiX, no service ACLs); MSIX (no Windows service support for this model). |
| `ansible-core` 2.21.5 (via `uvx`, GPL-3.0) | `install-linux` job | Runs the example role (`deploy/ansible`) against the runner to prove it installs, enrols, is idempotent and uninstalls cleanly. The role uses `ansible.builtin` modules only, so no collection is installed. | Testing the role only with `--syntax-check` (does not prove it works). |
| `WixToolset.Util.wixext` 5.0.2 (MS-RL) | Windows MSI service recovery | Configures restart actions with the required service access rights and rollback support. Pinned to the same version as WiX; adds no collector runtime dependency. | The native MSI failure-actions table fails with error 5 on the Windows install runner; a shell custom action would require our own upgrade and rollback implementation. |
| `rockylinux/rockylinux:9-ubi-init` (container image, pinned by digest) | `install-linux` job | A RHEL 9 family host with systemd as PID 1, so the rpm install test exercises the real unit, account and maintainer scripts on a GitHub runner. | AlmaLinux init images (equivalent; one is enough); a RHEL VM (not available on GitHub runners). |
| `actions/download-artifact` v8.0.2 (pinned SHA) | packaging and install jobs | Consumes the existing `publish` artefacts so packages contain exactly the binaries CI built and tested, and passes packages to the install tests. | Rebuilding the binaries in each packaging job (slower, and no longer the same artefacts). |

`Bower.Agent.Docker` uses the ASP.NET Core shared framework (`FrameworkReference`)
for the generic host, logging and `IHttpClientFactory`, so it adds no NuGet packages.
`Bower.Agent.Cloud` does the same; its only packages are the AWS SDKs above. Google
credentials are handled in-house (see "Removed for Native AOT" below), so no Google
package is referenced.
`Bower.Source.WindowsEventLog` uses the same shared framework for
`System.Diagnostics.Eventing.Reader` (`EvtQuery`, `EvtNext`, `EvtRender` over the local
event log service), which the collector already ships; it adds no NuGet packages. The
reader is Windows only (`[SupportedOSPlatform("windows")]`); event XML parsing uses
`System.Xml` with DTDs prohibited and no resolver.
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

### HTTP output (`BOWER_OUTPUT=http`)

`src/Bower.Output.Http` adds no NuGet packages: it uses `HttpClient`
(`SocketsHttpHandler`), `GZipStream` and `System.Text.Json` from the runtime, and
references only `Bower.Abstractions`. Alternatives considered: a Splunk SDK (adds a
dependency for a single documented POST) and a generic log shipper (out of scope: Bower
is not a log forwarder).

### Local syslog output (`BOWER_OUTPUT=syslog`)

`src/Bower.Output.Syslog` adds no NuGet packages: it sends datagrams on a Unix socket with
`System.Net.Sockets`. It references `Bower.Abstractions` and `Bower.Dcr`, the second for the
same record checks the Logs Ingestion output runs (`IngestionPreflight`, `SentinelSchema`)
before a record reaches `BowerSecurity_CL`, and `Bower.Dcr` has no package references of its
own. `Bower.Cli` references this project for the `bower doctor --syslog-socket` check.
Alternatives considered: a
syslog client library (a dependency for one message format on one local socket) and calling
`syslog(3)` through P/Invoke (process-wide state, no error per message, so a full socket would
be silent).

### Signed pack runtime activation

`Bower.Packs` reuses its existing Detection, Pipeline, PolicyEngine and Redaction
references for bounded raw mapping and post-redaction detection enrichment. The
collector composes that wrapper around its existing redactor; no external runtime
package is added. Detection's internal scalar/condition encoding uses a generated
System.Text.Json context (`DetectionJsonContext`) and evidence uses
`DetectionEvidenceJson`, preserving Native AOT analysis without suppressions.

## PowerShell modules (`powershell/`)

The Bower PowerShell modules bundle no third-party code and declare no
`RequiredModules`. Optional modules are imported only by the commands that need them,
with a clear error when absent:

| Module / tool | Used by | Why | Alternatives considered |
|---|---|---|---|
| `Az.Accounts` (optional) | `Connect-BowerManagement`, `Send-BowerSecurityEvent -Target AzureFunction -Audience` | First-party Entra token acquisition (`Get-AzAccessToken`, SecureString tokens) reusing the operator's existing Azure sign-in. `-AccessToken` and `-TokenProvider` work without it. | Bundling MSAL.PS (third-party, unmaintained); device-code flow in-module (token handling code to own). |
| `Microsoft.Graph.Applications` (optional) | `New-BowerEntraApplication -Apply` | First-party Graph cmdlets for app registrations and service principals. | Raw Graph REST calls (token handling and paging to own). |
| `az`, `aws`, `terraform`, `bower` CLIs (optional) | `Bower.Deployment`, `Test-BowerPrivacyProfile`, `Bower.Policy` | The deployment commands wrap the existing templates with the tools those templates already require. Invoked with argument arrays through one mockable function. | Re-implementing what-if, change sets or plans. |
| `Pester` 5.9, `PSScriptAnalyzer` 1.25 (development only) | `powershell/build.ps1`, CI | Standard PowerShell test framework and linter, both Microsoft/PowerShell-community maintained. Pinned in CI. | None comparable. |

## Collector settings trust: operating-system APIs

The C# settings loader uses the operating system's existing native libraries, with no
additional package or runtime service. Linux uses `libc` `openat`/`statx` to verify and
read the same objects. Windows uses `kernel32` handle APIs, `advapi32` security-descriptor
queries, and `ntdll` `NtCreateFile` for directory-handle-relative opens with
`OBJ_DONT_REPARSE`. Path-based ACL checks followed by another open permit substitution;
rejecting every ancestor metadata-write grant also rejects normal ProgramData ACLs.
Native calls are limited to read-only handles, bounded descriptors and fixed structures,
and failures refuse startup. Dedicated native platform tests gate release qualification.

The C# file tail source (`Bower.Source.File`) uses the same libc approach on Linux to open a
tailed file with `O_NOFOLLOW | O_NONBLOCK` and to compare `statx` device and inode of the
handle and the path (`FileTailHandles.cs`), so a link or another file swapped in after the
path checks is refused. .NET has no no-follow open or inode API; other platforms only
re-check that the path is not a link after opening.

## Documentation website

| Dependency | Scope | Reason and alternatives |
|---|---|---|
| MkDocs 1.6.1 and Material 9.x | Build time only, pinned with hashes in `tools/docs/requirements.txt` | Publish the existing Markdown as searchable, responsive static HTML on GitHub Pages. Material supplies navigation, local search and light/dark themes. A small local template adds Bower's animated dataflow. Docusaurus would introduce a second React application and more tooling without improving the existing Markdown workflow. No third-party analytics, remote fonts or runtime service is added. |

The site self-hosts the existing console's OFL-licensed Geist variable font. The
license accompanies the font in `docs/assets/fonts/`. Browser checks reuse the
console's Playwright version in a separate locked test package. `@axe-core/playwright` is a development-only
accessibility check for the documentation; it is never included in the published site. Lighthouse is a development-only performance/accessibility audit, also excluded from the site.

The docs test package temporarily overrides only `@sentry/bundler-plugins`'s
`glob` to 14.0.3. Lighthouse's current Sentry dependency requests glob 13, whose
minimatch dependency and cancellation handling have moderate denial-of-service
advisories. Glob 14.0.3 uses a patched minimatch. This crosses Sentry's declared
major-version range, so the docs checks must exercise compatibility; remove the
override when Sentry or Lighthouse supports a patched dependency chain.

### Windows lab queue identity evidence: inbox SQLite API

`lab/aws/monitoring/wec-qualification.ps1` uses `winsqlite3.dll`, the Windows
Server 2016+ inbox SQLite API, through PS5.1-compatible P/Invoke. This is a lab-only
read-only projection of `event_id` and `received_at` needed to reconcile native
WEC identities with actual durable queue acceptance. It avoids exporting queue
payloads or installing a separate SQLite executable/runtime package. Input rows
and field lengths are bounded; unsupported APIs and read errors fail the
qualification. The production collector retains its existing SQLite dependency.
The API must be exercised on the owned Windows host; cross-platform compilation
and mocked tests do not establish native compatibility.

# Dependency decisions

`AGENTS.md` requires written justification for new dependencies.

| Package | Used by | Why | Alternatives considered |
|---|---|---|---|
| `Hangfire.Core`, `Hangfire.NetCore` 1.8 | `Bower.Jobs` (collector, management API) | Recurring job scheduling with cron schedules, concurrency locks, retry policy and a monitoring API for health reporting. LGPL-3.0 (used unmodified as a library). No dashboard package is referenced. | Hand-written `PeriodicTimer` services (no shared retry, locking or status model); Quartz.NET (heavier configuration for the same job set). |
| `Hangfire.InMemory` 1.0 | `Bower.Jobs` | First-party Hangfire storage with no external database. Jobs are idempotent and state lives in Bower's SQLite stores, so scheduler state may be lost on restart. | `Hangfire.Storage.SQLite` (community-maintained), SQL Server or Redis storage (new infrastructure). |
| `Newtonsoft.Json` 13.0.4 (pinned) | `Bower.Jobs` | Hangfire.Core accepts Newtonsoft.Json ≥ 11.0.1, which has GHSA-5crp-9r3c-p9vr. Pinning a patched version removes the vulnerable resolution. Not used by Bower code. | None; required by Hangfire's serializer. |
| `AWSSDK.SQS`, `AWSSDK.S3` 4.0 | `Bower.Agent.Cloud` | SigV4-signed SQS receive/delete/visibility and bounded S3 `GetObject` with `ExpectedBucketOwner`, using the AWS default credential chain (EC2 instance profile with IMDSv2, ECS task role, EKS IRSA). Apache-2.0, first-party. Only these two service clients are referenced. | Hand-written SigV4 over `HttpClient` (security-sensitive code to own and audit); AWS CLI sidecar (shell, extra image surface). |
| `AWSSDK.SecurityToken` 4.0 | `Bower.Agent.Cloud` | Loaded by AWSSDK.Core to exchange an IRSA or Workload Identity web token for temporary credentials (`AssumeRoleWithWebIdentity`). Without it IRSA silently fails. | None for IRSA in .NET. |
| `Google.Apis.Auth` 1.77 | `Bower.Agent.Cloud` | Application Default Credentials including GKE Workload Identity, the metadata server and Workload Identity Federation (`external_account`, including AWS-sourced tokens), with token caching and refresh. Lets Bower detect and refuse service account key files. Apache-2.0, first-party. Pub/Sub itself is called over REST with `HttpClient`, so the gRPC stack is not pulled in. Brings `Google.Apis`, `Google.Apis.Core`, `Newtonsoft.Json` (already pinned) and `System.Management` (Windows-only code paths, unused on Linux). | `Google.Cloud.PubSub.V1` (gRPC, much larger dependency tree); hand-written STS token exchange for each credential type. |
| `Microsoft.AspNetCore.TestHost` | Tests only | Runs the collector and management API in-process for HTTP, authentication and rate-limit tests. | `Microsoft.AspNetCore.Mvc.Testing` (needs a single `Program` entry point per test assembly). |

| `nginxinc/nginx-unprivileged` (container base image) | `Dockerfile.web` | Serves the static console as a non-root user on a read-only filesystem, with runtime config. Official NGINX image. | Serving from the management API only (still supported); Caddy (no official unprivileged image). |

`Bower.Agent.Docker` uses the ASP.NET Core shared framework (`FrameworkReference`)
for the generic host, logging and `IHttpClientFactory`, so it adds no NuGet packages.
`Bower.Agent.Cloud` does the same; its only packages are the cloud SDKs above.
`Bower.Source.Gcp` and the AWS queue parser in `Bower.Source.Aws` have no dependencies:
parsing stays pure and testable without cloud access.

Review these when upgrading: AWS SDK for .NET 5.x, Google.Apis.Auth major versions
(credential-type changes affect the key-file refusal), Hangfire 2.x, a Hangfire release that drops the
Newtonsoft.Json floor, or a move to durable job storage.

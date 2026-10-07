# Dependency decisions

`AGENTS.md` requires written justification for new dependencies.

| Package | Used by | Why | Alternatives considered |
|---|---|---|---|
| `Hangfire.Core`, `Hangfire.NetCore` 1.8 | `Bower.Jobs` (collector, management API) | Recurring job scheduling with cron schedules, concurrency locks, retry policy and a monitoring API for health reporting. LGPL-3.0 (used unmodified as a library). No dashboard package is referenced. | Hand-written `PeriodicTimer` services (no shared retry, locking or status model); Quartz.NET (heavier configuration for the same job set). |
| `Hangfire.InMemory` 1.0 | `Bower.Jobs` | First-party Hangfire storage with no external database. Jobs are idempotent and state lives in Bower's SQLite stores, so scheduler state may be lost on restart. | `Hangfire.Storage.SQLite` (community-maintained), SQL Server or Redis storage (new infrastructure). |
| `Newtonsoft.Json` 13.0.4 (pinned) | `Bower.Jobs` | Hangfire.Core accepts Newtonsoft.Json ≥ 11.0.1, which has GHSA-5crp-9r3c-p9vr. Pinning a patched version removes the vulnerable resolution. Not used by Bower code. | None; required by Hangfire's serializer. |
| `Microsoft.AspNetCore.TestHost` | Tests only | Runs the collector and management API in-process for HTTP, authentication and rate-limit tests. | `Microsoft.AspNetCore.Mvc.Testing` (needs a single `Program` entry point per test assembly). |

Review these when upgrading: Hangfire 2.x, a Hangfire release that drops the
Newtonsoft.Json floor, or a move to durable job storage.

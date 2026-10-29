# Continuous integration

Every pull request and merge to `main` starts CI. A small change-selection job
decides which tests apply; it does not build every platform on every merge.
The six existing required check names remain stable. `ci-success` is the aggregate
merge gate: any failed or cancelled selected job blocks merging, including browser,
container and installer checks.

| Change | Routine validation |
| --- | --- |
| Documentation | Workflow lint; documentation build, links, browser/accessibility tests in the separate Documentation workflow |
| Console | Lint, audit, unit/build checks and browser tests against the management API |
| C# source/tests | Release build, unit tests, signed pack tests, formatting, Windows event-log tests and management browser tests |
| Rust | Formatting, Clippy, workspace tests and signed pack tests using the already-built debug profile |
| Packs, schemas, policies | C#, Rust, PowerShell and browser checks; default-policy changes also validate installers |
| PowerShell | PSScriptAnalyzer and Pester |
| Infrastructure | CloudFormation lint and Terraform validation; Azure templates also run C# contract tests |
| Containers, relay or enrolment integration | Container builds, enrolment/relay smoke tests and ARM64 AOT container builds |
| Installers, Ansible or systemd | Six native targets, Linux/Windows packages and installation tests |
| CI definitions, global build settings or unknown paths | Full validation, conservatively |

Release tags (`v*.*.*`), manual CI dispatch and the weekly Monday 03:23 UTC run
always validate everything, including the six native OS/architecture targets,
ARM64 containers and installers. Ordinary source edits defer that broad platform
coverage to these full runs unless they touch the specialist inputs above.
This saves runner time but means a platform-specific regression in an ordinary
source edit can be discovered by the weekly run rather than before merge. Run
full CI manually before shipping a release candidate.

Selection uses a local Git diff, not the GitHub API's capped file list. PRs use
their merge base; pushes compare the entire before/after range. Renames include
both old and new paths. Unknown files run the full suite; Git errors fail CI.
`tools/ci/test_select_jobs.py` protects these rules. Add selection tests when adding
a new product directory or workflow.

Only superseded PR runs are cancelled. NuGet and Cargo download caches reduce
network work, browser tests use the managed API host instead of publishing AOT,
and independent jobs start together rather than waiting for other builds.

## Container publication

The Images workflow publishes all six images for `linux/amd64` and `linux/arm64`
on a release tag or explicit manual dispatch. Merging to `main` does **not**
publish images. To refresh `edge`, dispatch Images on `main` after its CI passes:

```sh
gh workflow run images.yml --ref main
```

Manual publication retains the main-ancestry guard; release tags publish versioned
tags and `latest`. Build caches, SBOMs and provenance attestations remain enabled.
The `edge` tag therefore means the last manually published main revision, not
necessarily the newest merge.

# Continuous integration

Every pull request and merge to `main` starts CI. A small change-selection job
decides which tests apply; it does not build every platform on every merge.
The six existing required check names remain stable. `ci-success` is the aggregate
merge gate: any failed or cancelled selected job blocks merging, including browser,
container and installer checks.

| Change | Routine validation |
| --- | --- |
| Documentation (`docs/`, `tools/docs/`, `tools/compliance/`, README, PRODUCT, SECURITY) | Release build and unit tests (citation, CLI reference and Sentinel table contracts read these files); documentation build, links, browser/accessibility tests in the separate Documentation workflow |
| Site styling, plans, reports, contributor notes, Dependabot config, the Documentation, Images or ASVS examples workflow | Workflow lint only (the separate workflows run themselves) |
| Examples | Release build and unit tests, and the infrastructure jobs that run the cloud agent quick starts |
| Package versions (`Directory.Packages.props`) | Everything except the native platform matrix and installers; those also run when the CLI or collector lock file changes |
| Console | Lint, audit, unit/build checks and browser tests against the management API |
| C# source/tests | Release build, unit tests, signed pack tests, formatting, Windows event-log tests and management browser tests |
| Packs, schemas, policies | C#, PowerShell and browser checks; default-policy changes also validate installers |
| PowerShell | PSScriptAnalyzer and Pester |
| Infrastructure | CloudFormation lint and Terraform validation; Azure templates also run C# contract tests |
| Containers, relay or enrolment integration | Container builds, enrolment/relay smoke tests and ARM64 AOT container builds |
| Installers, Ansible or systemd | Six native targets, Linux/Windows packages and installation tests |
| CI definitions, global build settings or unknown paths | Full validation, conservatively |

Every .NET job restores with `--locked-mode`, so a package version change that reaches
the CLI or collector without regenerating `src/Bower.Cli/packages.lock.json` or
`src/Bower.Collector/packages.lock.json` fails `build-test` (#270). A version change that
does regenerate either lock file selects the six native targets and installers.

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

Only superseded PR runs are cancelled. NuGet download caches reduce
network work, browser tests use the managed API host instead of publishing AOT,
and independent jobs start together rather than waiting for other builds.

## Container publication

The Images workflow publishes all five images for `linux/amd64` and `linux/arm64`
on a release tag or explicit manual dispatch. Merging to `main` does **not**
publish images. To refresh `edge`, dispatch Images on `main` after its CI passes:

```sh
gh workflow run images.yml --ref main
```

Manual publication retains the main-ancestry guard; release tags publish versioned
tags and `latest`. Build caches, SBOMs and provenance attestations remain enabled.
The `edge` tag therefore means the last manually published main revision, not
necessarily the newest merge.

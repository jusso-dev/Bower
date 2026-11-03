# Release versioning: evidence (run `bower-version-20261103-063441`)

What was run: the release-versioning change in
[PR #175](https://github.com/jusso-dev/Bower/pull/175), documented in
[release versioning](../../operations/release-versioning.md). No AWS or Azure resources
were needed or created; the CI install jobs on Linux and Windows are the live proof.

## Local checks (macOS arm64, .NET SDK 10.0.403, Rust stable)

| Check | Result |
| --- | --- |
| `dotnet build Bower.sln -c Release` | Pass, 0 warnings |
| `dotnet test --solution Bower.sln -c Release` | Pass: 2,204 total, 0 failed, 2 skipped (Windows-only event log tests) |
| `dotnet format --verify-no-changes` | Pass |
| Build stamped with `-p:BowerVersion=0.1.0-dev.362 -p:BowerBuildNumber=362` | `bower --version` → `bower 0.1.0-dev.362`; `Bower.Collector --version` → `bower-collector 0.1.0-dev.362`; `BowerVersionTests` pass with `BOWER_EXPECTED_VERSION=0.1.0-dev.362` and fail (1 of 5) with `0.1.0-dev.999`, so the check bites |
| Invalid versions (`0.1.0-beta.1`, `0.1.1` against `VERSION` 0.1.0, build number 65536) | Build fails with the documented message |
| `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace --no-fail-fast` | Pass; unstamped binaries print `bower 0.1.0-dev.0` / `bower-collector 0.1.0-dev.0` |
| `python3 -m unittest discover -s tools/ci` | Pass, 33 tests (incl. 12 in `test_version.py`) |
| `python3 -m unittest discover -s lab/aws/tests` | Pass |
| `mkdocs build --strict` and `tools/docs/check_links.py` | Pass, 108 pages |
| `actionlint`, `zizmor --min-severity high` | Clean |
| PSScriptAnalyzer on `deploy/installers/windows` (5.1 and 7.4 syntax) | 0 findings |

Failed attempts kept for the record:

- The first MSBuild validation regex used `\.` and `\d`; MSBuild on macOS/Linux turned the
  backslashes into `/`, so the build rejected `0.1.0`. Fixed with character classes.
- The first full .NET run failed `PolicyParityVectorTests.LoaderVectors_MatchCSharpOutcomes`:
  YamlDotNet error text includes `Version=1.0.0.0` of the assembly, and the change had moved
  `AssemblyVersion` to `0.1.0.0`. `AssemblyVersion` is now pinned to `1.0.0.0`.
- The first full Rust run failed the status key-order test and the Lambda parity test
  (Lambda used `CARGO_PKG_VERSION`). Both now use the release version.

## CI (the live proof)

The `version`, `build-test`, `rust`, `docker`, `package-linux`, `package-windows`,
`install-linux` (Ubuntu deb, Rocky Linux 9 rpm) and `install-windows` (Windows Server MSI)
jobs of the PR's CI run are the proof for upgrade, refused downgrade, explicit rollback and
same-version reinstall. Their results are in the PR checks; a result not shown there as
passed is **not passed**.

## Limits

- Kubernetes, AWS EC2 and Azure VM hosts use the same packages and images; they were not run
  separately. arm64 packages are built, not install-tested.
- Upgrade tests run with an almost empty queue.

## Cleanup audit

No cloud resources were created for this run: no AWS or Azure API calls were made, so zero
resources with RunId `bower-version-20261103-063441` exist in either account.

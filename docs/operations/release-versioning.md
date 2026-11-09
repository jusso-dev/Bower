# Release numbering and versioning

Every Bower build has one version. The collector, the CLI, the packages, the MSI and the
container images all report it, so an operator can tell exactly which build is running and an
upgrade can never be mistaken for a downgrade. This page is the reference for the scheme, how
CI computes it, how to cut a release, how to read the installed version in every
environment, and how upgrades, downgrades and reinstalls behave.

Releases and packages are **unsigned**; signing is deferred. Bower still refuses unsigned or
untrusted packs. Verify every artefact by its SHA-256 from a trusted channel.

## The scheme

| Part | Rule | Example |
| --- | --- | --- |
| `VERSION` (repository root) | The next release, `MAJOR.MINOR.PATCH`. The single source of truth. MAJOR and MINOR at most 255 (MSI limit). It starts at `0.1.1`, above the `0.1.0` that builds before this scheme hard-coded, so every new build sorts above them. | `0.1.1` |
| Release | Git tag `v<VERSION>`. The version is `<VERSION>`. | `v0.1.1` → `0.1.1` |
| Release candidate | Git tag `v<VERSION>-rc.N`. | `v0.1.1-rc.1` → `0.1.1-rc.1` |
| Development build | Every other CI run (main, pull requests, manual runs): `<VERSION>-dev.<run number>`. | `0.1.1-dev.362` |
| Unnumbered build | A local build, a manually published image, or the CI upgrade-test package: `<VERSION>-dev.0`. | `0.1.1-dev.0` |
| Build number | The CI run number of the `CI` workflow (1–65535). Every installable build gets a new, higher one. | `362` |

Order, lowest first: `0.1.1-dev.1` < `0.1.1-dev.362` < `0.1.1-rc.1` < `0.1.1-rc.2` < `0.1.1` <
`0.1.2-dev.400` < `0.1.2`. This is semantic-version precedence for the two pre-release labels
Bower uses (`dev`, `rc`). No other labels and no `+build` metadata are accepted; CI and the
build fail on anything else.

**One ordering rule on every platform.** deb, rpm, the MSI and the fleet console all order
versions this way, and refuse or flag a semantic downgrade the same way, whatever order the
builds were made in. An installed `0.2.0-rc.1` is newer than a `0.2.0-dev.401` built after
it, and `0.2.1` is newer than a `0.2.0` rebuilt later.

### Where the version goes

| Artefact | Field | Value for build 362 of `0.1.1` |
| --- | --- | --- |
| .NET assemblies | `AssemblyInformationalVersion` (`BowerVersion.Current`) | `0.1.1-dev.362` |
| | `AssemblyVersion` (pinned: error text and parity vectors carry it) | `1.0.0.0` |
| | `FileVersion` (Windows file properties) | `0.1.1.362` |
| Collector | `/v1/status` `version`; management enrolment and heartbeat `version`; `collector.version` on every event, including `collector_health` | `0.1.1-dev.362` |
| CLI and collector binaries | `bower --version`, `bower version`, `Bower.Collector --version`, `bower-collector --version` | `bower 0.1.1-dev.362` |
| deb | `Version` (`~` sorts a pre-release before the release; release `1`) | `0.1.1~dev.362-1` |
| rpm | `Version`, `Release` | `0.1.1~dev.362`, `1` |
| Linux packages | `/usr/share/bower/version` (read by the next package's downgrade guard) | `0.1.1-dev.362` |
| MSI | `ProductVersion` (shown as `DisplayVersion` in Programs and Features) | `0.1.362` |
| | `HKLM\SOFTWARE\Bower\Collector\Version`, `ARPCOMMENTS` | `0.1.1-dev.362` |
| | `HKLM\SOFTWARE\Bower\Collector\VersionKey`: fixed-width sort key `MMM.mmm.PPPPP.S.NNNNN` (S: 0 dev, 1 rc, 2 release) | `000.001.00001.0.00362` |
| File names | Packages, offline bundles, MSI | `bower-collector-0.1.1-dev.362-x64.msi` |
| Container images | `org.opencontainers.image.version` label; image tags `<version>`, `sha-<commit>`, and for a final release also `MAJOR.MINOR` and `latest` (never for an rc) | `0.1.1` (release), `0.1.1-dev.0` (manual) |

**Why the MSI is `MAJOR.MINOR.BUILD`.** Windows Installer compares only the first three
fields of `ProductVersion` and ignores the fourth. The old `0.1.0.N` dev MSIs therefore all
compared as `0.1.0`: any one replaced any other, and a downgrade was not blocked. With the CI
build number as the third field, every build is a distinct product version. PATCH is not in
the MSI version; read the release version from the registry value above or from
`bower --version`.

**How the MSI refuses a semantic downgrade.** Build order is not version order (an rc built at
run 400 is newer than a dev build at run 401), so the MSI does not trust ProductVersion for
that decision. Each install writes `VersionKey`, a fixed-width key whose text order is the
semantic order above. The next MSI reads it (`RegistrySearch`) and its launch condition
refuses the install when the installed key is greater than its own, unless
`BOWERALLOWDOWNGRADE=1`. An install from before the key existed falls back to ProductVersion.
`tools/ci/version.py` and `build.ps1` compute the same key (tested).

### How CI computes it

The `version` job in `.github/workflows/ci.yml` runs `tools/ci/version.py` once per run and
passes `version`, `build` and `core` to every job that builds an artefact. It fetches the
tags and, on any build that is not a tag, fails once `v<VERSION>` exists, so `VERSION` must
be bumped right after a release:

```bash
python3 tools/ci/version.py --ref-type branch --ref-name main --build-number 362
# version=0.1.1-dev.362
# core=0.1.1
# build=362
# prerelease=true
# latest=false
# msi_version=0.1.362
# version_key=000.001.00001.0.00362
python3 tools/ci/version.py --ref-type tag --ref-name v0.1.1 --build-number 400
# version=0.1.1 ... latest=true ... msi_version=0.1.400 version_key=000.001.00001.2.00000
python3 tools/ci/version.py --ref-type tag --ref-name v0.2.0 --build-number 401
# error: tag v0.2.0 does not match VERSION 0.1.1: tag v0.1.1 or v0.1.1-rc.N, or update VERSION first
python3 tools/ci/version.py --build-number 402 --check-released   # after v0.1.1 is tagged, on main
# error: v0.1.1 is already released: bump VERSION before building more development builds, ...
```

- `publish` builds the .NET binaries with the MSBuild properties `BowerVersion` and
  `BowerBuildNumber`. `Directory.Build.props` reads `VERSION`, defaults to
  `<VERSION>-dev.0`, and fails the build if `BowerVersion` is not `<VERSION>`,
  `<VERSION>-dev.N` or `<VERSION>-rc.N`.
- `package-linux` and `package-windows` pass the version (and the build number for the MSI)
  to `deploy/installers/linux/build.sh` and `deploy/installers/windows/build.ps1`. They also
  build the **upgrade-test fixtures**: the same binaries packaged as `<VERSION>-dev.0`
  (artefacts `bower-upgrade-test-*`). They are never releases.
- `docker` builds `bower-collector` with
  `--build-arg BOWER_VERSION=...` and checks `--version` and the image label.
- `images.yml` (release tags and manual runs) publishes images with the release version, or
  `<VERSION>-dev.0` for a manual run of main; identify a manual image by its `sha-<commit>`
  tag and `org.opencontainers.image.revision`. Images use build number `0`: the build counter
  is the CI workflow's run number and only the MSI and Windows file version use it. Only a
  final release tag moves `latest` (`version.py` output `latest`); `v0.2.0-rc.1` publishes
  `0.2.0-rc.1` and `sha-<commit>` only, `v0.2.0` publishes `0.2.0`, `0.2`, `latest` and
  `sha-<commit>`.

## Cut a release

**Purpose.** Produce artefacts whose version is the release number everywhere.

**Prerequisites.** Maintainer rights on the repository, `gh` signed in, the release
checklist in [07 soak and release validation](../production-readiness/07-soak-and-release-validation.md#5-release-checklist-ci-gaps-1-to-7-pilot)
complete for the candidate commit.

1. Make sure `VERSION` on main holds the number you are releasing. If not, open a PR that
   changes `VERSION` (the only version source) and merge it.

   ```bash
   cat VERSION                                       # 0.2.0
   ```

2. Optional: tag a release candidate on the candidate commit and let CI build it.

   ```bash
   git fetch origin && git tag -a v0.2.0-rc.1 origin/main -m "Bower 0.2.0-rc.1" && git push origin v0.2.0-rc.1
   gh run list --workflow ci.yml --branch v0.2.0-rc.1 --limit 1
   ```

3. Tag the release on the same commit (or the commit that fixed the candidate):

   ```bash
   git tag -a v0.2.0 <commit> -m "Bower 0.2.0" && git push origin v0.2.0
   gh run watch "$(gh run list --workflow ci.yml --branch v0.2.0 --limit 1 --json databaseId --jq '.[0].databaseId')"
   ```

   Expected: the `version` job prints `version=0.2.0`; `package-*` produce
   `bower-collector_0.2.0-1_amd64.deb`, `bower-collector-0.2.0-1.x86_64.rpm` and
   `bower-collector-0.2.0-x64.msi`; `install-*` pass. `images.yml` publishes
   `ghcr.io/<owner>/bower-collector:0.2.0`.
4. Record the exact version, build number, commit, package versions, MSI ProductVersion and
   hashes in the release record (07, check 0).
5. **Immediately bump `VERSION` on main** to the next number (for example `0.2.1` or
   `0.3.0`). Until you do, every non-tag CI run fails in the `version`
   job with `v0.2.0 is already released`, because its `0.2.0-dev.N` builds would sort before
   the release.

Pass: every artefact name and every reported version is `0.2.0`. Fail: the tag build fails
in `version` (tag and `VERSION` differ: delete the tag, fix `VERSION`, tag again).

Rollback of a bad tag before anyone installs it: `git push origin :refs/tags/v0.2.0`, delete
the GitHub release and images if published, fix, and tag the next patch (`0.2.1`). Never
reuse a published version number for different content.

## Check the installed version

The version a collector reports must match the artefact you installed. Use the same checks
for upgrade verification and for the [07 release record](../production-readiness/07-soak-and-release-validation.md).

### Linux packages (RPM/DEB, systemd), including AWS EC2 and Azure VMs

```bash
cat /usr/share/bower/version                          # 0.1.1-dev.362
rpm -q bower-collector || dpkg-query -W bower-collector
/usr/bin/bower --version                              # bower 0.1.1-dev.362
/opt/bower/Bower.Collector --version                  # bower-collector 0.1.1-dev.362
# The header goes to curl on stdin (-K -), never in its argument list (visible in ps).
sudo cat /etc/bower/secrets/ingest-token | sed 's/^/header = "Authorization: Bearer /; s/$/"/' |
  curl -fsS -K - http://127.0.0.1:4319/v1/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'
```

On EC2 run the commands through SSM Run Command (`AWS-RunShellScript`); on Azure VMs through
Run Command (`RunShellScript`). Pass: all print the same version.

### Windows (MSI and Windows service), including WEC hosts

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Bower\Collector').Version                       # 0.1.1-dev.362
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object DisplayName -eq 'Bower Collector').DisplayVersion                  # 0.1.362
& "$env:ProgramFiles\Bower\bower.exe" --version                                     # bower 0.1.1-dev.362
& "$env:ProgramFiles\Bower\Bower.Collector.exe" --version                          # bower-collector 0.1.1-dev.362
(Get-Item "$env:ProgramFiles\Bower\Bower.Collector.exe").VersionInfo.FileVersion    # 0.1.1.362
$token = [IO.File]::ReadAllText("$env:ProgramData\Bower\secrets\ingest-token").Trim()
(Invoke-RestMethod http://127.0.0.1:4319/v1/status -Headers @{ Authorization = "Bearer $token" }).version
```

For ConfigMgr or Intune detection, use the product code of the MSI, or the registry value
`HKLM\SOFTWARE\Bower\Collector\Version` equal to the deployed version.

### Docker and Kubernetes

```bash
docker image inspect ghcr.io/<owner>/bower-collector:0.2.0 \
  --format '{{ index .Config.Labels "org.opencontainers.image.version" }}'   # 0.2.0
docker run --rm ghcr.io/<owner>/bower-collector:0.2.0 --version              # bower-collector 0.2.0
kubectl --context <context> -n <namespace> exec deploy/bower-collector -- /app/Bower.Collector --version
```

Pin images by release tag or digest in `deploy/kubernetes`, never by `edge`.

### On-premises and the destination

Every event carries `collector.version` (the AWS, GCP, AMA and EC2 agent mappers stamp
the same build version), so Sentinel shows what each collector runs:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(1h)
| summarize Events = count(), LastSeen = max(TimeGenerated)
    by CollectorId, Version = tostring(RawEnvelope.collector.version)
```

The management console shows the heartbeat `version` per collector, and the fleet view calls
a collector old when it reports a lower version than the newest in the fleet, in the order
above. The newest is the newest release; a preview build (dev, rc) never makes released
collectors old. A fleet with no release yet compares its pre-releases, so drift still shows.
Builds from before this scheme report `0.1.0` and count as a release, so while one is in the
fleet the newer `0.1.1-dev.N` collectors are never called old and drift among them shows
once the last legacy collector is upgraded.

## Upgrades, reinstalls and downgrades

| Operation | deb (`dpkg -i`, `apt-get install`) | rpm (`rpm -U`, `dnf`) | MSI (`msiexec /i`) | Containers |
| --- | --- | --- | --- | --- |
| Newer build | Upgrade in place; service restarted if running; `bower.env` kept | Same | Major upgrade; old product removed first; `bower.env`, secrets, credential and queue kept | New image on the same volume |
| Same version | `dpkg -i` reinstalls | `rpm -U --replacepkgs` reinstalls (the offline installer uses it) | Same MSI: a no-op (exit 0, service untouched). A rebuild with the same ProductVersion: reinstalled as a major upgrade | Same image: nothing changes |
| Older version (semantic order, whatever the build order) | **Refused**: `bower-collector: refusing to downgrade from X to Y.` | **Refused**: natively by `rpm -U`/`dnf install`; with `--oldpackage` or `dnf downgrade` by the package guard | **Refused** by the installed `VersionKey`, even when the older version has a higher ProductVersion: exit `1603`, log: `A newer Bower Collector is already installed (X), so this older version (Y) was not installed.` | Not detected: an older image starts on the queue if the schema allows it, and is refused before any change only if it has the schema pre-check (#163 and later) |
| Explicit rollback | `sudo BOWER_ALLOW_DOWNGRADE=1 apt-get install --allow-downgrades ./old.deb` | `sudo BOWER_ALLOW_DOWNGRADE=1 dnf downgrade ./old.rpm` | `msiexec /i old.msi BOWERALLOWDOWNGRADE=1` | Pin the older tag |

### Downgrades

A refused downgrade changes nothing: the package, the running service (same PID), its
settings and the queue are untouched. On deb the old package's maintainer scripts are not
run at all on the refusal path beyond the no-op `prerm upgrade`; `postinst abort-upgrade`
does nothing. On rpm the transaction element fails in `%pre`, before files are touched.
If `/usr/share/bower/version` is present but does not hold a Bower version (for example a
corrupted or hand-edited marker), the package is refused the same way, because a newer
install cannot be ruled out.

A rollback is sometimes needed (a bad release). Allow it explicitly, and only after these
checks:

1. Read the target's release notes: the queue schema and Windows bookmark version must be
   supported by the target. If not, the target collector (targets with the pre-check, #163
   and later) refuses to start with `UnsupportedQueueSchemaException` and changes nothing; follow
   [04 rollback](../production-readiness/04-upgrade-backup-recovery.md#rollback) instead.
2. Take a backup: `bower queue backup` (see
   [04 backup](../production-readiness/04-upgrade-backup-recovery.md#back-up-a-live-collector)).
3. Roll back with the override for your platform (table above). The MSI removes the newer
   product the way an upgrade does, so `bower.env`, the secrets, the management credential
   and the queue stay.
4. Verify with [Check the installed version](#check-the-installed-version): the package and
   registry show the older version and the service is healthy.

The guard lives in the package being installed. It protects every target built with this
scheme. Rolling back to a package built **before** it (labelled `0.1.0-dev.N`) runs that
package's old maintainer scripts, which have no guard, so the platforms differ:

| Target built before the scheme | deb | rpm | MSI (`0.1.0.N`) |
| --- | --- | --- | --- |
| Behaviour over a new build | `dpkg -i` warns `downgrading` and installs it; `apt-get` asks, or needs `--allow-downgrades` with `-y` | `rpm -U` / `dnf install` refuse natively; `--oldpackage` / `dnf downgrade` install it without a guard | Refused by the old MSI's own `MajorUpgrade` (`0.1.0` < `0.1.N`); it has no override, so a rollback to it needs an uninstall first (which deletes `bower.env`, the secrets and the credential) |

**Pass/fail.** Pass: the refusal message appears, the exit status is non-zero (`1` for
dpkg/rpm, `100` for apt, `1603` for msiexec), and the installed version, service PID,
`bower.env` hash and queue are as before. Fail: anything changed.

## Troubleshooting

| Symptom | Cause | Action |
| --- | --- | --- |
| Build fails: `BowerVersion must be 0.1.1, 0.1.1-dev.N or 0.1.1-rc.N` | `-p:BowerVersion` (or the `BowerVersion` environment variable) does not match `VERSION` | Use `tools/ci/version.py` output, or omit it for a local `-dev.0` build |
| CI `version` job fails: `tag vX does not match VERSION Y` | Tag pushed before `VERSION` was bumped | Delete the tag, bump `VERSION`, tag again |
| `bower-collector: refusing to downgrade from X to Y.` | Installing an older package | Use the newer package, or roll back on purpose (above) |
| `bower-collector: refusing to install X: /usr/share/bower/version does not hold a Bower version` | The marker is corrupted or was edited by hand | Check what is installed (`dpkg -s bower-collector` or `rpm -q bower-collector`), back up the queue (`bower queue backup`), then rerun the install with `BOWER_ALLOW_DOWNGRADE=1` |
| msiexec `1603`, log `A newer Bower Collector is already installed (X)` | Installing an older version, even one built later | Use the newer MSI, or roll back with `BOWERALLOWDOWNGRADE=1` |
| CI `version` job fails: `vX is already released: bump VERSION` | A non-tag build after the release tag | Bump `VERSION` |
| An older dev MSI upgrades over a newer one | Both are pre-scheme `0.1.0.N` MSIs | Install a build made with this scheme first |
| The collector reports `0.1.0` | A build from before this scheme | Upgrade; check the package version instead |
| Status reports `X-dev.0` on a host | A local build, a manual image, or the CI upgrade-test package was installed | Install a CI or release artefact |
| Programs and Features shows `0.2.412` for release `0.2.0` | Expected: the MSI ProductVersion is `MAJOR.MINOR.BUILD` | Read `HKLM\SOFTWARE\Bower\Collector\Version` |

## Known limits

- **Unsigned.** Packages, MSIs and images are unsigned until signing is enabled.
- **Rollback to pre-scheme packages** is not guarded; see the table in
  [Downgrades](#downgrades). deb is the weakest: `dpkg -i` of an old package only warns.
- **Build numbers come from one workflow.** ProductVersion uses the `CI` workflow's run
  number, so every build is a distinct MSI product version. A local MSI
  (`build.ps1 -BuildNumber`) should use a number not used by an installed build of the same
  version. Re-running a CI run keeps its number and rebuilds the same version.
- **The `rc` → later dev window.** A dev build made after an rc tag is semantically older than
  the rc (`0.2.0-dev.401` < `0.2.0-rc.1`), so every platform refuses to install it over the rc;
  test dev builds on hosts without the rc, or tag the next rc.
- **Pull-request builds** are numbered like main builds: a PR build is "newer" than older main
  builds. Do not install PR builds on production hosts.
- **Containers** have no downgrade guard. An older image is refused before any change
  (`UnsupportedQueueSchemaException`) only if it includes the queue schema pre-check (#163 and
  later); an older image without it can write tables into a newer queue before failing. Never
  start an older image on a volume a newer release has opened.
- **PowerShell modules** keep their own module versions (`0.1.0`); they are not Bower release
  artefacts.
- **Upgrade-test fixtures** carry this build's binaries under an older package version, so after
  installing one the collector still reports this build's version.

## How we tested this

No cloud resources were needed: the CI install jobs are the live proof, and they run for every
change to the installers, packaging or workflows.

- `tools/ci/test_version.py`: version parsing and ordering, tag validation, MSI version
  mapping, and the rendered `preinstall.sh` guard with faked
  account commands (refusal, override, upgrade, same-version reinstall, unparseable versions).
- `BowerVersionTests` (C#): the stamped version reaches every assembly, `CollectorSettings`
  (no environment variable overrides it), and equals `BOWER_EXPECTED_VERSION` in CI.
  `CollectorHostTests`, `HeartbeatV2CollectorTests` and `CollectorHealthRecordTests` check
  `/v1/status`, the heartbeat and `collector_health` (`collector.version`).
  `DurabilityAdversarialTests.Replay_AfterAnUpgradeIsADuplicateAlthoughCollectorVersionChanged`
  proves a replay across an upgrade or downgrade is a duplicate, not an identity conflict.
- `install-linux` (`tests/installers/upgrade-linux.sh`) on Ubuntu (deb) and Rocky Linux 9
  (rpm) and `install-windows` (`tests/installers/windows.ps1`) on Windows Server: install
  `<VERSION>-dev.0`, upgrade, check every reported version, attempt each downgrade path,
  prove nothing changed, reinstall the same version, roll back with the override, upgrade
  again.

Local results, failed attempts and the CI jobs that prove it are recorded in the
[evidence](../evidence/version-20261103-063441/README.md) for
[PR #175](https://github.com/jusso-dev/Bower/pull/175).

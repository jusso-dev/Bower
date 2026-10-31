# Native installers: deb, rpm, MSI, Ansible and offline bundles

Issue #112 (fleet epic #116). Native packages for the Native AOT C# collector and the
`bower` CLI, built in CI from the `publish` job artefacts, plus an offline installer that
applies a pre-seeded [enrolment token](../architecture/collector-enrolment.md) and trusted
keys. A silent install joins management as `Pending`; an approver decides as usual.
Containers, Kubernetes and the plain systemd unit stay supported.

> **Signing status.** The packages are **unsigned** until a maintainer configures the
> signing secrets (below). CI then signs automatically; until then every bundle carries
> `UNSIGNED.txt`, the Windows installer warns, and you must verify artefacts by checksum
> from a channel you trust. Bower has no signed release yet (see `SECURITY.md`).

## Artefacts

Full CI runs (release tags, weekly or manual) and changes to packaging, Ansible,
systemd or default policies upload two workflow artefacts. Ordinary source and
documentation changes skip packaging; see [CI](../architecture/ci.md).

| Artefact | Contents |
|---|---|
| `bower-packages-linux` | `bower-collector_<version>-1_{amd64,arm64}.deb`, `bower-collector-<version>-1.{x86_64,aarch64}.rpm`, `bower-collector-offline-<version>-linux-{amd64,arm64}.tar.gz` |
| `bower-packages-windows` | `bower-collector-<version>-{x64,arm64}.msi`, `bower-collector-offline-<version>-win-{x64,arm64}.zip` |

`<version>` is `0.1.0-dev.<run number>` for CI builds (`0.1.0~dev.<n>` in deb and rpm
naming). The Linux binaries need glibc 2.34 or later: Ubuntu 22.04+, Debian 12+, RHEL,
Rocky and AlmaLinux 9+. Windows needs a version .NET 10 supports (x64 or arm64).

## What the packages install

| Item | Linux (deb, rpm) | Windows (MSI) |
|---|---|---|
| Binaries | `/opt/bower/` (`Bower.Collector`, `bower`, SQLite), `/usr/bin/bower` | `%ProgramFiles%\Bower\` |
| Service | `bower.service` ([unit](../../deploy/systemd/bower.service)), enabled and started | `Bower`, automatic start without delay, restart on failure |
| Account | `bower` system account and group, no shell, no home contents | Virtual account `NT SERVICE\Bower` |
| Settings | `/etc/bower/bower.env` (root:bower 0640) | Service `Environment` value, from MSI properties |
| Policies | `/etc/bower/policies` (config files) | `%ProgramData%\Bower\policies` |
| Trusted keys, packs | `/etc/bower/keys`, `/etc/bower/packs` (root, 0644) | `%ProgramData%\Bower\keys`, `packs` |
| Operator secrets | `/etc/bower/secrets` (root:bower 0750) | `%ProgramData%\Bower\secrets` |
| Queue and credential | `/var/lib/bower` (bower 0700) | `%ProgramData%\Bower\state` |
| Enrolment token | `/var/lib/bower/enrolment/enrolment-token` (bower 0600) | `%ProgramData%\Bower\enrolment\enrolment-token` |

Least privilege:

- Linux: the unit runs as `bower` with an empty capability bounding set,
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, private `/tmp` and devices,
  and `UMask=0077`. It can write only `/var/lib/bower` and `/var/spool/bower`. Settings,
  keys and secrets are readable by the service and writable only by root.
- Windows: `%ProgramData%\Bower` does not inherit the ProgramData ACL (which lets every
  user create files). SYSTEM and Administrators have full control; `NT SERVICE\Bower`
  can read everything and modify only `state`, `enrolment` and `spool`. No other
  principal has any access. The service SID type is unrestricted so the ACL applies.
- Put secret values (ingest token, privacy HMAC key, proxy password) in files under the
  secrets folder and point the `*_FILE` settings at them. Never put a value inline.

## Silent install with a pre-seeded token

The Windows MSI clears delayed automatic startup on install and reinstall. Earlier
packages deliberately delayed startup and exceeded the AWS lab's 120-second reboot
recovery target. The collector now starts in the normal automatic-service phase;
existing restart-on-failure actions remain in place for transient startup failures.
Installer CI checks the actual service registry setting. This removes the deliberate
delay but does not establish a boot-time guarantee: the exact signed package still
needs a Windows reboot test with destination-arrival measurements. See the
[production readiness gates](../operations/production-readiness.md).

1. An administrator creates a one-time token on the console's Enrolment page, bound to
   the environment and, ideally, the collector id. Tokens are single use and expire (24
   hours by default, at most 7 days). One token per host.
2. Copy the offline bundle to the host and put the token in `seed/enrolment-token`,
   with any trusted keys and packs (see the bundle's `README.txt`).
3. Run the installer. It installs the package, writes the settings, moves the token into
   the enrolment folder, deletes the seed copy and restarts the service.
4. The collector exchanges the token for a key-bound credential (the record lands in
   `Pending`), records only the token's SHA-256, then deletes its copy because the
   installers set `BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE=true`. A refused
   token is deleted as well; a network failure keeps it for the next attempt.
5. The installer waits for that outcome and exits 0 (enrolled, Pending), 3 (refused:
   create a new token) or 4 (not confirmed in time; the collector keeps retrying).
6. An approver approves the collector; its next heartbeat makes it `Active`.

### Linux

```bash
tar -xzf bower-collector-offline-0.1.0-linux-amd64.tar.gz
cd bower-collector-offline-0.1.0-linux-amd64
(umask 077; cat >seed/enrolment-token)   # paste the token, then Ctrl-D
cp pack-signing.pub.pem seed/pack-trusted.pem
printf 'BOWER_MANAGEMENT_ENDPOINT=https://bower-management.example.com/\nBOWER_ENVIRONMENT=production\n' >seed/settings.env
sudo ./install.sh            # or: --endpoint URL --collector-id ID --environment NAME
```

`install.sh` verifies `SHA256SUMS`, installs the deb (`dpkg -i`) or rpm (`rpm -U`) with no
network access, and accepts only `BOWER_*` settings with plain values (an inline
`BOWER_INGEST_TOKEN` is refused).

### Ansible

The example role [`deploy/ansible/roles/bower_collector`](../../deploy/ansible/roles/bower_collector)
installs the deb or rpm, writes the settings and trusted keys, seeds the token only while
the collector has not used it (it compares hashes on the host, so the private key never
leaves it), restarts the service and checks the outcome. Keep `bower_enrolment_token` in
Ansible Vault, one per host. Uninstall with `bower_state: absent` (`bower_purge: true`
also deletes the queue).

```bash
ansible-playbook -i inventory.ini deploy/ansible/playbook.yml \
  -e bower_package=dist/bower-collector_0.1.0-1_amd64.deb \
  -e bower_management_endpoint=https://bower-management.example.com/
```

### Windows

```powershell
Expand-Archive bower-collector-offline-0.1.0-win-x64.zip -DestinationPath C:\Temp
Set-Location C:\Temp\bower-collector-offline-0.1.0-win-x64
# Put the token in seed\enrolment-token and keys in seed\, then as an administrator:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-BowerCollector.ps1 `
  -ManagementEndpoint https://bower-management.example.com/ -Environment production -RequireSignature
```

`Install-BowerCollector.ps1` runs on Windows PowerShell 5.1 and PowerShell 7. It calls
`msiexec /qn` with only public, non-secret properties (after copying trusted keys and
packs into a data folder it creates with the MSI's protected ACL; it refuses an existing
`%ProgramData%\Bower` not owned by SYSTEM or Administrators), then writes the token into the
enrolment folder (it inherits the folder ACL) and deletes the source file. Drop
`-RequireSignature` only for unsigned CI builds.

The MSI alone takes these properties (remembered for repair and upgrade):

| Property | Effect |
|---|---|
| `MANAGEMENTENDPOINT` | Management URL; turns on token enrolment and token removal after use |
| `COLLECTORID` | Collector id (default: computer name) |
| `BOWERENVIRONMENT` | Environment (default: `unknown`) |
| `PACKS`, `PACKTRUSTEDKEYS`, `COMMANDTRUSTEDKEYS` | Comma-separated file paths |

```powershell
msiexec /i bower-collector-0.1.0-x64.msi /qn MANAGEMENTENDPOINT=https://bower-management.example.com/ BOWERENVIRONMENT=production
```

Other collector settings (output, sources, privacy key file, ingest token file) are not
MSI properties. Put them in `%ProgramData%\Bower\bower.env` (`KEY=VALUE`, `BOWER_*` and
`AZURE_*` only), which the service reads through `BOWER_SETTINGS_FILE`. The MSI rewrites
the service `Environment` value on repair and upgrade, so edits there do not persist;
`bower.env` is not an MSI file and is kept. It inherits the folder's protected ACL; the
collector refuses it unless SYSTEM or Administrators own it and only they can write it. See
[Upgrades, backup and recovery](../production-readiness/04-upgrade-backup-recovery.md#windows-msi-including-wec-hosts). Warnings and errors go to the Application event log (source
`Bower.Collector`).

Service recovery restarts the collector five seconds after each failure and resets
the failure count after one day. The MSI uses the WiX Util service configuration
action; the Windows install test verifies the installed recovery settings.

#### Intune, ConfigMgr and Group Policy

- **Intune (Win32 app).** Package the bundle folder with the Win32 Content Prep Tool.
  Install command: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
  .\Install-BowerCollector.ps1 -ManagementEndpoint <url> -Environment <name>
  -RequireSignature`. Uninstall: `msiexec /x {ProductCode} /qn`. Detection: the MSI
  product code, or the `Bower` service. Because tokens are single use, deliver each
  device's token separately (for example a per-device remediation script writing
  `seed\enrolment-token` before install), or use Entra-identity collectors instead of
  tokens for large fleets. Treat exit code 3 as a hard failure and 4 as retry.
- **ConfigMgr (application).** Same install and uninstall command lines and MSI product
  code detection. Run as SYSTEM, which the installer accepts.
- **Group Policy.** Software installation can assign the MSI with a transform that sets
  `MANAGEMENTENDPOINT` and `BOWERENVIRONMENT`, but it cannot deliver per-machine tokens.
  Use a computer startup script that runs `Install-BowerCollector.ps1` from a share
  readable only by the target computer accounts, or assign the MSI and place tokens out
  of band. Never put a token on a share several machines can read.

## Uninstall

| Action | Removed | Kept |
|---|---|---|
| `apt remove`, `dnf remove`, `rpm -e` | Service, binaries, management credential, any unused token, `/etc/bower/secrets`, `/etc/bower/bower.env` | The queue in `/var/lib/bower` (it may hold events the destination has not acknowledged), policies, keys |
| `apt purge` | Everything above plus `/var/lib/bower`, `/var/spool/bower`, `/etc/bower` and the `bower` account | Nothing |
| `msiexec /x` | Service, binaries, management credential, any unused token, `%ProgramData%\Bower\secrets`, `bower.env`, remembered settings | `%ProgramData%\Bower\state` (the queue), policies, keys |

Upgrades keep the credential, so an upgraded collector stays enrolled. Delete the queue
yourself once you know it is drained (rpm has no purge).

## Signing in CI

The `package-linux` and `package-windows` jobs sign only when these repository secrets
exist, and skip signing cleanly (with a notice) when they do not:

| Secret | Used for |
|---|---|
| `BOWER_PACKAGE_GPG_KEY` (armored private key), `BOWER_PACKAGE_GPG_PASSPHRASE` | nfpm signs the rpm (`rpm -K`) and the deb (debsigs `origin` signature) |
| `BOWER_WINDOWS_SIGNING_PFX` (base64 PFX), `BOWER_WINDOWS_SIGNING_PFX_PASSWORD` | `signtool` signs `Bower.Collector.exe`, `bower.exe` and the MSI (SHA-256, RFC 3161 timestamp) |

Key material is written to the runner's temporary folder only for the build step and
deleted afterwards; the PFX is imported into the CurrentUser store so its password never
reaches a command line. Publishing the public GPG key and a signed apt/dnf repository is
not part of this change.

## CI install tests

| Job | Proves |
|---|---|
| `install-linux` (ubuntu-latest) | Offline bundle and Ansible role (deb) on the runner, offline bundle (rpm) in a Rocky Linux 9 systemd container: each joins `Pending` against a loopback management API, runs as the `bower` system account with no capabilities, has the permissions above, deletes the token and never writes it to disk or the journal. `remove` leaves no secret and keeps the queue; `purge` leaves nothing. The Ansible role is idempotent. |
| `install-windows` (windows-latest, Windows Server) | `Install-BowerCollector.ps1` under Windows PowerShell 5.1 installs the MSI, the collector joins `Pending` as `NT SERVICE\Bower`, the service SID matches the MSI, no principal beyond SYSTEM, Administrators and the service can access `%ProgramData%\Bower`, the token is gone and absent from every file and msiexec log. `msiexec /x` removes the service, credential, token and secrets and keeps the queue. |

The jobs use a development-authentication management API on loopback; approval and the
`Active` transition with a real token are covered by the compose enrolment e2e.

## Known limits

- Unsigned until the signing secrets are configured (see above).
- MSI and RPM upgrades with populated queues were exercised on AWS
  ([evidence](../evidence/ws4-20261031-074918/README.md)), not in CI. MSI compares only
  `major.minor.build`, so it cannot block a downgrade between `0.1.0.N` development builds.
- arm64 packages and MSIs are built but not install-tested (no arm64 install job).
- No apt or dnf repository, no auto-update channel (out of scope for #112).
- The Windows service reports restart requests (managed privacy profile) as a normal
  stop; the service recovery actions restart it only after a failure exit.
- Azure Arc extension: evaluated, not built. See [Azure Arc evaluation](azure-arc-extension.md).

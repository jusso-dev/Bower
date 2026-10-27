# Native installer instructions

deb and rpm (`linux/`, nfpm), the MSI (`windows/`, WiX v5), the offline installers
(`offline/install.sh`, `windows/Install-BowerCollector.ps1`) and, alongside, the Ansible
role in `deploy/ansible`. Read the root and `deploy/AGENTS.md` and
[installers](../../docs/deployment/installers.md) first.

- Packages contain only the `publish` job artefacts; never rebuild the binaries here.
- Least privilege: the service runs as `bower` / `NT SERVICE\Bower`, never root or
  SYSTEM. Secrets and state stay owner-only; settings, keys and packs are writable only
  by root or Administrators. Keep `deploy/systemd/bower.service` the packaged unit.
- A token or other secret is never a package or MSI property, a command-line argument, a
  log line or installer output. The token is moved into the enrolment folder, the seed
  copy is deleted, and `BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE=true` is set.
- Uninstall (not upgrade) must delete the management credential, any unused token and the
  secrets folder, and must keep the queue (unacknowledged events) unless purging.
- Signing runs only when the repository secrets exist and skips cleanly otherwise.
  Unsigned output says so (`UNSIGNED.txt`). Never commit keys or certificates.
- `Install-BowerCollector.ps1` must run on Windows PowerShell 5.1; `powershell/build.ps1`
  analyses it for 5.1 and 7.4 and `powershell/tests` covers its helpers.
- The MSI service SID in `Bower.wxs` is derived from the service name; renaming the
  service changes it (CI checks it with `sc showsid`).
- Changes here run the `package-*` and `install-*` CI jobs; keep them passing on Ubuntu,
  Rocky Linux 9 and Windows.

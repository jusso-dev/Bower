# Azure Arc extension: evaluation

Issue #112 asks for an evaluation of shipping the collector as an Azure Arc VM extension.
Decision: **do not build a Bower Arc extension now.** Use the native packages with the
existing Arc and Azure tooling below, and revisit when there is a customer who manages
collectors only through Arc. Nothing in this change installs, publishes or configures an
Arc extension.

## Options considered

| Option | What it takes | Verdict |
|---|---|---|
| Own Arc VM extension (`Bower.Collector` publisher type) | Extension handler for Windows and Linux (install, enable, disable, update, uninstall, status files), packaging to Microsoft's extension format, and onboarding as an extension publisher with Microsoft. Publishing is not self-service: third-party extensions go through Microsoft's publishing process and appear only after it. | Not feasible in this ticket: it needs a publisher agreement and a second packaging and update channel alongside deb, rpm and MSI. |
| Custom Script Extension on Arc servers | Arc-enabled servers support `CustomScriptExtension` (Windows) and `CustomScript` (Linux). Point it at the offline bundle and run `Install-BowerCollector.ps1` or `install.sh`. | Works today. The token must reach the machine: use `protectedSettings` (encrypted to the machine, not shown in the portal or logs) and one token per machine. |
| Arc Run Command | Run the installer as a one-off command on selected machines. | Works for small fleets; same token rule. Command output is stored with the run, so the installer prints no secret (it does not). |
| Azure Policy machine configuration | Audit that `bower.service` / the `Bower` service is present and running; remediation packages can install it. | Good for compliance reporting. Remediation should ship as a signed machine configuration package; do it after the Bower packages are signed. |
| Arc managed identity instead of tokens | Arc gives every machine a system-assigned managed identity (local endpoint `http://localhost:40342`). The collector can use `BOWER_MANAGEMENT_AUTH=entra` with `BOWER_AZURE_CREDENTIAL=managed-identity`, so no token is needed at all. | The strongest option for Arc fleets, with a caveat below. |

## Arc managed identity: the caveat

Reading the Arc identity endpoint requires membership of the `himds` group (Linux) or
the `Hybrid agent extension applications` group (Windows). Adding the `bower` account or
`NT SERVICE\Bower` to it lets the collector obtain tokens for the machine's identity, so
any Azure role assigned to that machine identity becomes reachable from the collector.
Assign the machine identity only the Bower management app role (`Bower.Collector`) and,
if the collector delivers directly, `Monitoring Metrics Publisher` on its DCR, and
nothing else. On Linux the unit also needs `SupplementaryGroups=himds` and the
`IDENTITY_ENDPOINT` and `IMDS_ENDPOINT` variables in `/etc/bower/bower.env`, because
systemd services do not inherit the Arc agent's environment. This configuration is not
tested in CI (no Arc-connected machine is available to the pipeline).

## When to revisit

- A customer needs Bower to appear in the Arc extension blade, with Arc-driven updates.
- Signed packages exist (an extension would wrap them, not replace them).
- Microsoft offers a self-service publishing path for private extensions.

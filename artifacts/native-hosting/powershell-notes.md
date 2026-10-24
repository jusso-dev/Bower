# PowerShell modules: README-ready summary

Proposed README section (the README itself was not edited). Full guide:
[docs/operations/powershell.md](../../docs/operations/powershell.md).

---

## PowerShell

Bower includes PowerShell 7.4+ modules (Windows, Linux, macOS) for producers,
operators and deployers. They are thin clients over the collector `/v1/events` API,
the management API, the `bower` CLI and the checked-in deployment templates.

```powershell
Import-Module ./powershell/modules/Bower/Bower.psd1

# Send a validated security event to the local collector
New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in -EventAction sign-in `
    -EventResult failure -ApplicationName payroll -ApplicationEnvironment production |
    Send-BowerSecurityEvent

# Operate the management API (Entra token kept in memory only)
Connect-BowerManagement -Endpoint https://bower-api.example.gov.au -Audience api://<api-client-id>
Get-BowerCollector -Status Pending | Approve-BowerCollector -Reason 'Inventory verified'

# Review and assign privacy profiles
Submit-BowerPrivacyProfile -Path ./contoso.privacy.yaml -ChangeSummary 'Add custom.employee-id'
Set-BowerCollectorPrivacyProfile -CollectorId web-07 -VersionId <id> -Reason 'Rollout PRIV-77'

# Plan (default) or apply deployments
Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel -CreateIngestIdentity
```

| Module | Commands |
|---|---|
| `Bower.Events` | `New-`, `Test-`, `Send-BowerSecurityEvent` (collector, Azure Function, SigV4 Lambda Function URL) |
| `Bower.Management` | Connect/Disconnect, collectors (approve, deny, suspend, resume, revoke), audit, jobs, privacy profile versions (validate, preview, submit, approve, deny), assignment |
| `Bower.Deployment` | `New-BowerEntraApplication`, `Deploy-BowerSentinelResource`, `Deploy-BowerAzureFunction`, `Deploy-BowerAwsCloudTrailLake`, `Deploy-BowerAwsSecurity`, `Deploy-BowerGcpSecurity` |
| `Bower.Privacy` | `Test-BowerPrivacyProfile`, `New-BowerCustomDetector`, `ConvertTo-BowerSecretFieldName` |

Safety defaults: deployments plan until `-Apply` is confirmed; revoke, privacy profile
assignment and deployments prompt (`ConfirmImpact High`); management decisions need a
`-Reason`; tokens are SecureString and never persisted or logged; HTTPS only (loopback
http allowed) with TLS validation always on; bounded retries honour `Retry-After`; no
telemetry.

Development: `pwsh -NoProfile -File powershell/build.ps1` (PSScriptAnalyzer, manifest
checks, Pester).

Suggested README edits:

- Add the section above after the CLI/SDK usage section.
- Add `powershell` to the repository map in `AGENTS.md`-style lists:
  "`powershell`: PowerShell 7.4+ modules (events, management, deployment, privacy). See
  `powershell/AGENTS.md`."
- Link `docs/operations/powershell.md` from the operations documentation list.

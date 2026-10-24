# PowerShell modules

Bower ships PowerShell 7.4+ modules (Core edition; Windows, Linux and macOS) for
producers, operators and deployers. They are thin clients over existing contracts: the
collector `/v1/events` API, the management API, the `bower` CLI and the checked-in
deployment templates. They add no server-side behaviour and enforce nothing the
servers do not already enforce. Windows PowerShell 5.1 is not supported.

| Module | Purpose | Commands |
|---|---|---|
| `Bower.Events` | Build, validate and send security events | `New-BowerSecurityEvent`, `Test-BowerSecurityEvent`, `Send-BowerSecurityEvent` |
| `Bower.Management` | Operate the management API | `Connect-BowerManagement`, `Disconnect-BowerManagement`, `Get-BowerManagementConnection`, `Invoke-BowerManagementRequest`, `Get-BowerCollector`, `Approve-BowerCollector`, `Deny-BowerCollector`, `Suspend-BowerCollector`, `Resume-BowerCollector`, `Revoke-BowerCollector`, `Get-BowerAuditEvent`, `Get-BowerJob`, `Start-BowerJob`, `Invoke-BowerPrivacyProfilePreview`, `Submit-BowerPrivacyProfile`, `Get-BowerPrivacyProfileVersion`, `Approve-BowerPrivacyProfileVersion`, `Deny-BowerPrivacyProfileVersion`, `Set-BowerCollectorPrivacyProfile`, `Clear-BowerCollectorPrivacyProfile`, `Get-BowerPrivacyProfileAssignment` |
| `Bower.Deployment` | Plan-first deployment wrappers | `New-BowerEntraApplication`, `Deploy-BowerSentinelResource`, `Deploy-BowerAzureFunction`, `Deploy-BowerAwsLambda`, `Deploy-BowerAwsSecurity`, `Deploy-BowerGcpSecurity` |
| `Bower.Privacy` | Local privacy profile tooling | `Test-BowerPrivacyProfile`, `New-BowerCustomDetector`, `ConvertTo-BowerSecretFieldName` |
| `Bower.Policy` | Local telemetry policy tooling | `New-BowerPolicy`, `Test-BowerPolicy`, `Test-BowerPolicyEvent` |
| `Bower` | Meta-module: nests all five | all of the above |

Every command has comment-based help: `Get-Help Send-BowerSecurityEvent -Full`.

## Install and import

From a checkout (no gallery package yet):

```powershell
Import-Module ./powershell/modules/Bower/Bower.psd1          # everything
Import-Module ./powershell/modules/Bower.Events/Bower.Events.psd1   # or one module
```

To import by name, copy the six folders under `powershell/modules/` into a
directory on `$env:PSModulePath` (for example `~/.local/share/powershell/Modules`
on Linux/macOS or `Documents/PowerShell/Modules` on Windows), keeping them side by
side. `Bower.Deployment` locates templates relative to the repository; outside a
checkout pass `-TemplatePath`, `-ManifestDirectory` or `-WorkingDirectory`.

Optional modules and tools, loaded only by the commands that need them:

| Needed for | Requirement |
|---|---|
| Entra tokens without `-AccessToken` | `Az.Accounts` (`Connect-AzAccount` first) |
| `Send-BowerSecurityEvent -Target Lambda` | `AWS.Tools.Common` (credentials for SigV4) |
| `New-BowerEntraApplication -Apply` | `Microsoft.Graph.Applications` (`Connect-MgGraph -Scopes Application.ReadWrite.All`) |
| Bicep deployments | Azure CLI `az` with Bicep |
| CloudFormation deployments | AWS CLI v2 `aws` |
| GCP deployment | `terraform` |
| `Test-BowerPrivacyProfile` (local) | the `bower` CLI with `bower privacy validate` |
| `Test-BowerPolicy`, `Test-BowerPolicyEvent` | the `bower` CLI with `bower validate` and `bower policy test` |

## Authentication

Tokens are always `[securestring]` values (or a script block that returns one), never
plain-string parameters. Bearer tokens are passed to `Invoke-RestMethod
-Authentication Bearer -Token`, so they never appear in header dictionaries, verbose
or debug output. TLS certificate validation is never disabled; plain http is accepted
only for loopback hosts, and URLs with embedded credentials or query strings are
refused (no URL keys).

| Target | Credential |
|---|---|
| Collector `/v1/events` | Producer token: `-Token` (SecureString) or `-TokenProvider`. Required for non-loopback collectors. |
| Azure Function collector | Entra access token: `-AccessToken`, `-TokenProvider`, or `-Audience` (Az.Accounts `Get-AzAccessToken -ResourceUrl <Audience>`). |
| Lambda Function URL (`AWS_IAM`) | SigV4 with AWS credentials from `AWS.Tools.Common`: `-AwsProfileName`, `Set-AWSCredential`, or the SDK default chain. |
| Management API | `Connect-BowerManagement` with Az.Accounts (`-Audience api://<api-client-id>`), `-AccessToken`, or `-TokenProvider`. |

`SecretManagement` works well as a token provider:

```powershell
$token = Get-Secret -Name bower-ingest            # SecureString
Connect-BowerManagement -Endpoint https://bower-api.example.gov.au -TokenProvider { Get-Secret -Name bower-mgmt }
```

The management connection (endpoint, token, provider) lives in module-scoped memory
only. Nothing is written to disk. `Disconnect-BowerManagement` discards it; ending the
session does too. Az.Accounts and provider tokens are re-acquired automatically when
they are within two minutes of expiry; a static `-AccessToken` is not refreshed.

To use Az.Accounts with the management API, the Azure PowerShell client must be
allowed to request tokens for the Bower Management API (pre-authorise it on the API
app registration) or use `-TokenProvider` with your own MSAL flow. Your token's
`roles` claim decides what you can do; the API enforces every permission.

## Bower.Events

```powershell
$event = New-BowerSecurityEvent -EventCategory authentication -EventType user_sign_in `
    -EventAction sign-in -EventResult failure -EventSeverity medium `
    -ApplicationName payroll -ApplicationEnvironment production `
    -Actor @{ userId = 'u-123'; type = 'human' } -EventId 'payroll-audit-981'

$event | Test-BowerSecurityEvent -Detailed
$event | Send-BowerSecurityEvent                                   # loopback collector
Get-Content ./events.jsonl | Send-BowerSecurityEvent -Uri https://collector.example.gov.au -Token $token
$events | Send-BowerSecurityEvent -Target AzureFunction -Uri https://bower-fn.azurewebsites.net/api -Audience api://bower-function
$events | Send-BowerSecurityEvent -Target Lambda -Uri https://abc123.lambda-url.ap-southeast-2.on.aws -AwsProfileName bower
```

- Validation mirrors `schemas/envelope/security-event.schema.json` 1.0.0: required
  fields, case-sensitive property names, enumerations, lengths (code points), RFC
  3339 timestamps with offsets, at most 64 labels/attributes, and the collector's
  1 MiB request limit. Invalid events produce a non-terminating error and are not sent;
  valid events in the same pipeline still are.
- One event per request (the collector contract). `-BatchSize` (1-500, default 100)
  groups input for ShouldProcess and pacing; `-BatchDelayMilliseconds` spaces batches
  below the collector's ingest rate (`BOWER_INGEST_RATE_PER_SECOND`, default 500).
- 429 and 503 are retried up to `-MaximumRetryCount` (0-10, default 4) times, honouring
  `Retry-After` (seconds or date) and capping each delay at
  `-MaximumRetryDelaySeconds` (1-300, default 60); without `Retry-After` the delay is
  1, 2, 4, ... seconds. Persistent backpressure, 401 or a 5xx stops the command with a
  terminating error naming the first unsent event. Resend with the same event IDs; the
  collector de-duplicates them.
- Results are `Bower.EventSubmission` objects. `Accepted` is `$false` for policy
  rejections (422), invalid events (400), producer scope denials (403), event identity
  conflicts (409, with `Remediation`; see [event identity
  conflicts](event-identity-conflicts.md)) and oversized events (413).
- `-WhatIf` validates and lists the batches without sending.

## Bower.Management

```powershell
Connect-AzAccount -Tenant <tenant-id>
Connect-BowerManagement -Endpoint https://bower-api.example.gov.au -Audience api://<api-client-id>
Get-BowerManagementConnection            # who you are and your Bower roles; never the token

Get-BowerCollector -Status Pending | Approve-BowerCollector -Reason 'Inventory CHG-1042 verified'
Suspend-BowerCollector -Id web-07 -Reason 'INC-311 investigation'
Resume-BowerCollector  -Id web-07 -Reason 'INC-311 closed'
Revoke-BowerCollector  -Id web-07 -Reason 'Decommissioned CHG-2201'     # prompts (High)
Get-BowerAuditEvent -TargetType collector -TargetId web-07
Get-BowerJob; Start-BowerJob -Id collector-staleness
```

Privacy profiles (versioned review and assignment; the API enforces the two-person
rule and the approved-only assignment rule):

```powershell
Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml -Remote          # server-side validation
Invoke-BowerPrivacyProfilePreview -Path ./contoso.privacy.yaml -SamplePath ./sample-event.json
Submit-BowerPrivacyProfile -Path ./contoso.privacy.yaml -ChangeSummary 'Add custom.employee-id (PRIV-77)'

# A different person reviews:
Get-BowerPrivacyProfileVersion -Status PendingReview | Format-Table id, profileId, version, authorName
Get-BowerPrivacyProfileVersion -Id <version-id> | Select-Object -ExpandProperty content
Approve-BowerPrivacyProfileVersion -Id <version-id> -Reason 'Reviewed with privacy office'

# An administrator assigns (prompts, ConfirmImpact High):
Get-BowerCollector -Status Active | Set-BowerCollectorPrivacyProfile -VersionId <version-id> -Reason 'Fleet rollout PRIV-77'
Get-BowerCollector -Id web-07 | Select-Object id, desiredPrivacyProfile, reportedPrivacyProfileHash, privacyProfileInSync
Clear-BowerCollectorPrivacyProfile -CollectorId web-07 -Reason 'Rollback PRIV-80'
Get-BowerPrivacyProfileAssignment -CollectorId web-07
```

- Every state-changing command supports `-WhatIf`/`-Confirm`; collector and version
  decisions and assignments require `-Reason` (1-500 characters). `Start-BowerJob` has
  no reason because the trigger endpoint records none. `Submit-BowerPrivacyProfile`
  uses `-ChangeSummary` (1-500 characters).
- Per-item failures in pipelines are non-terminating errors carrying the API `error`
  message (for example `HTTP 409 (Conflict): The author of a privacy profile version
  cannot review it.`); add `-ErrorAction Stop` to stop at the first failure.
- GET requests retry 429/503; POST requests retry 429 only (a 503 may arrive after the
  server acted). `Invoke-BowerManagementRequest -Path /overview` reaches endpoints
  without a dedicated command.

## Bower.Privacy

```powershell
Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml                     # bower privacy validate
Test-BowerPrivacyProfile -Path ./contoso.privacy.yaml -HmacKeyFile ./hmac.key -SamplePath ./sample-event.json -BowerPath ./bin/bower

New-BowerCustomDetector -Id custom.employee-id -Pattern 'EMP-\d{6}' -Action mask -WholeWord `
    -Match 'EMP-123456', 'user EMP-000001 logged in' -NoMatch 'EMP-12345' -Description 'Contoso employee numbers'

'sessionKey', 'x-contoso-signature' | ConvertTo-BowerSecretFieldName -AsYaml
```

- `Test-BowerPrivacyProfile` runs `bower privacy validate FILE [--hmac-key-file KEY]
  [--sample SAMPLE]` and returns its metadata-only JSON summary as an object (every
  property passed through, plus `Source` and `Path`). A non-zero exit with a JSON
  summary is a validation result (`valid` is `$false`), not a command failure.
  `-Remote` validates on the management API instead.
- `New-BowerCustomDetector` writes a `customDetectors` YAML snippet (custom detectors,
  or custom redaction rules) and checks the structural limits: id
  `^custom\.[a-z0-9]+(-[a-z0-9]+)*$` and at most 64 characters, pattern 1-512
  characters, description at most 256, 1-16 `tests.match` and 0-16 `tests.noMatch`
  samples of 1-1024 characters, at most 32 detectors, unique ids. The restricted
  pattern syntax, complexity limit and test samples are checked only by the Privacy &
  Secret Protection Engine, so always validate the finished profile.
- `ConvertTo-BowerSecretFieldName` shows the engine's normalisation (letters and digits,
  lower-cased) and duplicates, and emits a `secretFieldNames` snippet.

## Bower.Policy

```powershell
New-BowerPolicy -Id BWR-POL-ORDERS-EXPORT -Name 'Order exports' -Version 1.0.0 -Owner 'Security Operations' `
    -EventCategory data-access -EventType sensitive_data_exported `
    -RequiredField timeGenerated, eventType, actor.userId, target.id -RecommendedField request.correlationId `
    -Path ./policies/custom/orders-export.yaml

Test-BowerPolicy -PolicyDirectory ./policies/custom                         # bower validate
Get-ChildItem ./samples/must-accept -Filter *.json |
    Test-BowerPolicyEvent -PolicyDirectory ./policies/custom -ExpectedDecision accept -ErrorAction Stop
```

- `New-BowerPolicy` writes a `bower.security/v1` `TelemetryPolicy` (every string quoted)
  or returns the YAML without `-Path`. It needs a category or type to match, keeps an
  existing file unless `-Force`, and asks before writing (`ConfirmImpact = 'Medium'`).
- `Test-BowerPolicy` runs `bower validate --policy-directory DIR` and returns each
  policy's id, version and hash. A policy the loader refuses is a result (`Valid` is
  `$false`, `Error` holds the bounded loader message), not a command failure.
- `Test-BowerPolicyEvent` runs `bower policy test` once for every piped file, with the
  same bundle options as the collector (`-PolicyDirectory`, `-PackPath` with
  `-TrustedKeyPath`, `-PrivacyProfilePath`, `-HmacKeyFile`). Each result carries the
  decision, `WouldQueue`, `PrivacyAlert`, reasons and the policy id, version, hash and
  score; never event content. With `-ExpectedDecision`, each mismatch also writes a
  non-terminating error. Samples are judged at the current time, so a `timeGenerated`
  more than five years old is quarantined, as in the collector.

## Bower.Deployment

All deployment commands plan by default and change nothing until `-Apply` is given and
confirmed (`ConfirmImpact = 'High'`, so PowerShell prompts unless `-Confirm:$false`).
`-WhatIf` runs no external command at all. Each returns a `Bower.DeploymentPlan` with
the exact command, template and parameter SHA-256 hashes, a `PlanSha256`, the tool
output and remaining manual checks. External CLIs run with argument arrays (no shell).

| Command | Plan (default) | `-Apply` |
|---|---|---|
| `New-BowerEntraApplication` | Returns the API and SPA application bodies from `deploy/entra/*.json`; calls nothing | Creates both registrations and service principals through Microsoft Graph. No secrets or certificates. |
| `Deploy-BowerSentinelResource` | `az deployment group what-if` on `deploy/bicep/main.bicep` | `az deployment group create` |
| `Deploy-BowerAzureFunction` | `az deployment group what-if` on `deploy/azure-function/main.bicep` | `az deployment group create` |
| `Deploy-BowerAwsLambda` | `aws cloudformation deploy --no-execute-changeset` on `deploy/aws/bower-aws-lambda.yaml` (CloudWatch Logs by default, or `-Destination cloudtrail-lake`) | `aws cloudformation deploy` |
| `Deploy-BowerAwsSecurity` | same, for `bower-aws-security.yaml` or `bower-aws-global-forwarder.yaml` | `aws cloudformation deploy` |
| `Deploy-BowerGcpSecurity` | `terraform init` + `terraform plan -out` in `deploy/gcp` (refuses to overwrite a plan) | `terraform apply <reviewed plan>` |

```powershell
Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel -CreateIngestIdentity
Deploy-BowerSentinelResource -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel -CreateIngestIdentity -Apply

Deploy-BowerAzureFunction -ResourceGroupName rg-bower -Location australiaeast `
    -DcrResourceId <dcr-resource-id> -LogsIngestionEndpoint https://<dce>.australiaeast-1.ingest.monitor.azure.com `
    -EntraTenantId <tenant-id> -EntraAudience api://bower-function

# CloudWatch Logs (the cmdlet default; always passed explicitly): an event log group kept on stack deletion
Deploy-BowerAwsLambda -CodeS3Bucket bower-artifacts -CodeS3Key lambda/bower-lambda.zip `
    -AllowedInvokerPrincipalArns arn:aws:iam::123456789012:role/bower-producer -EventLogRetentionDays 365
# CloudTrail Lake (accounts onboarded before 31 May 2026)
Deploy-BowerAwsLambda -StackName bower-lambda-lake -Destination cloudtrail-lake -RetentionDays 365 `
    -CodeS3Bucket bower-artifacts -CodeS3Key lambda/bower-lambda.zip -AllowedInvokerPrincipalArns arn:aws:iam::123456789012:role/bower-producer
# One ingress per stack: a separate stack for direct Invoke, attributed to one producer
Deploy-BowerAwsLambda -StackName bower-lambda-lake-invoke -Destination cloudtrail-lake -RetentionDays 365 `
    -IngressMode invoke -InvokeProducer batch -ExistingChannelArn <ChannelArn output of the first stack> `
    -CodeS3Bucket bower-artifacts -CodeS3Key lambda/bower-lambda.zip -AllowedInvokerPrincipalArns arn:aws:iam::123456789012:role/bower-batch

Deploy-BowerGcpSecurity -VarFile ./prod.tfvars -PlanFile ./bower-gcp.tfplan
Deploy-BowerGcpSecurity -PlanFile ./bower-gcp.tfplan -Apply

New-BowerEntraApplication -RedirectUri https://bower.example.gov.au
New-BowerEntraApplication -RedirectUri https://bower.example.gov.au -TenantId <tenant-id> -Apply
```

Notes:

- A CloudFormation "plan" creates a change set (and, for a new stack, a stack in
  `REVIEW_IN_PROGRESS`). Review it with `aws cloudformation describe-change-set`
  before `-Apply`. AWS defaults to `ap-southeast-2`.
- `Deploy-BowerSentinelResource` validates inputs like
  `deploy/entra/plan_ingestion.py`: exactly one of `-IngestPrincipalObjectId` or
  `-CreateIngestIdentity`, Azure region identifiers, exact HTTPS federation issuer and
  subject without wildcards. Use `plan_ingestion.py` when you need the offline
  parameter and plan files.
- `New-BowerEntraApplication -Apply` refuses a Graph connection in a different tenant
  than `-TenantId`, refuses manifests containing credentials, and leaves admin consent,
  group-to-role assignment and `Bower.Collector` assignment as manual steps (see
  [management identity and RBAC](../security/management-identity-and-rbac.md)).

## Safety defaults

| Default | Why |
|---|---|
| Deployments plan; `-Apply` plus confirmation mutates | Matches `deploy/AGENTS.md`: plan-only by default, explicit apply intent |
| `ConfirmImpact High` for revoke, privacy profile assign/clear, Entra and deployments | Prompts by default for changes that affect redaction, identity or cloud resources |
| Mandatory `-Reason` on management decisions | Written into the same-transaction management audit row |
| Tokens are SecureString, module memory only | Never persisted, returned, logged or put in header dictionaries |
| HTTPS only (loopback http allowed); TLS validation always on; no URL keys | Prevents token disclosure in transit or in URLs |
| Bounded retries honouring `Retry-After` | Respects collector backpressure without unbounded loops |
| Metadata-only errors | API `error` text or bounded CLI stderr; non-JSON bodies are not echoed |
| No telemetry | The modules call only the endpoints you configure |

## Development

```bash
pwsh -NoProfile -File powershell/build.ps1
```

The build runs PSScriptAnalyzer with `powershell/PSScriptAnalyzerSettings.psd1` (fails
on any Warning or Error), `Test-ModuleManifest` for every manifest and the Pester 5
suite in `powershell/tests/`. Tests mock `Invoke-RestMethod`, external CLIs, Microsoft
Graph and token acquisition, and never contact a real service. CI runs the same script
in the `powershell` job. See `powershell/AGENTS.md` for contributor rules.

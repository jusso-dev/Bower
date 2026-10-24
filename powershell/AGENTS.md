# PowerShell module instructions

`powershell/` holds the Bower PowerShell modules (PowerShell 7.4+, Core edition,
cross-platform): `Bower.Events`, `Bower.Management`, `Bower.Deployment`,
`Bower.Privacy` and the `Bower` meta-module that nests all four. They are thin
clients: the collector, management API, bower CLI and cloud CLIs remain the
authority for every rule. Read the root `AGENTS.md`, `deploy/AGENTS.md` and
`docs/operations/powershell.md` before editing.

## Layout and conventions

- `modules/<Name>/<Name>.psd1` + `<Name>.psm1` + `Public/` (one exported function per
  file, file name = function name) + `Private/`.
- Manifests: `ModuleVersion`, `PowerShellVersion = '7.4'`, `CompatiblePSEditions =
  @('Core')`, explicit `FunctionsToExport` (no wildcards) and empty
  `CmdletsToExport`/`VariablesToExport`/`AliasesToExport`. Add new public functions to
  the module manifest and to `modules/Bower/Bower.psd1`.
- Every public function: `[CmdletBinding()]`, approved verb, comment-based help with
  synopsis, description, every parameter and at least one example.
- State-changing commands use `SupportsShouldProcess`. Revoke, privacy profile
  assign/clear, Entra and every `Deploy-*` command use `ConfirmImpact = 'High'`.
  Management decisions take a mandatory 1-500 character `-Reason`.
- `Private/Shared/*.ps1` files are duplicated on purpose (modules install
  independently) and must stay byte-identical: `BowerHttp.ps1`/`BowerToken.ps1` in
  Events and Management, `BowerCli.ps1` in Privacy and Deployment.

## Security invariants

- Tokens and secrets are `[securestring]` parameters or a token-provider script block,
  never plain strings. Bearer tokens go to `Invoke-RestMethod -Authentication Bearer
  -Token`, never into a header dictionary. Never print, log, return or persist a token,
  the AWS secret key or a session token. The management token lives only in
  module-scoped memory.
- Never disable TLS validation (`-SkipCertificateCheck`, certificate callbacks). Plain
  http is allowed only for loopback hosts. Reject URLs with credentials or query
  strings (no URL keys).
- No `Invoke-Expression`, no string-built command lines. External CLIs run only through
  `Invoke-BowerCli` with an argument array; Microsoft Graph only through
  `Invoke-BowerGraphCommand`.
- Deployment commands plan by default (what-if, change set without execution,
  terraform plan). Mutation needs `-Apply` plus ShouldProcess confirmation.
- Retries are bounded (count and per-delay cap) and honour `Retry-After`. Management
  POSTs retry 429 only.
- Error messages surface the API `error` text or bounded CLI stderr; never echo
  non-JSON response bodies.
- No telemetry and no network calls other than the endpoint the caller configured.

## Tests

`pwsh -NoProfile -File powershell/build.ps1` runs PSScriptAnalyzer (zero Warning/Error
findings with `PSScriptAnalyzerSettings.psd1`), `Test-ModuleManifest` and Pester 5.
Tests mock `Invoke-RestMethod`, `Invoke-BowerCli`, `Invoke-BowerGraphCommand` and token
acquisition, with a fallback mock that fails any unmocked request. Tests must never
contact a real collector, management API, Entra tenant or cloud account. Cover request
shapes against the API contract, auth handling, ShouldProcess/WhatIf, retry bounds,
error propagation, validation and token non-disclosure for every new command.

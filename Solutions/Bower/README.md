# Bower Microsoft Sentinel Content Hub Solution

This directory packages Bower's Microsoft Sentinel content following the
[Azure/Azure-Sentinel `Solutions/`](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions)
V3 Content Hub layout, so security teams can deploy Bower's parsers, scheduled analytics
rules, threat-hunting queries, data connector guidance and operations workbook into an
existing Log Analytics workspace in one click.

## One-click deployment

### Option 1: Full Bower Sentinel stack (Bicep-compiled ARM template)

Deploys the `BowerSecurity_CL` table, Data Collection Endpoint (DCE), Data Collection Rule
(DCR), `BowerSecurityEvents` and `BowerSecurityEventsOfType` KQL parsers, replay-safe
scheduled analytics rules, OWASP ASVS starter rules, Sentinel pipeline health rules and the
operations workbook into an existing Log Analytics workspace. All analytics rules start
**disabled** by default (`enableRules = false`) in line with `deploy/AGENTS.md`.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjusso-dev%2FBower%2Fmain%2Fdeploy%2Fsentinel%2Fazuredeploy.json)

Source template: [`deploy/sentinel/deploy-to-azure.bicep`](../../deploy/sentinel/deploy-to-azure.bicep)
(compiled to [`deploy/sentinel/azuredeploy.json`](../../deploy/sentinel/azuredeploy.json)).

### Option 2: Content Hub V3 solution package

Installs the Content Hub V3 `contentPackages` and `contentTemplates` resources (data
connector metadata, parsers, workbook, hunting queries and analytic rule templates) using
the portal wizard defined in `Package/createUiDefinition.json`:

[![Deploy Content Hub Package](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjusso-dev%2FBower%2Fmain%2FSolutions%2FBower%2FPackage%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjusso-dev%2FBower%2Fmain%2FSolutions%2FBower%2FPackage%2FcreateUiDefinition.json)

## Content inventory

| Category | Count | Files | Source in repository |
| --- | --- | --- | --- |
| Data Connectors | 1 | `Data Connectors/Bower_LogsIngestion.json` | `deploy/bicep/main.bicep`, `deploy/bicep/ama-syslog-dcr.bicep` |
| Parsers | 2 | `Parsers/BowerSecurityEvents.yaml`, `Parsers/BowerSecurityEventsOfType.yaml` | `deploy/sentinel/analytics/bower-security-events*.kql` |
| Analytic Rules | 10 | `Analytic Rules/Bower*.yaml` | `deploy/sentinel/analytics/main.bicep`, `asvs.bicep`, `deploy/sentinel/monitoring/sentinel-health-rules.bicep` |
| Hunting Queries | 6 | `Hunting Queries/Bower*.yaml` | `deploy/sentinel/monitoring/queries/delivery-*.kql`, `docs/production-readiness/02-replay-safe-detections.md` |
| Workbooks | 1 | `Workbooks/BowerSecurityOperations.json` | `docs/production-readiness/06-monitoring-and-runbooks.md` |
| Playbooks | 0 | None | No Logic App playbooks are shipped in Bower |

### Analytic Rules

1. **Bower: Windows failed network logons from one address (replay-safe)** (`BowerWecBruteForce.yaml`) — Medium, `CredentialAccess` (`T1110`), IP entity mapping.
2. **Bower: repeated firewall denials from one address (replay-safe)** (`BowerFirewallDeny.yaml`) — Low, `Discovery` (`T1046`), IP entity mapping.
3. **Bower: events arrived later than the replay-safe rules evaluate** (`BowerEventsBeyondTolerance.yaml`) — Informational, Host entity mapping (`CollectorId`).
4. **Bower ASVS: password spraying or credential stuffing from one address** (`BowerAsvsPasswordSpray.yaml`) — Medium, `CredentialAccess` (`T1110`), IP entity mapping.
5. **Bower ASVS: privilege, role or permission change** (`BowerAsvsPrivilegeChange.yaml`) — Low, `PrivilegeEscalation`, `Persistence` (`T1098`), Account entity mapping.
6. **Bower ASVS: administrative action outside business hours** (`BowerAsvsAdminAfterHours.yaml`) — Medium, `Persistence`, `DefenseEvasion` (`T1078`), Account entity mapping, `Australia/Sydney` default time zone.
7. **Bower ASVS: mass export or bulk sensitive reads by one user** (`BowerAsvsMassExport.yaml`) — High, `Exfiltration`, `Collection` (`T1567`, `T1530`), Account entity mapping.
8. **Bower ASVS: application stopped sending security events** (`BowerAsvsLogSilence.yaml`) — Medium, `DefenseEvasion` (`T1562`), CloudApplication entity mapping.
9. **Bower collector health record missing** (`BowerCollectorHealthMissing.yaml`) — High, `DefenseEvasion` (`T1562`), Host entity mapping (`CollectorId`).
10. **Bower source silent at the destination** (`BowerSourceSilentAtDestination.yaml`) — Medium, `DefenseEvasion` (`T1562`), Host entity mapping (`CollectorId`).

### Hunting Queries

1. **Bower - Late events beyond detection tolerance (14-day hunt)** (`BowerLateEventsBeyondTolerance.yaml`)
2. **Bower - Delivery reconciliation (queued vs arrived events)** (`BowerDeliveryReconciliation.yaml`)
3. **Bower - Collector health sequence gaps (post-delivery loss detection)** (`BowerDeliverySequenceGaps.yaml`)
4. **Bower - Replay and duplicate delivery summary** (`BowerReplaySummary.yaml`)
5. **Bower - High-risk sensitive data and secret redaction findings** (`BowerSensitiveDataDetected.yaml`)
6. **Bower - Sentinel rule health and alert visibility latency** (`BowerRuleHealthAndAlertLatency.yaml`)

### Microsoft Defender XDR custom detections

None of Bower's detections query Microsoft Defender XDR tables (`DeviceEvents`,
`EmailEvents`, `IdentityLogonEvents`, `CloudAppEvents`, `EntraIdSignInEvents`). All Bower
detections query the custom `BowerSecurity_CL` table (through `BowerSecurityEvents` and
`BowerSecurityEventsOfType`) and `SecurityAlert`, so no `defender-xdr/` rules are bundled.

## Regenerating and validating the package

```bash
# Recompile the one-click ARM template from Bicep
az bicep build --file deploy/sentinel/deploy-to-azure.bicep --outfile deploy/sentinel/azuredeploy.json

# Regenerate Solutions/Bower/Package/mainTemplate.json and createUiDefinition.json
python3 tools/sentinel/build_solution.py

# Validate Bicep, ARM schemas, Content Hub V3 parity, YAML rules and KQL syntax
python3 tools/sentinel/validate_sentinel.py --require-bicep
python3 -m unittest discover -s tools/sentinel -v
```

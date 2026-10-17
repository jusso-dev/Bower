# `bower doctor` and DCR generation

Azure handles several failure modes silently: field values over 64 KB are truncated,
wrongly typed values are stored empty or as text, a stream column missing from the
DCR drops that value, and a `parse kind=regex` that does not match the whole value
leaves every extracted column empty. Bower checks for these **before** they happen.

## One schema, generated everywhere

`Bower.Dcr.SentinelSchema.Default` defines the `BowerSecurity_CL` table, the
`Custom-BowerSecurity` stream and the transformation. The Bicep template in
`deploy/bicep/main.bicep` is tested against it, and the CLI generates an equivalent
ARM template:

```bash
bower dcr generate --out bower-dcr.json --total-retention-days 365
az deployment group create -g <rg> -f bower-dcr.json -p workspaceName=<workspace>
```

The generated rule is `kind: Direct`, so it exposes its own logs ingestion endpoint;
a DCE is only needed for Private Link. Total retention defaults to 365 days (ISM).

ARM api-versions are pinned per resource provider (`Bower.Dcr.AzureApiVersions`,
`bower_dcr::*_API_VERSION`), and the generated template, `main.bicep`, `doctor`,
`dcr diff` and `evidence run` all use them:

| Resource type | api-version |
|---|---|
| `Microsoft.OperationalInsights/workspaces`, `workspaces/tables` | `2025-07-01` |
| `Microsoft.Insights/dataCollectionRules` (and `dataCollectionEndpoints`) | `2024-03-11` (latest GA) |

ARM rejects an api-version a provider does not publish, so never share one version
across providers.

## Drift

```bash
# Offline, from exported JSON
az monitor data-collection rule show -g <rg> -n bower-dcr > rule.json
bower dcr diff --rule rule.json

# Live, read-only
bower dcr diff --dcr-resource-id /subscriptions/…/dataCollectionRules/bower-dcr \
  --workspace-resource-id /subscriptions/…/workspaces/<name> --credential azure-cli
```

Findings: missing or retyped stream/table columns, wrong output stream, transformation
drift, transformation over 15,360 characters, regex `parse` full-match trap, more than
10 columns per `parse`, row filters, and total retention under 365 days. Exit code 1
on any error.

## Doctor

```bash
bower doctor \
  --pack linux-ssh-gateway-1.0.0.bowerpack --trusted-key bower-signing.pub.pem \
  --hmac-key-file /run/secrets/bower-hmac \
  --collector-url https://collector.example.org:4319 \
  --database /var/lib/bower/queue.db \
  --ingestion-endpoint https://bower-dcr-xxxx.australiaeast-1.ingest.monitor.azure.com \
  --dcr-resource-id /subscriptions/…/dataCollectionRules/bower-dcr \
  --workspace-resource-id /subscriptions/…/workspaces/<name>
```

| Check | What it catches |
|---|---|
| policies, pack | Strict policy load, pack signature and file hashes, duplicate policy ids |
| privacy | Profile errors, HMAC configured without a key |
| schema, preflight | Invalid/reserved column names; a representative redacted event exceeding API limits |
| region | Ingestion endpoint, DCR or workspace outside Australian regions; data lake only in Australia East |
| collector | Reachability, dead letters, running policy bundle hash |
| ledger | Queue tamper-evidence chain |
| dcr, table | Live drift against Bower's schema |

Every check is read-only. Exit code 1 when any check fails. `--json` for automation.
An unreachable collector, including one that does not answer within 10 seconds, is a
`FAIL collector Unreachable: …` check rather than a crash. ARM reads (`doctor`,
`dcr diff`) time out after 30 seconds and end the command with that error and exit
code 1.

## Runtime preflight

The Azure output runs the same checks on every record before upload. Records Azure
would truncate or coerce are dead-lettered as `preflight-<code>` instead of being
silently damaged (including a `dynamic` column such as `labels` that is not a JSON
object or array: the transformation reads its members, so a plain string would leave
every derived column empty), and the privacy engine truncates strings above
`maximumFieldLength` (default 32,768) at intake so the limit is rarely reached.

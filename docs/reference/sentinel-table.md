# BowerSecurity_CL columns

Every Sentinel path writes to one table, `BowerSecurity_CL`. `SentinelSchema.Default` in
`src/Bower.Dcr` defines the columns, and `deploy/bicep/main.bicep` and the Azure Monitor Agent
rule (`deploy/bicep/ama-syslog-dcr.bicep`) follow it. Tests fail when any of them differ, and a
test checks that this page lists the same columns in the same order.

The schema only ever grows: no column is renamed or retyped, and `schemaVersion` stays `1.0.0`.

| Column | Type | From the envelope |
|---|---|---|
| `TimeGenerated` | datetime | `timeGenerated` |
| `EventId` | string | `eventId` |
| `EventOriginalId` | string | `eventOriginalId` |
| `EventCategory` | string | `eventCategory` |
| `EventType` | string | `eventType` |
| `EventAction` | string | `eventAction` |
| `EventResult` | string | `eventResult` |
| `EventSeverity` | string | `eventSeverity` |
| `ApplicationName` | string | `application.name` |
| `ApplicationEnvironment` | string | `application.environment` |
| `ActorUserId` | string | `actor.userId` |
| `ActorUsername` | string | `actor.username` |
| `SourceIpAddress` | string | `source.ipAddress` |
| `CorrelationId` | string | `request.correlationId` |
| `PolicyId` | string | `security.policyId` |
| `PolicyVersion` | string | `security.policyVersion` |
| `PolicyHash` | string | `security.policyHash` |
| `ValueScore` | int | `security.valueScore` |
| `CollectorId` | string | `collector.id` |
| `PrivacyDetected` | dynamic | `privacy.detected` |
| `Labels` | dynamic | `labels` |
| `RawEnvelope` | dynamic | the whole envelope |
| `TimeObserved` | datetime | `timeObserved` |
| `EventOutcomeReason` | string | `eventOutcomeReason` |
| `Target` | dynamic | `target` |
| `Change` | dynamic | `change` |
| `Attributes` | dynamic | `attributes` |
| `Origin` | dynamic | `collector.origin`, or the agent's host on the Azure Monitor Agent path |

## Origin

`Origin` says where an event entered Bower, so a row can be traced to the system that wrote it
during an investigation. The producer cannot set it. Bower rebuilds `collector` on every event,
so a value an application puts there is replaced.

| `Origin.kind` | Set by | Fields |
|---|---|---|
| `cloudwatch-logs` | the collector, from the cloud forwarder's `X-Bower-Origin` header | `logGroup`, `logStream` (the CloudWatch Logs group and stream the line was written to, for example the instance ID) |
| `ama-syslog` | the collection rule, from the row Azure Monitor Agent made | `host` (the agent's `Computer`) |
| (empty) | | any other path: the producer is already identified by its ingest token |

- **`cloudwatch-logs`.** The collector honours the header only from producers listed in
  `BOWER_ORIGIN_PRODUCERS`, which should be the `bower-cloud` agent's tokens-file producer ID.
  A header from any other producer is ignored. The log group and stream identify the server
  that wrote the line only as far as your IAM policies allow: limit `logs:PutLogEvents` to each
  server's own stream (see the
  [CloudWatch agent quick start](../getting-started/aws-cloudwatch-agent.md)).
- **`ama-syslog`.** The host is the machine the agent ran on, not a value in the message. A
  local account can still send a forged message on that host (see the
  [trust boundary](../deployment/ama-syslog-output.md#who-can-write-to-the-table)), but the row
  names the host it came from.

Example query, rows per server in the last day:

```kusto
BowerSecurity_CL
| where TimeGenerated > ago(1d)
| summarize Rows = count() by Kind = tostring(Origin.kind),
    Server = coalesce(tostring(Origin.host), tostring(Origin.logStream))
```

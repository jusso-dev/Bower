# Replay-safe Sentinel analytics for Bower

Bower delivers at least once, so `BowerSecurity_CL` can hold more than one row for an
event, and events can arrive hours late after a destination outage. This folder ships
content that counts each event once and alerts once:

| File | Purpose |
| --- | --- |
| `bower-security-events.kql` | `BowerSecurityEvents` function: one row per `(CollectorId, EventId)` with first/last ingestion, copies and original event time |
| `rules/wec-brute-force.kql` | Windows 4625 failed network logons from one address |
| `rules/firewall-deny.kql` | Repeated firewall denials from one address |
| `rules/beyond-tolerance.kql` | Informational: events later than the rules evaluate |
| `main.bicep` | Deploys the function and the three rules, **disabled by default** |
| `validation/` | Fault-injection proxy, synthetic event driver, query-cost load generator, verifier and strict cleanup audit for the test procedure (standard-library Python, synthetic data only) |

Deploy (plan first, then apply):

```bash
az deployment group what-if -g <rg> --template-file main.bicep --parameters workspaceName=<workspace>
az deployment group create  -g <rg> --template-file main.bicep --parameters workspaceName=<workspace>
```

The function excludes `collector_health` and `collector_canary` rows; the monitoring
content in `deploy/sentinel/monitoring` reads those from the raw table. Archive replays
keep their identity only through a replay collector with the original
`BOWER_COLLECTOR_ID`; a collector with another id refuses them.

The rule files run unchanged in **Logs** with the template defaults. Do not change the
table, DCR or stream schema for this content; it reads the columns from
`deploy/bicep/main.bicep` as they are.

The full guide covers parameters and trade-offs, portal and PowerShell deployment,
converting existing rules, hunting and exports, `CollectorId` stability and the
validation procedure: [docs/production-readiness/02-replay-safe-detections.md](../../../docs/production-readiness/02-replay-safe-detections.md).

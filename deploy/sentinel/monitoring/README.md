# Bower operational monitoring

Alert rules, host checks and the fleet check for Bower collectors. The alert catalogue,
deployment steps for every environment, runbooks and the audited replay procedure are in
[Operational monitoring, alerting and runbooks](../../../docs/production-readiness/06-monitoring-and-runbooks.md).

| Path | Content |
|---|---|
| `monitoring.bicep` | Azure Monitor log alerts on `BowerSecurity_CL` (collector health, dead letters, backlog, storage, source silence, source loss indicators, DCR errors), DCR metric alerts and the DCR error-log diagnostic setting. Created disabled by default |
| `sentinel-health-rules.bicep` | Microsoft Sentinel scheduled analytics rules (collector missing, source silent) that open incidents. Disabled by default |
| `queries/*.kql` | The rule queries, with `__PLACEHOLDERS__` the templates replace. Paste into Logs or the portal after replacing them |
| `host/` | Local health checks for Linux (`bower-healthcheck.py`, systemd service and timer, `bower.service` drop-in) and Windows (`Test-BowerCollectorHealth.ps1`), with tests |
| `fleet/` | `bower-fleet-check.py`: exit code and Prometheus text from the management API fleet view, with tests |

The log rules need collectors that send `collector_health` records
(`BOWER_HEALTH_RECORD_INTERVAL_SECONDS` and the
[`collector-health` policy](../../../examples/policies/collector-health/collector-health.yaml)).

```bash
az bicep lint --file deploy/sentinel/monitoring/monitoring.bicep
az bicep lint --file deploy/sentinel/monitoring/sentinel-health-rules.bicep
python3 -B -m unittest discover -s deploy/sentinel/monitoring/host -v
python3 -B -m unittest discover -s deploy/sentinel/monitoring/fleet -v
pwsh -NoProfile -Command "Invoke-Pester -Path deploy/sentinel/monitoring/host -Output Detailed"
```

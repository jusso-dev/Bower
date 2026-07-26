# Logs Ingestion API mode

Configure HTTPS DCE endpoint, immutable DCR ID and stream name. Prefer managed
identity or Kubernetes workload identity. Assign only DCR data sender permission
for required rule scope.

```text
BOWER_OUTPUT=azure-logs-ingestion
BOWER_DCE_ENDPOINT=https://<name>.<region>.ingest.monitor.azure.com
BOWER_DCR_ID=dcr-<immutable-id>
BOWER_STREAM_NAME=Custom-BowerSecurity
```

Azure SDK handles authentication and bounded concurrent upload. Partial failures
are mapped back to local event IDs where supplied. 408, 429 and 5xx failures retry;
non-retryable poison records dead-letter. Never place credentials in arguments or
configuration committed to source.

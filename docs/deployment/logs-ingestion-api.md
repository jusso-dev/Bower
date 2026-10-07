# Logs Ingestion API mode

Configure HTTPS DCE endpoint, immutable DCR ID and stream name. Choose exactly
one credential source with `BOWER_AZURE_CREDENTIAL` (`managed-identity` default,
`workload-identity`, `environment`, `azure-cli` for development). Set
`BOWER_AZURE_CLIENT_ID` for a user-assigned managed identity. Assign only the
Monitoring Metrics Publisher (DCR data sender) role on the required rule.

```text
BOWER_OUTPUT=azure-logs-ingestion
BOWER_DCE_ENDPOINT=https://<name>.<region>.ingest.monitor.azure.com
BOWER_DCR_ID=dcr-<immutable-id>
BOWER_STREAM_NAME=Custom-BowerSecurity
```

Azure SDK handles authentication and bounded concurrent upload. The SDK reports
failed logs as serialised records; Bower maps each back to its event by the
`eventId` inside the record. A failure that cannot be attributed fails the whole
batch (retry) rather than counting anything as delivered. 408, 429 and 5xx
failures retry; 4xx, unparseable payloads and payloads whose `eventId` does not
match the queued event dead-letter individually. Acknowledgements are recorded as
`azure-logs-ingestion:accepted:<request-id>`: ingestion acceptance, not Sentinel
queryability. Never place credentials in arguments or
configuration committed to source.

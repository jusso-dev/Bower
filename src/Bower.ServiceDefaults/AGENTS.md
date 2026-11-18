# Bower.ServiceDefaults instructions

Opt-in OpenTelemetry defaults used by the collector, management API, Functions collector
and the Aspire harness.

- Inert unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Never register anything unconditionally;
  `ServiceDefaultsTests` pins this. No shipped deployment may set that variable.
- Export metadata only. Never add body, header, query string or scope capture, enrichers
  that read requests, or anything that could carry tokens, payloads or personal data.
  Spans pass `MetadataOnlyActivityProcessor` (attribute allowlist); framework request-log
  categories are filtered to Warning for the OpenTelemetry provider. Extend the allowlist
  only with metadata, and add a regression marker test for it.
- Never apply resilience or service discovery to all HTTP clients. Bower retries through the
  durable queue; the management client's enrolment token is single use.
- No `Microsoft.AspNetCore.App` reference: the Functions worker must stay a plain
  `Microsoft.NETCore.App` process. Keep it AOT and trim clean.

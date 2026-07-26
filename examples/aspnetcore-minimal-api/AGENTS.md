<!-- bower:security-telemetry:start -->
## Bower security telemetry

This repository uses Bower for structured security audit events.

When changing authentication, authorisation, administration, identity,
sensitive-data access, export, integration or security-control behaviour:

1. Determine whether change creates or modifies a security-relevant event.
2. Use strongly typed Bower SDK.
3. Emit only after authoritative action succeeds.
4. Include actor, action, target, outcome and correlation data.
5. Never include passwords, tokens, cookies, secrets or unrestricted bodies.
6. Add or update telemetry contract tests and event catalogue.
7. Run `dotnet test`, `dotnet bower analyse`, and
   `dotnet bower catalogue validate`.

Do not use ILogger as substitute for Bower security event. Do not create
free-form event types where semantic event exists. Do not duplicate events
across controller, service and persistence layers. Never weaken validation
or bypass redaction.
<!-- bower:security-telemetry:end -->

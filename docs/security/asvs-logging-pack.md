# OWASP ASVS 5.0 logging pack

The signed pack [`packs/owasp-asvs-app-logging`](../../packs/owasp-asvs-app-logging) selects
the security events that OWASP ASVS 5.0 chapter V16 asks an application to log, redacts them
with a pack privacy profile, and sends them to `BowerSecurity_CL` through the existing DCR
and stream. It adds event types and policies. It doesn't change the envelope schema, the
table, the DCR or `policies/default`.

Every ASVS and ISM ID on this page is from the [verified lists](verified-standards.md)
(ASVS 5.0.0 at tag `v5.0.0_release`, ISM September 2026).

## What the pack covers

| ASVS 5.0 | Requirement (summary) | How the pack supports it |
|---|---|---|
| V16.1.1 | Inventory of what is logged, where, how long and who can read it | This page, the [event catalogue](default-event-catalogue.md) and the signed pack manifest are the Bower part of the inventory. Destinations are fixed by policy routing |
| V16.2.1 | Each entry has when, where, who and what | Policies quarantine events missing the [investigation fields](#field-map) |
| V16.2.2 | Synchronised time; UTC or explicit offset | The envelope requires RFC 3339 `timeGenerated`; the collector quarantines events more than five minutes in the future |
| V16.2.3 | Logs go only to documented destinations | Policy `routing.destination: security-events`; outputs are operator-configured, never producer-chosen |
| V16.2.4 | Readable and correlatable by the log processor | One versioned envelope, fixed Sentinel columns, `request.correlationId` and `request.traceId` |
| V16.2.5 | Sensitive data logged per protection level; tokens only hashed or masked | [Redaction](#redaction): secrets removed by field name and value detectors, session ids and usernames HMAC'd, display names removed |
| V16.3.1 | All authentication operations, success and failure, with factors | `authentication_success`, `authentication_failure` (default policy), the `mfa_*` types and `labels.authMethod` / `labels.mfaFactor` |
| V16.3.2 | Failed authorisation; at L3 all decisions and sensitive data access | `authorisation_failure`, `sensitive_data_accessed`, `sensitive_record_changed` |
| V16.3.3 | Documented security events and bypass attempts | `input_validation_failure`, `business_logic_violation`, `anti_automation_triggered`, admin and configuration events |
| V16.3.4 | Unexpected errors and security control failures | `application_error`, `security_control_failure` |
| V16.4.1 | Encoding to prevent log injection | CR and LF replaced in every value and property name; JSON encoding end to end |
| V16.4.2 | Logs protected from access and modification | Owner-only queue files, hash-chained queue ledger, ledger-verified archive (see [ISM alignment](ism-alignment.md)) |
| V16.4.3 | Logs sent to a logically separate system | The collector runs outside the application and delivers to Sentinel |
| V16.5.1 to V16.5.4 | Generic error messages, secure failure, last-resort handler | Application-owned. The pack logs the outcome (`application_error`) and removes `stackTrace` and `exceptionMessage` |

Related requirements in other chapters:

| ASVS 5.0 | Event types |
|---|---|
| V6.1.1, V6.3.1 | `authentication_failure`, `anti_automation_triggered`; the [spraying rule](#sentinel-analytics) |
| V6.3.5 | `authentication_success` and `mfa_failure` with `source.ipAddress` and `labels.userAgent`, so suspicious attempts can be detected and the user notified |
| V6.3.7, V6.4.3, V6.4.6 | `password_reset_requested`, `password_reset_completed`, `password_changed` (`labels.initiatedBy`) |
| V6.5.6, V7.5.1 | `mfa_factor_enrolled`, `mfa_factor_removed`, `authentication_success` with action `authentication.reauthenticate` |
| V6.6.3, V6.6.4 | `mfa_failure`, `mfa_challenge` (push), `anti_automation_triggered` |
| V7.2.4 | `session_rotated` |
| V7.4.1, V7.4.2, V7.4.3, V7.4.5 | `session_terminated` (`session.logout`, `session.timeout`, `session.revoke_others`, `session.admin_terminate`, `session.revoke_all`), `account_status_changed` |
| V8.2.1, V8.2.2, V8.2.3 | `authorisation_failure` with action `authz.function`, `authz.object` or `authz.field` |
| V8.3.2 | `authorisation_failure` with action `authz.stale_grant` (local detection) |
| V2.4.1 | `anti_automation_triggered`; the [mass export rule](#sentinel-analytics) |
| V4.1.3, V15.3.4 | `source.ipAddress` must come from a trusted proxy header; see each [framework guide](../developer-integration/aspnetcore.md) |
| V13.4.5 | The collector's monitoring endpoints need the ingest token; keep `/health` and `/v1/status` off the internet |
| V14.1.2, V14.2.4 | The privacy profile is the documented logging rule for each data class |

The application still owns most of V16.5 and the controls themselves (rate limits, MFA,
session revocation). The pack makes their outcomes visible.

## Field map

Every field the brief asks for already has a home in envelope 1.0.0. Two are carried as
labels instead of new schema fields:

| Need | Envelope field | Sentinel column | Notes |
|---|---|---|---|
| UTC time | `timeGenerated` | `TimeGenerated` | RFC 3339 with `Z` or an offset |
| Event type | `eventCategory`, `eventType`, `eventAction` | `EventCategory`, `EventType`, `EventAction` | Lower snake case type, dotted action |
| User | `actor.userId`, `actor.username`, `actor.role`, `actor.type` | `ActorUserId`, `ActorUsername` | Username is an HMAC pseudonym after redaction |
| Tenant | `application.tenantId` | `RawEnvelope.application.tenantId` | |
| Source IP | `source.ipAddress` | `SourceIpAddress` | Original client address from a trusted proxy only (V15.3.4, V4.1.3) |
| User agent | `labels.userAgent` | `Labels.userAgent` | Truncated to 256 characters |
| Request or trace ID | `request.correlationId`, `request.traceId` | `CorrelationId`, `RawEnvelope.request.traceId` | W3C trace id where the app uses OpenTelemetry |
| Route | `labels.route` (template), `request.method`, `request.path` | `Labels.route`, `RawEnvelope.request` | Query strings and fragments are removed from `request.path` |
| Outcome | `eventResult`, `eventOutcomeReason`, `request.statusCode` | `EventResult`, `EventOutcomeReason` | Reason is a short code, never free text from the user |
| Severity | `eventSeverity` | `EventSeverity` | |

**Why labels for user agent and route.** The envelope is `additionalProperties: false`,
and a new `request.userAgent` member would be an additive schema change. But a new Sentinel
column would also need `SentinelSchema.Default`, the Bicep table, the DCR and every deployed
workspace to change together. Labels already exist (64 string values of 256 characters at
most) and already land in the `Labels` dynamic column, so the pack needs no schema, table or
DCR change. If a future envelope version adds `request.userAgent` and `request.route`, these
labels map one to one. The route label holds the template (`/api/invoices/{id}`), not the
concrete path, so it groups well and carries no identifiers.

## Event catalogue

`policies/default` keeps `authentication_failure`, `account_lockout`,
`role_membership_changed` and `sensitive_data_exported`. The pack never redefines those
types, and `AsvsLoggingPackTests` fails if it does. Each pack policy accepts, never
samples, and quarantines events missing required fields. Unknown types stay denied.

| Event type | Category | Actions | Result | Severity | Required (plus time, type, result, app) | Recommended | ASVS 5.0 | Policy |
|---|---|---|---|---|---|---|---|---|
| `authentication_success` | authentication | `authentication.login`, `authentication.reauthenticate`, `authentication.token_issued` | success | informational | correlation id; user id or username | source IP, `labels.authMethod`, user agent, trace id, tenant | V16.3.1, V7.5.1 | `BWR-PACK-ASVS-AUTH-SUCCESS` |
| `mfa_challenge`, `mfa_success`, `mfa_failure` | authentication | `mfa.challenge`, `mfa.verify` | success or failure | informational, low on failure | correlation id, `labels.mfaFactor`; user | source IP, reason, user agent | V16.3.1, V6.6.3, V6.6.4 | `BWR-PACK-ASVS-MFA` |
| `mfa_factor_enrolled`, `mfa_factor_removed`, `password_reset_requested`, `password_reset_completed`, `password_changed` | identity-management | `mfa.enrol`, `mfa.remove`, `mfa.revoke`, `password.reset_request`, `password.reset_complete`, `password.change` | any | informational, medium on removal | correlation id, `target.id`; user | source IP, factor, `labels.initiatedBy` | V6.3.7, V6.4.3, V6.4.6, V6.5.6 | `BWR-PACK-ASVS-FACTOR-LIFECYCLE` |
| `account_status_changed` | identity-management | `account.create`, `account.disable`, `account.enable`, `account.delete`, `account.unlock` | any | medium | correlation id, `actor.userId`, `target.id` | reason, role, source IP | V7.4.2 | `BWR-PACK-ASVS-ACCOUNT-STATUS` |
| `session_terminated`, `session_rotated` | authentication | `session.logout`, `session.timeout`, `session.admin_terminate`, `session.revoke_others`, `session.revoke_all`, `session.rotate` | any | informational | correlation id; user or target | `request.sessionId` (HMAC), `attributes.sessionsTerminated` | V7.2.4, V7.4.1, V7.4.3, V7.4.5 | `BWR-PACK-ASVS-SESSION` |
| `authorisation_failure` | authorisation | `authz.function`, `authz.object`, `authz.field`, `authz.stale_grant` | denied or failure | medium, high for stale grants | action, correlation id, `target.type`; user or source IP | route, method, role, target id, `labels.requiredPermission` | V16.3.2, V8.2.1, V8.2.2, V8.2.3, V8.3.2 | `BWR-PACK-ASVS-AUTHZ-FAILURE` |
| `sensitive_data_accessed`, `sensitive_record_changed` | data-access | `data.read`, `data.create`, `data.update`, `data.delete` | any | informational, medium on delete | action, correlation id, `actor.userId`, `target.type`, `target.id`, `labels.dataClassification` | `attributes.recordCount`, route | V16.3.2, V14.2.4 | `BWR-PACK-ASVS-SENSITIVE-DATA` |
| `admin_action`, `configuration_changed`, `permission_changed` | administrative-activity | any (`admin.grant`, `admin.impersonate`, `config.update`, ...) | any | medium or high | action, correlation id, `actor.userId`, `target.type` | role, target id, `change.field` | V16.3.3, V7.4.5 | `BWR-PACK-ASVS-ADMIN` |
| `input_validation_failure`, `business_logic_violation`, `anti_automation_triggered` | application-security, api-security | any (`validation.reject`, `ratelimit.exceeded`, `captcha.failed`, ...) | denied or failure | low | action, correlation id; source IP or user | route, method, reason, user agent | V16.3.3, V2.4.1, V6.3.1 | `BWR-PACK-ASVS-CONTROL-BYPASS` (suppressed above 20 a minute per app, type and address) |
| `application_error`, `security_control_failure` | application-security | any (`error.unhandled`, `tls.handshake`, `csrf.validate`, ...) | failure | medium | action, correlation id, `eventOutcomeReason` | route, status code, `labels.errorType`, trace id | V16.3.4, V16.5.3, V16.5.4 | `BWR-PACK-ASVS-ERRORS` |
| `database_audit` | data-access, administrative-activity, authentication | `db.logon`, `db.logoff`, `db.logon_failure`, `db.ddl`, `db.dcl`, `db.privileged`, `db.sensitive_read`, `db.sensitive_write`, `db.query_error`, `db.audit_config` | any | by action | action, `target.type`, `labels.dbEngine`; user | `target.name`, source IP, `labels.dbStatementClass` | V16.3.2, V16.3.3 | `BWR-PACK-ASVS-DB-AUDIT` |

Existing default types the pack relies on: `authentication_failure` and `account_lockout`
(V16.3.1, V6.3.1), `role_membership_changed` (V16.3.3) and `sensitive_data_exported`
(V16.3.2).

Rate-limit floods are the one family the pack suppresses. Above 20 events a minute per
application, type and source address, Bower stores one `telemetry_aggregation_summary` per
window with the counts, so the volume stays visible without a row per request. Every other
family is never sampled.

## Redaction

The pack privacy profile `owasp-asvs-app-logging` runs on top of the default Australian
detectors, before anything is written to the queue:

| Data | Action | Why |
|---|---|---|
| Passwords, tokens, API keys, cookies, `Authorization`, `headers`, `body`, `payload` | Removed by field name (built in) | Never logged (V16.2.5) |
| `otp`, `otpCode`, `totp`, `mfaCode`, `verificationCode`, `recoveryCode`, `backupCode`, `securityAnswer`, `magicLink`, `nonce`, `samlResponse`, `idToken`, `setCookie`, `rawBody`, `rawQuery`, `queryString`, `stackTrace`, `exceptionMessage`, `statement`, `queryText`, `sqlText` | Removed by field name (pack) | Authentication material, raw input, internals and SQL literals |
| JWTs, cloud keys, connection strings, card numbers, TFNs, Medicare numbers and so on in any value | Default value detectors | Catches secrets in free text |
| `actor.username`, `request.sessionId` | Keyed HMAC | Joinable for analytics, unreadable without the host key (V16.2.5 hashing) |
| `actor.displayName` | Removed | Not needed for investigation |
| `labels.userAgent` | Truncated to 256 characters | Bounded |
| CR or LF anywhere, including property names | Replaced (`custom.log-line-break`) | Log injection (V16.4.1) |
| Query strings and fragments in `request.path` and other URL fields | Removed (built in) | OAuth codes and tokens live there |
| `change.previousValue`, `change.newValue` | Removed for every type except `role_membership_changed` (built in) | A config or password change records only the field name |

The pack samples prove each row: a sample with a password, bearer token, cookie and CRLF
payload comes out with none of them, and `bower pack build` refuses to sign if any survives.
Set `BOWER_PRIVACY_HMAC_KEY_FILE` and `BOWER_PRIVACY_HMAC_KEY_ID` on the collector. Only one
privacy profile is active at a time: if you already use one, copy these rules into it.

Applications should still not send secrets. Redaction is the last line, not the plan.

## Install

```bash
bower keys generate --out-dir ./keys
bower pack build packs/owasp-asvs-app-logging --key ./keys/bower-signing.key.pem --out ./artifacts/packs
bower pack test ./artifacts/packs/owasp-asvs-app-logging-1.0.0.bowerpack --trusted-key ./keys/bower-signing.pub.pem
```

```text
BOWER_PACKS=/etc/bower/packs/owasp-asvs-app-logging-1.0.0.bowerpack
BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/bower-signing.pub.pem
BOWER_PRIVACY_HMAC_KEY_FILE=/run/secrets/bower-hmac
BOWER_PRIVACY_HMAC_KEY_ID=k2026
```

Keep `policies/default` as the policy directory: the pack adds to it. Applications send
events to `POST /v1/events` with their ingest token; see the
[framework guides](../developer-integration/aspnetcore.md).

## Sentinel ingestion

Pack events use the same stream (`Custom-BowerSecurity`), DCR transform and table
(`BowerSecurity_CL`) as every other Bower event. The fixed columns carry the common fields;
`Labels`, `Attributes`, `Target`, `Change` and `RawEnvelope` carry the rest as dynamic
values. No table, DCR or stream change is needed.

Use `BowerSecurityEvents` (deployed by
[`deploy/sentinel/analytics/main.bicep`](../../deploy/sentinel/analytics/main.bicep)) for
counts, because Bower delivers at least once. Example queries per family:

```kusto
// Authentication and MFA: methods, factors and failure reasons per app
BowerSecurityEvents
| where EventType in ("authentication_success", "authentication_failure", "mfa_success", "mfa_failure")
| summarize count() by ApplicationName, EventType, AuthMethod = tostring(Labels.authMethod),
    Factor = tostring(Labels.mfaFactor), EventOutcomeReason
```

```kusto
// Factor, password and account lifecycle for one (pseudonymised) user
BowerSecurityEvents
| where EventCategory == "identity-management"
| where EventType startswith "mfa_factor" or EventType startswith "password_" or EventType == "account_status_changed"
| project BowerEventTime, ApplicationName, EventType, EventAction, ActorUserId, TargetId = tostring(Target.id),
    InitiatedBy = tostring(Labels.initiatedBy), SourceIpAddress
```

```kusto
// Sessions revoked by administrators
BowerSecurityEvents
| where EventType == "session_terminated" and EventAction in ("session.admin_terminate", "session.revoke_all")
| project BowerEventTime, ApplicationName, ActorUserId, TargetId = tostring(Target.id),
    Sessions = toint(Attributes.sessionsTerminated)
```

```kusto
// Authorisation failures by route and kind (IDOR, function, field, stale grant)
BowerSecurityEvents
| where EventType == "authorisation_failure"
| summarize Failures = count(), Users = count_distinct(ActorUserId)
    by ApplicationName, EventAction, Route = tostring(Labels.route), TargetType = tostring(Target.type)
| sort by Failures desc
```

```kusto
// Sensitive reads, changes and exports per classification
BowerSecurityEvents
| where EventType in ("sensitive_data_accessed", "sensitive_record_changed", "sensitive_data_exported")
| summarize Events = count(), Records = sum(tolong(Attributes.recordCount))
    by ApplicationName, EventType, Classification = tostring(Labels.dataClassification)
```

```kusto
// Privileged and configuration changes
BowerSecurityEvents
| where EventCategory == "administrative-activity" or EventType == "role_membership_changed"
| project BowerEventTime, ApplicationName, EventType, EventAction, ActorUserId, ActorRole = tostring(RawEnvelope.actor.role),
    Setting = tostring(Change.field), TargetId = tostring(Target.id)
```

```kusto
// Validation, business logic and rate-limit hits, including suppressed counts.
// Summaries carry the suppressed type in Labels and the key (with the address) in Attributes.
BowerSecurityEvents
| where EventType in ("input_validation_failure", "business_logic_violation", "anti_automation_triggered")
    or (EventType == "telemetry_aggregation_summary" and tostring(Labels.suppressedEventType) == "anti_automation_triggered")
| extend Address = coalesce(SourceIpAddress, tostring(Attributes.suppressionKey["source.ipAddress"]))
| summarize Stored = countif(EventType != "telemetry_aggregation_summary"), Suppressed = sum(tolong(Attributes.suppressedCount))
    by ApplicationName, Address
```

```kusto
// Errors and security control failures
BowerSecurityEvents
| where EventType in ("application_error", "security_control_failure")
| summarize count() by ApplicationName, EventType, EventOutcomeReason, ErrorType = tostring(Labels.errorType)
```

```kusto
// Database audit by engine and action
BowerSecurityEvents
| where EventType == "database_audit"
| summarize count() by Engine = tostring(Labels.dbEngine), EventAction, EventResult, Database = tostring(Target.name)
```

Summary fields are described in the
[suppression guide](../operations/suppression-archive-and-source-silence.md#suppression).

## Sentinel analytics

[`deploy/sentinel/analytics/asvs.bicep`](../../deploy/sentinel/analytics/asvs.bicep) deploys
five scheduled rules from
[`rules/asvs`](../../deploy/sentinel/analytics/rules/asvs), **disabled by default**. Deploy
`main.bicep` first, because the rules read its functions.

| Rule | Fires when | Parameters |
|---|---|---|
| `password-spray.kql` | One address fails sign-in against at least 10 distinct accounts in 10 minutes (stuffing or spraying); reports any successes from that address | `sprayAccountThreshold` |
| `privilege-change.kql` | Any successful role, permission or `admin.grant` change | none |
| `admin-after-hours.kql` | Privileged or configuration change outside 07:00 to 19:00 on a weekday, or on a weekend, local time | `timeZone` (default `Australia/Sydney`), `businessStartHour`, `businessEndHour` |
| `mass-export.kql` | One user exports or reads at least 10,000 sensitive records, or runs 5 exports, in an hour | `exportRecordThreshold`, `exportCountThreshold` |
| `log-silence.kql` | An application with at least 20 events in the last 7 days has sent none for 60 minutes | `silenceMinutes` |

```bash
az deployment group what-if -g <rg> --template-file deploy/sentinel/analytics/asvs.bicep \
  --parameters workspaceName=<workspace> timeZone=Australia/Perth
```

Every rule uses a detection key, so a replayed or late row never raises a second alert.
The event rules re-check late rows for an hour, like the existing replay-safe rules.
`AsvsAnalyticsContentTests` checks the columns, anchors, defaults and replay safety
statically. The rules haven't been run against a live workspace yet: validate them in your
workspace before you set `enableRules=true`.

`log-silence.kql` needs no setup. The collector's own
[source expectations](../operations/suppression-archive-and-source-silence.md) are more
exact (per source, with a set allowance) and should be used where you can configure them.

The pack also ships three local Sigma detections that tag events before they leave the host:
an MFA factor removed, an action under a withdrawn grant, and a backend TLS failure.

## Database audit

[Database audit notes](../deployment/database-audit.md) cover pgaudit, MySQL, SQL Server,
MongoDB and Azure Cosmos DB, and when to use a native connector instead of `database_audit`
events.

## ISM mapping

For Australian government readers. This adds to, and doesn't repeat, the
[ISM alignment](ism-alignment.md) for the collector and delivery path. ISM September 2026.

| Control | Requirement (summary) | Pack support | Organisation responsibility |
|---|---|---|---|
| ISM-2051 | Software generates enough event logs to detect cyber security events | Event catalogue and per-framework guides; policies quarantine events missing investigation fields | Instrument every application; review coverage when features change |
| ISM-2052 | Event logs produced by software protect sensitive data | Pack privacy profile: secrets removed, usernames and session ids HMAC'd, CRLF neutralised, query strings dropped | Don't send secrets; protect the HMAC key; classify data correctly |
| ISM-1911 | Security-relevant usage, errors and crashes of software centrally logged | `application_error`, `security_control_failure` and every usage family above | Wire the last-resort error handler to emit the event |
| ISM-1978, ISM-1979 | Security-relevant events for server applications centrally logged | Same events, delivered to Sentinel | Deploy a collector for internet-facing and internal servers |
| ISM-1895 | Successful and unsuccessful single-factor authentication centrally logged | `authentication_success`, `authentication_failure` | Emit both outcomes |
| ISM-1683 | Successful and unsuccessful MFA events centrally logged | `mfa_challenge`, `mfa_success`, `mfa_failure`, factor lifecycle | Emit from the MFA provider or the app |
| ISM-1509 | Privileged access events centrally logged | `admin_action`, after-hours rule | Mark privileged roles in `actor.role` |
| ISM-1650 | Privileged account and security group management centrally logged | `role_membership_changed`, `permission_changed`, `account_status_changed`, privilege change rule | Emit from every place roles change |
| ISM-1566 | Use of unprivileged access centrally logged | `authentication_success`, sessions, sensitive data access | Decide which unprivileged actions matter |
| ISM-1910, ISM-2015 | Network API calls that change or read non-public data centrally logged | `sensitive_data_accessed`, `sensitive_record_changed`, `sensitive_data_exported` with route and method | Emit for every such API, internet-facing or not |
| ISM-1537 | Security-relevant database events centrally logged | `database_audit` policy; [database audit notes](../deployment/database-audit.md) | Enable native auditing and choose the connector |
| ISM-1536 | All queries from software to databases, and resulting errors, centrally logged | `db.query_error` events; the pack removes statement text | Native database or driver audit logs carry the statements, with their own access controls |
| ISM-0585 | Date, time, user or process, description, equipment captured | Required fields per policy; `application.instance` and `source` for equipment | Supply the fields |
| ISM-0988 | Accurate, consistent time source | UTC `timeGenerated`; future-dated events quarantined | NTP on application hosts |
| ISM-1959 | Consistent, structured format | One envelope for every family | None |
| ISM-1405, ISM-1906, ISM-1907, ISM-1228 | Central logging; timely analysis; incident identification | Delivery to Sentinel; five starter rules; log silence rule | Tune, enable and triage the rules |
| ISM-1985, ISM-1815 | Logs protected from access, modification and deletion | Collector queue and archive controls (see [ISM alignment](ism-alignment.md)) | Sentinel RBAC and immutability |

## Limits and gaps

- No ASVS ID from the pre-check failed verification. The application, not Bower, meets the
  controls the events report on (rate limits, MFA, session revocation, V16.5 error handling).
- The analytics rules are statically tested only. No live Sentinel run is claimed.
- The SDK (`Bower.Sdk`) has typed helpers only for the three default events. Other families
  are sent as envelopes over HTTP; typed helpers are a follow-up.
- User agent and route are labels, not first-class columns. Query them as `Labels.userAgent`
  and `Labels.route`.

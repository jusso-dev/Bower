#!/usr/bin/env python3
"""Regenerate samples/asvs.jsonl. Standard library only; deterministic output.

    python3 -I tools/compliance/generate_asvs_samples.py

The JSONL file is the signed pack content; this script is how it is written and is not
part of the pack (it is not listed in pack.yaml).
"""

import json
import pathlib

APP = {"name": "contoso-portal", "environment": "production", "version": "2.4.1", "tenantId": "tenant-0001"}
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15"


def event(n, category, etype, action, result, severity="informational", **extra):
    base = {
        "schemaVersion": "1.0.0",
        "eventId": f"asvs-sample-{n:03d}",
        "timeGenerated": "{{now}}",
        "eventCategory": category,
        "eventType": etype,
        "eventAction": action,
        "eventResult": result,
        "eventSeverity": severity,
        "application": APP,
        "source": {"ipAddress": "203.0.113.24"},
        "request": {"correlationId": f"req-{n:03d}", "traceId": f"4bf92f3577b34da6a3ce929d0e0e{n:04d}",
                    "method": "POST", "path": "/api/login", "statusCode": 200},
        "labels": {"userAgent": UA, "route": "/api/login"},
    }
    for key, value in extra.items():
        if value is None:
            base.pop(key, None)
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = {**base[key], **value}
        else:
            base[key] = value
    return base


def line(name, expect, ev, **kwargs):
    return {"name": name, "expect": expect, **kwargs, "event": ev}


samples = []
n = 0


def add(name, expect, *args, sample=None, **kwargs):
    global n
    n += 1
    samples.append(line(name, expect, event(n, *args, **kwargs), **(sample or {})))


# Authentication (V16.3.1)
add("password sign-in success is accepted and the username pseudonymised", "accept",
    "authentication", "authentication_success", "authentication.login", "success",
    actor={"userId": "user-1001", "username": "alice@example.com", "type": "human"},
    labels={"userAgent": UA, "route": "/api/login", "authMethod": "password+totp"},
    sample={"mustNotContain": ["alice@example.com"],
            "expectFields": {"actor.username": "present", "actor.userId": "user-1001", "labels.authMethod": "password+totp",
                             "source.ipAddress": "203.0.113.24", "request.traceId": "present", "application.tenantId": "tenant-0001",
                             "labels.userAgent": UA}})
add("sign-in success without a correlation id is quarantined", "quarantine",
    "authentication", "authentication_success", "authentication.login", "success",
    actor={"userId": "user-1001"}, request={"correlationId": None})
add("re-authentication before a sensitive change is accepted", "accept",
    "authentication", "authentication_success", "authentication.reauthenticate", "success",
    actor={"userId": "user-1001"}, labels={"authMethod": "webauthn", "route": "/account/email"})

# MFA (V16.3.1, V6.6.3, V6.6.4)
add("MFA challenge issued", "accept", "authentication", "mfa_challenge", "mfa.challenge", "success",
    actor={"userId": "user-1001"}, labels={"mfaFactor": "push", "route": "/api/mfa"})
add("MFA success", "accept", "authentication", "mfa_success", "mfa.verify", "success",
    actor={"userId": "user-1001"}, labels={"mfaFactor": "totp", "route": "/api/mfa"})
add("MFA failure never carries the submitted code", "accept", "authentication", "mfa_failure", "mfa.verify", "failure", "low",
    actor={"userId": "user-1001"}, eventOutcomeReason="InvalidCode",
    labels={"mfaFactor": "totp", "route": "/api/mfa"}, attributes={"otpCode": "493021", "attempt": 3},
    sample={"mustNotContain": ["493021"], "expectFields": {"attributes.otpCode": "absent", "attributes.attempt": 3}})
add("MFA event without the factor is quarantined", "quarantine", "authentication", "mfa_success", "mfa.verify", "success",
    actor={"userId": "user-1001"})

# Factor and password lifecycle (V6.4.3, V6.4.6, V6.5.6, V6.3.7, V7.5.1)
add("MFA factor enrolled", "accept", "identity-management", "mfa_factor_enrolled", "mfa.enrol", "success",
    actor={"userId": "user-1001"}, target={"type": "user", "id": "user-1001"}, labels={"mfaFactor": "webauthn"})
add("MFA factor removed raises the local detection", "accept", "identity-management", "mfa_factor_removed", "mfa.remove", "success", "medium",
    actor={"userId": "user-1001"}, target={"type": "user", "id": "user-1001"}, labels={"mfaFactor": "totp"},
    sample={"expectedDetections": ["bower-pack-asvs-mfa-factor-removed-001"]})
add("admin-initiated password reset never carries the reset link or token", "accept",
    "identity-management", "password_reset_requested", "password.reset_request", "success",
    actor={"userId": "admin-7", "role": "helpdesk"}, target={"type": "user", "id": "user-1001"},
    labels={"initiatedBy": "administrator"},
    attributes={"resetToken": "f3c9a1d2e8b7465fa0c1d2e3f4a5b6c7", "magicLink": "https://portal.example.com/reset?t=abc123"},
    sample={"mustNotContain": ["f3c9a1d2e8b7465fa0c1d2e3f4a5b6c7", "abc123"],
            "expectFields": {"attributes.resetToken": "absent", "attributes.magicLink": "absent"}})
add("password change never carries old or new password", "accept", "identity-management", "password_changed", "password.change", "success",
    actor={"userId": "user-1001"}, target={"type": "user", "id": "user-1001"},
    change={"field": "password", "previousValue": "Winter2026!", "newValue": "Summer2027!"},
    sample={"mustNotContain": ["Winter2026!", "Summer2027!"],
            "expectFields": {"change.field": "password", "change.previousValue": "absent", "change.newValue": "absent"}})

# Account status (V7.4.2)
add("account disabled", "accept", "identity-management", "account_status_changed", "account.disable", "success", "medium",
    actor={"userId": "admin-7", "role": "user-admin"}, target={"type": "user", "id": "user-2002"},
    eventOutcomeReason="EmployeeOffboarded")

# Sessions (V7.2.4, V7.4.x)
add("logout keeps only a pseudonymised session id", "accept", "authentication", "session_terminated", "session.logout", "success",
    actor={"userId": "user-1001"}, request={"sessionId": "s%3Aq9XkLm2PzR7vT1yB4nC8dF0gH"},
    sample={"mustNotContain": ["q9XkLm2PzR7vT1yB4nC8dF0gH"], "expectFields": {"request.sessionId": "present"}})
add("admin terminates all sessions for a user", "accept", "authentication", "session_terminated", "session.admin_terminate", "success", "medium",
    actor={"userId": "admin-7", "role": "user-admin"}, target={"type": "user", "id": "user-2002"},
    attributes={"sessionsTerminated": 4},
    sample={"expectFields": {"attributes.sessionsTerminated": 4}})

# Authorisation (V16.3.2, V8.2.x, V8.3.2)
add("object-level authorisation failure (IDOR)", "accept", "authorisation", "authorisation_failure", "authz.object", "denied", "medium",
    actor={"userId": "user-1001", "role": "customer"}, target={"type": "invoice", "id": "inv-88412"},
    labels={"route": "/api/invoices/{id}", "requiredPermission": "invoice.read"},
    request={"method": "GET", "path": "/api/invoices/inv-88412", "statusCode": 403})
add("stale grant raises the local detection", "accept", "authorisation", "authorisation_failure", "authz.stale_grant", "denied", "high",
    actor={"userId": "user-3003"}, target={"type": "function", "id": "reports.export"},
    sample={"expectedDetections": ["bower-pack-asvs-authz-stale-grant-001"]})
add("authorisation failure without a target type is quarantined", "quarantine", "authorisation", "authorisation_failure", "authz.function", "denied",
    actor={"userId": "user-1001"})
add("authorisation success is not a failure event and stays denied", "reject", "authorisation", "authorisation_failure", "authz.function", "success",
    actor={"userId": "user-1001"}, target={"type": "function"})

# Sensitive data (V16.3.2 L3, V14.2.4)
add("sensitive record read without the record content", "accept", "data-access", "sensitive_data_accessed", "data.read", "success",
    actor={"userId": "user-1001"}, target={"type": "patient", "id": "pt-5531"},
    labels={"dataClassification": "OFFICIAL:Sensitive", "route": "/api/patients/{id}"},
    attributes={"recordCount": 1, "responseBody": "{\"name\":\"Jane Citizen\",\"medicare\":\"2123 45670 1\"}"},
    sample={"mustNotContain": ["Jane Citizen", "2123 45670 1"], "expectFields": {"attributes.responseBody": "absent", "attributes.recordCount": 1}})
add("sensitive record deleted", "accept", "data-access", "sensitive_record_changed", "data.delete", "success", "medium",
    actor={"userId": "admin-7"}, target={"type": "patient", "id": "pt-5531"}, labels={"dataClassification": "OFFICIAL:Sensitive"})
add("sensitive read without a classification is quarantined", "quarantine", "data-access", "sensitive_data_accessed", "data.read", "success",
    actor={"userId": "user-1001"}, target={"type": "patient", "id": "pt-5531"})

# Admin and configuration (V16.3.3)
add("security configuration change records the setting, not its values", "accept",
    "administrative-activity", "configuration_changed", "config.update", "success", "medium",
    actor={"userId": "admin-7", "role": "tenant-admin"}, target={"type": "setting", "id": "auth.mfa.required"},
    change={"field": "auth.mfa.required", "previousValue": "true", "newValue": "false"},
    sample={"expectFields": {"change.field": "auth.mfa.required", "change.previousValue": "absent", "change.newValue": "absent"}})
add("privileged admin action", "accept", "administrative-activity", "admin_action", "admin.impersonate", "success", "high",
    actor={"userId": "admin-7", "role": "support-admin"}, target={"type": "user", "id": "user-2002"})

# Control bypass (V16.3.3, V2.4.1)
add("rate-limit hit is accepted (suppressed per address after 20 a minute)", "accept",
    "api-security", "anti_automation_triggered", "ratelimit.exceeded", "denied", "low",
    eventOutcomeReason="LoginRateLimit", request={"statusCode": 429})
add("input validation failure never carries the submitted value", "accept",
    "application-security", "input_validation_failure", "validation.reject", "failure", "low",
    eventOutcomeReason="UnexpectedField", attributes={"field": "role", "rawBody": "{\"role\":\"admin\",\"password\":\"hunter2\"}"},
    sample={"mustNotContain": ["hunter2"], "expectFields": {"attributes.rawBody": "absent", "attributes.field": "role"}})

# Errors (V16.3.4, V16.5.x)
add("backend TLS failure raises the local detection", "accept", "application-security", "security_control_failure", "tls.handshake", "failure", "medium",
    eventOutcomeReason="BackendTlsHandshakeFailed", labels={"errorType": "AuthenticationException", "route": "/api/payments"},
    sample={"expectedDetections": ["bower-pack-asvs-backend-tls-failure-001"]})
add("unhandled error never carries the stack trace or exception message", "accept",
    "application-security", "application_error", "error.unhandled", "failure", "medium",
    eventOutcomeReason="UnhandledException", request={"statusCode": 500},
    labels={"errorType": "NullReferenceException"},
    attributes={"stackTrace": "at Contoso.Billing.Charge(String apiKey=sk_live_51Hx)", "exceptionMessage": "Login failed for user sa password=P@ss"},
    sample={"mustNotContain": ["sk_live_51Hx", "P@ss"], "expectFields": {"attributes.stackTrace": "absent", "attributes.exceptionMessage": "absent"}})
add("error without a reason is quarantined", "quarantine", "application-security", "application_error", "error.unhandled", "failure")

# Database audit (ISM-1537)
add("database privileged action from pgaudit, statement removed", "accept",
    "administrative-activity", "database_audit", "db.dcl", "success", "high",
    actor={"username": "dbadmin", "type": "human"}, target={"type": "database", "name": "billing"},
    labels={"dbEngine": "postgresql", "dbStatementClass": "ROLE"},
    attributes={"statement": "ALTER ROLE app_rw WITH PASSWORD 'Tr0ub4dor&3'"},
    request=None,
    sample={"mustNotContain": ["Tr0ub4dor&3", "dbadmin"], "expectFields": {"attributes.statement": "absent", "labels.dbStatementClass": "ROLE"}})
add("database audit without an engine is quarantined", "quarantine", "data-access", "database_audit", "db.logon", "success",
    actor={"username": "app"}, target={"type": "database"}, request=None)

# Injection and secret handling across every family (V16.4.1, V16.2.5)
add("CRLF in a username cannot forge a log line", "accept", "authentication", "mfa_failure", "mfa.verify", "failure",
    actor={"userId": "user-1001", "username": "bob\r\n2026-11-09T00:00:00Z INFO admin login ok"},
    labels={"mfaFactor": "sms"},
    sample={"mustNotContain": ["\r", "\n", "INFO admin login ok"]})
add("CRLF in a reason and a label is replaced", "accept", "application-security", "input_validation_failure", "validation.reject", "failure",
    eventOutcomeReason="Bad header\r\nX-Injected: 1", labels={"route": "/api/x", "userAgent": "curl/8\r\nSet-Cookie: a=b"},
    sample={"mustNotContain": ["\r", "\n"], "expectFields": {"eventOutcomeReason": "Bad header***REDACTED***X-Injected: 1"}})
add("authorization header, cookies, bearer token and password never leave the host", "accept",
    "authorisation", "authorisation_failure", "authz.function", "denied",
    actor={"userId": "user-1001"}, target={"type": "function", "id": "admin.users"},
    attributes={"headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"},
                "cookie": "session=abc; csrftoken=xyz", "password": "hunter2", "authorization": "Basic YWxpY2U6aHVudGVyMg=="},
    sample={"mustNotContain": ["eyJhbGciOiJIUzI1NiJ9", "hunter2", "YWxpY2U6aHVudGVyMg", "csrftoken=xyz"],
            "expectFields": {"attributes.headers": "absent", "attributes.cookie": "absent", "attributes.password": "absent", "attributes.authorization": "absent"}})
add("query strings are dropped from the request path", "accept", "authentication", "authentication_success", "authentication.login", "success",
    actor={"userId": "user-1001"}, request={"path": "/oauth/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz"},
    sample={"mustNotContain": ["SplxlOBeZQQYbYS6WxSbIA"], "expectFields": {"request.path": "/oauth/callback"}})

# Default deny
add("an event type the pack does not list stays denied", "reject", "application-security", "page_viewed", "page.view", "success",
    actor={"userId": "user-1001"})

out = pathlib.Path(__file__).resolve().parents[2] / "packs" / "owasp-asvs-app-logging" / "samples" / "asvs.jsonl"
out.write_text("".join(json.dumps(s, ensure_ascii=False, separators=(",", ":")) + "\n" for s in samples), encoding="utf-8")
print(f"wrote {len(samples)} samples to {out.name}")

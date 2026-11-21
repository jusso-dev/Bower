using System.Text.Json;
using Bower.Contracts;

namespace Bower.Sdk;

internal sealed partial class BufferedBowerClient
{
    public ValueTask<EmitResult> AuthenticationSucceededAsync(
        AuthenticationSucceededEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        RequireAtLeastOne(securityEvent.UserId, securityEvent.Username, nameof(securityEvent), "UserId or Username is required.");
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        string action = securityEvent.Kind switch
        {
            AuthenticationSuccessKind.Login => "authentication.login",
            AuthenticationSuccessKind.Reauthenticate => "authentication.reauthenticate",
            AuthenticationSuccessKind.TokenIssued => "authentication.token_issued",
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        Dictionary<string, string>? labels = BuildLabels(
            ("authMethod", securityEvent.AuthMethod),
            ("userAgent", securityEvent.UserAgent));

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.Authentication,
            "authentication_success",
            action,
            EventResult.Success,
            null,
            new ActorContext { UserId = securityEvent.UserId, Username = securityEvent.Username, Type = ActorType.Human },
            null,
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Request = new RequestContext { CorrelationId = securityEvent.CorrelationId, TraceId = securityEvent.TraceId },
            Labels = labels
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> MfaEventAsync(
        MfaSecurityEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        RequireAtLeastOne(securityEvent.UserId, securityEvent.Username, nameof(securityEvent), "UserId or Username is required.");
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Factor);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        (string eventType, string action, EventResult result) = securityEvent.Outcome switch
        {
            MfaOutcome.Challenge => ("mfa_challenge", "mfa.challenge", EventResult.Success),
            MfaOutcome.Success => ("mfa_success", "mfa.verify", EventResult.Success),
            MfaOutcome.Failure => ("mfa_failure", "mfa.verify", EventResult.Failure),
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        Dictionary<string, string>? labels = BuildLabels(
            ("mfaFactor", securityEvent.Factor),
            ("userAgent", securityEvent.UserAgent));

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.Authentication,
            eventType,
            action,
            result,
            securityEvent.Reason,
            new ActorContext { UserId = securityEvent.UserId, Username = securityEvent.Username, Type = ActorType.Human },
            null,
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Request = new RequestContext { CorrelationId = securityEvent.CorrelationId, TraceId = securityEvent.TraceId },
            Labels = labels
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> AuthenticationFactorLifecycleAsync(
        AuthenticationFactorLifecycleEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        RequireAtLeastOne(securityEvent.ActorUserId, securityEvent.ActorUsername, nameof(securityEvent), "ActorUserId or ActorUsername is required.");
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        (string eventType, string action) = securityEvent.Action switch
        {
            FactorLifecycleAction.MfaEnrolled => ("mfa_factor_enrolled", "mfa.enrol"),
            FactorLifecycleAction.MfaRemoved => ("mfa_factor_removed", "mfa.remove"),
            FactorLifecycleAction.MfaRevoked => ("mfa_factor_removed", "mfa.revoke"),
            FactorLifecycleAction.PasswordResetRequested => ("password_reset_requested", "password.reset_request"),
            FactorLifecycleAction.PasswordResetCompleted => ("password_reset_completed", "password.reset_complete"),
            FactorLifecycleAction.PasswordChanged => ("password_changed", "password.change"),
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        Dictionary<string, string>? labels = BuildLabels(
            ("mfaFactor", securityEvent.Factor),
            ("initiatedBy", securityEvent.InitiatedBy),
            ("userAgent", securityEvent.UserAgent));

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.IdentityManagement,
            eventType,
            action,
            securityEvent.Result,
            securityEvent.Reason,
            new ActorContext { UserId = securityEvent.ActorUserId, Username = securityEvent.ActorUsername, Type = ActorType.Human },
            new TargetContext { Type = "user", Id = securityEvent.TargetUserId },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Labels = labels
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> AccountStatusChangedAsync(
        AccountStatusChangedEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.ActorUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        string action = securityEvent.Action switch
        {
            AccountStatusAction.Create => "account.create",
            AccountStatusAction.Disable => "account.disable",
            AccountStatusAction.Enable => "account.enable",
            AccountStatusAction.Delete => "account.delete",
            AccountStatusAction.Unlock => "account.unlock",
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.IdentityManagement,
            "account_status_changed",
            action,
            securityEvent.Result,
            securityEvent.Reason,
            new ActorContext { UserId = securityEvent.ActorUserId, Role = securityEvent.ActorRole, Type = ActorType.Human },
            new TargetContext { Type = "user", Id = securityEvent.TargetUserId },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null);
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> SessionLifecycleAsync(
        SessionLifecycleEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);
        if (string.IsNullOrWhiteSpace(securityEvent.ActorUserId)
            && string.IsNullOrWhiteSpace(securityEvent.ActorUsername)
            && string.IsNullOrWhiteSpace(securityEvent.TargetId))
        {
            throw new ArgumentException("At least one of ActorUserId, ActorUsername, or TargetId is required.", nameof(securityEvent));
        }

        if (securityEvent.SessionsTerminated is < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(securityEvent), "SessionsTerminated cannot be negative.");
        }

        (string eventType, string action) = securityEvent.Action switch
        {
            SessionLifecycleAction.Logout => ("session_terminated", "session.logout"),
            SessionLifecycleAction.Timeout => ("session_terminated", "session.timeout"),
            SessionLifecycleAction.AdminTerminate => ("session_terminated", "session.admin_terminate"),
            SessionLifecycleAction.RevokeOthers => ("session_terminated", "session.revoke_others"),
            SessionLifecycleAction.RevokeAll => ("session_terminated", "session.revoke_all"),
            SessionLifecycleAction.Rotate => ("session_rotated", "session.rotate"),
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        Dictionary<string, JsonElement>? attributes = securityEvent.SessionsTerminated is { } count
            ? new Dictionary<string, JsonElement>
            {
                ["sessionsTerminated"] = JsonSerializer.SerializeToElement(count, SdkJsonContext.Default.Int64)
            }
            : null;

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.Authentication,
            eventType,
            action,
            securityEvent.Result,
            null,
            securityEvent.ActorUserId is null && securityEvent.ActorUsername is null
                ? null
                : new ActorContext { UserId = securityEvent.ActorUserId, Username = securityEvent.ActorUsername, Type = ActorType.Human },
            securityEvent.TargetId is null ? null : new TargetContext { Type = "session", Id = securityEvent.TargetId },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Request = new RequestContext
            {
                CorrelationId = securityEvent.CorrelationId,
                SessionId = securityEvent.SessionId
            },
            Labels = BuildLabels(("userAgent", securityEvent.UserAgent)),
            Attributes = attributes
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> AuthorisationFailedAsync(
        AuthorisationFailedEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetType);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);
        if (securityEvent.Result is not (EventResult.Denied or EventResult.Failure))
        {
            throw new ArgumentOutOfRangeException(nameof(securityEvent), "AuthorisationFailedEvent Result must be Denied or Failure.");
        }

        if (string.IsNullOrWhiteSpace(securityEvent.ActorUserId)
            && string.IsNullOrWhiteSpace(securityEvent.ActorUsername)
            && securityEvent.SourceIpAddress is null)
        {
            throw new ArgumentException("At least one of ActorUserId, ActorUsername, or SourceIpAddress is required.", nameof(securityEvent));
        }

        string action = securityEvent.Kind switch
        {
            AuthorisationFailureKind.FunctionLevel => "authz.function",
            AuthorisationFailureKind.ObjectLevel => "authz.object",
            AuthorisationFailureKind.FieldLevel => "authz.field",
            AuthorisationFailureKind.StaleGrant => "authz.stale_grant",
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        SecurityEventEnvelope envelope = CreateEnvelope(
            "authorisation",
            "authorisation_failure",
            action,
            securityEvent.Result,
            securityEvent.Reason,
            securityEvent.ActorUserId is null && securityEvent.ActorUsername is null
                ? null
                : new ActorContext
                {
                    UserId = securityEvent.ActorUserId,
                    Username = securityEvent.ActorUsername,
                    Role = securityEvent.ActorRole,
                    Type = ActorType.Human
                },
            new TargetContext { Type = securityEvent.TargetType, Id = securityEvent.TargetId },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Request = new RequestContext
            {
                CorrelationId = securityEvent.CorrelationId,
                Method = securityEvent.HttpMethod
            },
            Labels = BuildLabels(
                ("route", securityEvent.Route),
                ("requiredPermission", securityEvent.RequiredPermission))
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> SensitiveDataAccessedAsync(
        SensitiveDataAccessEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.ActorUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetType);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.DataClassification);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);
        if (securityEvent.RecordCount is < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(securityEvent), "RecordCount cannot be negative.");
        }

        (string eventType, string action) = securityEvent.Operation switch
        {
            SensitiveDataOperation.Read => ("sensitive_data_accessed", "data.read"),
            SensitiveDataOperation.Create => ("sensitive_record_changed", "data.create"),
            SensitiveDataOperation.Update => ("sensitive_record_changed", "data.update"),
            SensitiveDataOperation.Delete => ("sensitive_record_changed", "data.delete"),
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        Dictionary<string, JsonElement>? attributes = securityEvent.RecordCount is { } count
            ? new Dictionary<string, JsonElement>
            {
                ["recordCount"] = JsonSerializer.SerializeToElement(count, SdkJsonContext.Default.Int64)
            }
            : null;

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.DataAccess,
            eventType,
            action,
            securityEvent.Result,
            null,
            new ActorContext { UserId = securityEvent.ActorUserId, Type = ActorType.Human },
            new TargetContext { Type = securityEvent.TargetType, Id = securityEvent.TargetId },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Labels = BuildLabels(
                ("dataClassification", securityEvent.DataClassification),
                ("route", securityEvent.Route)),
            Attributes = attributes
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> AdministrativeActionAsync(
        AdministrativeSecurityEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.ActorUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Action);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetType);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        string eventType = securityEvent.Kind switch
        {
            AdministrativeEventKind.AdminAction => "admin_action",
            AdministrativeEventKind.ConfigurationChanged => "configuration_changed",
            AdministrativeEventKind.PermissionChanged => "permission_changed",
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.AdministrativeActivity,
            eventType,
            securityEvent.Action,
            securityEvent.Result,
            securityEvent.Reason,
            new ActorContext { UserId = securityEvent.ActorUserId, Role = securityEvent.ActorRole, Type = ActorType.Human },
            new TargetContext { Type = securityEvent.TargetType, Id = securityEvent.TargetId },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Change = string.IsNullOrWhiteSpace(securityEvent.ChangedField)
                ? null
                : new ChangeContext { Field = securityEvent.ChangedField },
            Labels = BuildLabels(("userAgent", securityEvent.UserAgent))
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> ControlBypassAttemptedAsync(
        ControlBypassEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Action);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);
        if (securityEvent.Result is not (EventResult.Denied or EventResult.Failure))
        {
            throw new ArgumentOutOfRangeException(nameof(securityEvent), "ControlBypassEvent Result must be Denied or Failure.");
        }

        if (securityEvent.SourceIpAddress is null
            && string.IsNullOrWhiteSpace(securityEvent.ActorUserId)
            && string.IsNullOrWhiteSpace(securityEvent.ActorUsername))
        {
            throw new ArgumentException("At least one of SourceIpAddress, ActorUserId, or ActorUsername is required.", nameof(securityEvent));
        }

        string eventType = securityEvent.Kind switch
        {
            ControlBypassKind.InputValidationFailure => "input_validation_failure",
            ControlBypassKind.BusinessLogicViolation => "business_logic_violation",
            ControlBypassKind.AntiAutomationTriggered => "anti_automation_triggered",
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        SecurityEventEnvelope envelope = CreateEnvelope(
            "application-security",
            eventType,
            securityEvent.Action,
            securityEvent.Result,
            securityEvent.Reason,
            securityEvent.ActorUserId is null && securityEvent.ActorUsername is null
                ? null
                : new ActorContext { UserId = securityEvent.ActorUserId, Username = securityEvent.ActorUsername, Type = ActorType.Human },
            null,
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            null) with
        {
            Request = new RequestContext
            {
                CorrelationId = securityEvent.CorrelationId,
                Method = securityEvent.HttpMethod
            },
            Labels = BuildLabels(
                ("route", securityEvent.Route),
                ("userAgent", securityEvent.UserAgent))
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> SecurityErrorAsync(
        SecurityErrorEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Action);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Reason);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        string eventType = securityEvent.Kind switch
        {
            SecurityErrorKind.ApplicationError => "application_error",
            SecurityErrorKind.SecurityControlFailure => "security_control_failure",
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        SecurityEventEnvelope envelope = CreateEnvelope(
            "application-security",
            eventType,
            securityEvent.Action,
            EventResult.Failure,
            securityEvent.Reason,
            null,
            null,
            null,
            securityEvent.CorrelationId,
            null) with
        {
            EventSeverity = securityEvent.Severity,
            Request = new RequestContext
            {
                CorrelationId = securityEvent.CorrelationId,
                TraceId = securityEvent.TraceId,
                StatusCode = securityEvent.StatusCode
            },
            Labels = BuildLabels(
                ("route", securityEvent.Route),
                ("errorType", securityEvent.ErrorType))
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> DatabaseAuditAsync(
        DatabaseAuditEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.DbEngine);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetType);
        RequireAtLeastOne(securityEvent.ActorUsername, securityEvent.ActorUserId, nameof(securityEvent), "ActorUsername or ActorUserId is required.");

        (string category, string action) = securityEvent.Action switch
        {
            DatabaseAuditAction.Logon => (SecurityEventCategories.Authentication, "db.logon"),
            DatabaseAuditAction.Logoff => (SecurityEventCategories.Authentication, "db.logoff"),
            DatabaseAuditAction.LogonFailure => (SecurityEventCategories.Authentication, "db.logon_failure"),
            DatabaseAuditAction.Ddl => (SecurityEventCategories.AdministrativeActivity, "db.ddl"),
            DatabaseAuditAction.Dcl => (SecurityEventCategories.AdministrativeActivity, "db.dcl"),
            DatabaseAuditAction.Privileged => (SecurityEventCategories.AdministrativeActivity, "db.privileged"),
            DatabaseAuditAction.AuditConfig => (SecurityEventCategories.AdministrativeActivity, "db.audit_config"),
            DatabaseAuditAction.SensitiveRead => (SecurityEventCategories.DataAccess, "db.sensitive_read"),
            DatabaseAuditAction.SensitiveWrite => (SecurityEventCategories.DataAccess, "db.sensitive_write"),
            DatabaseAuditAction.QueryError => (SecurityEventCategories.DataAccess, "db.query_error"),
            _ => throw new ArgumentOutOfRangeException(nameof(securityEvent))
        };

        SecurityEventEnvelope envelope = CreateEnvelope(
            category,
            "database_audit",
            action,
            securityEvent.Result,
            securityEvent.Reason,
            new ActorContext
            {
                Username = securityEvent.ActorUsername,
                UserId = securityEvent.ActorUserId,
                Type = ActorType.Human
            },
            new TargetContext { Type = securityEvent.TargetType, Name = securityEvent.TargetName },
            securityEvent.SourceIpAddress is null ? null : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId ?? Guid.CreateVersion7().ToString(),
            null) with
        {
            Labels = BuildLabels(
                ("dbEngine", securityEvent.DbEngine),
                ("dbStatementClass", securityEvent.StatementClass))
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    private static void RequireAtLeastOne(string? first, string? second, string paramName, string message)
    {
        if (string.IsNullOrWhiteSpace(first) && string.IsNullOrWhiteSpace(second))
        {
            throw new ArgumentException(message, paramName);
        }
    }

    private static Dictionary<string, string>? BuildLabels(params (string Key, string? Value)[] pairs)
    {
        Dictionary<string, string>? labels = null;
        foreach ((string key, string? value) in pairs)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            labels ??= new Dictionary<string, string>(StringComparer.Ordinal);
            labels[key] = value;
        }

        return labels;
    }
}

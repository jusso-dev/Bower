using System.Net;
using Bower.Contracts;

namespace Bower.Sdk;

public enum AuthenticationSuccessKind
{
    Login,
    Reauthenticate,
    TokenIssued
}

public sealed record AuthenticationSucceededEvent
{
    public string? UserId { get; init; }
    public string? Username { get; init; }
    public AuthenticationSuccessKind Kind { get; init; } = AuthenticationSuccessKind.Login;
    public string? AuthMethod { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? TraceId { get; init; }
    public required string CorrelationId { get; init; }
}

public enum MfaOutcome
{
    Challenge,
    Success,
    Failure
}

public sealed record MfaSecurityEvent
{
    public string? UserId { get; init; }
    public string? Username { get; init; }
    public required MfaOutcome Outcome { get; init; }
    public required string Factor { get; init; }
    public string? Reason { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? TraceId { get; init; }
    public required string CorrelationId { get; init; }
}

public enum FactorLifecycleAction
{
    MfaEnrolled,
    MfaRemoved,
    MfaRevoked,
    PasswordResetRequested,
    PasswordResetCompleted,
    PasswordChanged
}

public sealed record AuthenticationFactorLifecycleEvent
{
    public string? ActorUserId { get; init; }
    public string? ActorUsername { get; init; }
    public required string TargetUserId { get; init; }
    public required FactorLifecycleAction Action { get; init; }
    public EventResult Result { get; init; } = EventResult.Success;
    public string? Factor { get; init; }
    public string? InitiatedBy { get; init; }
    public string? Reason { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? UserAgent { get; init; }
    public required string CorrelationId { get; init; }
}

public enum AccountStatusAction
{
    Create,
    Disable,
    Enable,
    Delete,
    Unlock
}

public sealed record AccountStatusChangedEvent
{
    public required string ActorUserId { get; init; }
    public string? ActorRole { get; init; }
    public required string TargetUserId { get; init; }
    public required AccountStatusAction Action { get; init; }
    public EventResult Result { get; init; } = EventResult.Success;
    public string? Reason { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public required string CorrelationId { get; init; }
}

public enum SessionLifecycleAction
{
    Logout,
    Timeout,
    AdminTerminate,
    RevokeOthers,
    RevokeAll,
    Rotate
}

public sealed record SessionLifecycleEvent
{
    public string? ActorUserId { get; init; }
    public string? ActorUsername { get; init; }
    public string? TargetId { get; init; }
    public required SessionLifecycleAction Action { get; init; }
    public EventResult Result { get; init; } = EventResult.Success;
    public string? SessionId { get; init; }
    public long? SessionsTerminated { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? UserAgent { get; init; }
    public required string CorrelationId { get; init; }
}

public enum AuthorisationFailureKind
{
    FunctionLevel,
    ObjectLevel,
    FieldLevel,
    StaleGrant
}

public sealed record AuthorisationFailedEvent
{
    public string? ActorUserId { get; init; }
    public string? ActorUsername { get; init; }
    public string? ActorRole { get; init; }
    public required AuthorisationFailureKind Kind { get; init; }
    public required string TargetType { get; init; }
    public string? TargetId { get; init; }
    public EventResult Result { get; init; } = EventResult.Denied;
    public string? Route { get; init; }
    public string? HttpMethod { get; init; }
    public string? RequiredPermission { get; init; }
    public string? Reason { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public required string CorrelationId { get; init; }
}

public enum SensitiveDataOperation
{
    Read,
    Create,
    Update,
    Delete
}

public sealed record SensitiveDataAccessEvent
{
    public required string ActorUserId { get; init; }
    public required SensitiveDataOperation Operation { get; init; }
    public required string TargetType { get; init; }
    public required string TargetId { get; init; }
    public required string DataClassification { get; init; }
    public EventResult Result { get; init; } = EventResult.Success;
    public long? RecordCount { get; init; }
    public string? Route { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public required string CorrelationId { get; init; }
}

public enum AdministrativeEventKind
{
    AdminAction,
    ConfigurationChanged,
    PermissionChanged
}

public sealed record AdministrativeSecurityEvent
{
    public required string ActorUserId { get; init; }
    public string? ActorRole { get; init; }
    public required AdministrativeEventKind Kind { get; init; }
    public required string Action { get; init; }
    public required string TargetType { get; init; }
    public string? TargetId { get; init; }
    public string? ChangedField { get; init; }
    public EventResult Result { get; init; } = EventResult.Success;
    public string? Reason { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? UserAgent { get; init; }
    public required string CorrelationId { get; init; }
}

public enum ControlBypassKind
{
    InputValidationFailure,
    BusinessLogicViolation,
    AntiAutomationTriggered
}

public sealed record ControlBypassEvent
{
    public required ControlBypassKind Kind { get; init; }
    public required string Action { get; init; }
    public EventResult Result { get; init; } = EventResult.Denied;
    public string? ActorUserId { get; init; }
    public string? ActorUsername { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? Route { get; init; }
    public string? HttpMethod { get; init; }
    public string? UserAgent { get; init; }
    public string? Reason { get; init; }
    public required string CorrelationId { get; init; }
}

public enum SecurityErrorKind
{
    ApplicationError,
    SecurityControlFailure
}

public sealed record SecurityErrorEvent
{
    public required SecurityErrorKind Kind { get; init; }
    public required string Action { get; init; }
    public required string Reason { get; init; }
    public string? ErrorType { get; init; }
    public string? Route { get; init; }
    public int? StatusCode { get; init; }
    public EventSeverity Severity { get; init; } = EventSeverity.High;
    public string? TraceId { get; init; }
    public required string CorrelationId { get; init; }
}

public enum DatabaseAuditAction
{
    Logon,
    Logoff,
    LogonFailure,
    Ddl,
    Dcl,
    Privileged,
    SensitiveRead,
    SensitiveWrite,
    QueryError,
    AuditConfig
}

public sealed record DatabaseAuditEvent
{
    public required string DbEngine { get; init; }
    public required DatabaseAuditAction Action { get; init; }
    public EventResult Result { get; init; } = EventResult.Success;
    public string? ActorUsername { get; init; }
    public string? ActorUserId { get; init; }
    public string TargetType { get; init; } = "database";
    public string? TargetName { get; init; }
    public string? StatementClass { get; init; }
    public string? Reason { get; init; }
    public IPAddress? SourceIpAddress { get; init; }
    public string? CorrelationId { get; init; }
}

namespace Bower.Sdk;

public interface IBowerTelemetry
{
    ValueTask<EmitResult> AuthenticationFailedAsync(
        AuthenticationFailedEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> RoleMembershipChangedAsync(
        RoleMembershipChangedEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> SensitiveDataExportedAsync(
        SensitiveDataExportedEvent securityEvent,
        CancellationToken cancellationToken = default);
}

public sealed record EmitResult(bool AcceptedForDelivery, string EventId, string? FailureCode);

/// <summary>Optional diagnostics implemented by the built-in SDK client.</summary>
public interface IBowerTelemetryDiagnostics
{
    /// <summary>Payload-free snapshot. Accepted means buffered, not durable or delivered.</summary>
    DeliveryStatus DeliveryStatus { get; }
}

/// <summary>Accepted = Delivered + Failed + Pending. Rejected items were never accepted.</summary>
public sealed record DeliveryStatus(long Accepted, long Delivered, long Failed, long Pending,
    long Rejected, long Retries, string SenderState, string? LastFailureCode);

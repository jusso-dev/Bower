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

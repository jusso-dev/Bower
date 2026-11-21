namespace Bower.Sdk;

/// <summary>
/// Strongly typed OWASP ASVS 5.0 application security telemetry API matching
/// <c>packs/owasp-asvs-app-logging</c>. Composes with <see cref="IBowerTelemetry"/>
/// without altering existing contracts.
/// </summary>
public interface IAsvsTelemetry
{
    ValueTask<EmitResult> AuthenticationSucceededAsync(
        AuthenticationSucceededEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> MfaEventAsync(
        MfaSecurityEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> AuthenticationFactorLifecycleAsync(
        AuthenticationFactorLifecycleEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> AccountStatusChangedAsync(
        AccountStatusChangedEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> SessionLifecycleAsync(
        SessionLifecycleEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> AuthorisationFailedAsync(
        AuthorisationFailedEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> SensitiveDataAccessedAsync(
        SensitiveDataAccessEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> AdministrativeActionAsync(
        AdministrativeSecurityEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> ControlBypassAttemptedAsync(
        ControlBypassEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> SecurityErrorAsync(
        SecurityErrorEvent securityEvent,
        CancellationToken cancellationToken = default);

    ValueTask<EmitResult> DatabaseAuditAsync(
        DatabaseAuditEvent securityEvent,
        CancellationToken cancellationToken = default);
}

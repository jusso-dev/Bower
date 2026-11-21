namespace Bower.Abstractions;

/// <summary>
/// Immutable redactor and policy evaluator pair captured once per event so an atomic hot
/// reload never causes one event to be redacted under one bundle and evaluated under another.
/// </summary>
public sealed record ActivePolicyRuntime(
    IEventRedactor Redactor,
    ITelemetryPolicyEvaluator PolicyEvaluator);

/// <summary>
/// Supplies the active redactor and policy evaluator pair for hot-reloading hosts.
/// </summary>
public interface IPolicyRuntimeProvider
{
    ActivePolicyRuntime Current { get; }
}

/// <summary>Fixed runtime provider used when a host or test overrides DI services directly.</summary>
public sealed class StaticPolicyRuntimeProvider(ActivePolicyRuntime current) : IPolicyRuntimeProvider
{
    public ActivePolicyRuntime Current { get; } = current;
}

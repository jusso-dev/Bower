using Bower.Core;

namespace Bower.Collector;

/// <summary>Expected sources and their silence state. Empty when no expectations are configured.</summary>
public sealed class SourceHealth(SourceExpectations? expectations, PipelineTelemetry telemetry, TimeProvider clock)
{
    public bool IsConfigured => expectations is not null;

    public IReadOnlyList<SourceSilenceStatus> Evaluate() =>
        expectations is null
            ? []
            : SourceSilenceEvaluator.Evaluate(expectations, telemetry.Sources(), telemetry.StartedAt, clock.GetUtcNow());
}

using Bower.Abstractions;
using Bower.Core;

namespace Bower.Collector;

/// <summary>Expected sources and their silence state. Empty when no expectations are configured.</summary>
public sealed class SourceHealth(SourceExpectations? expectations, PipelineTelemetry telemetry, TimeProvider clock)
{
    private IReadOnlyList<SourceMonitoring> monitoring = [];

    public bool IsConfigured => expectations is not null;

    /// <summary>
    /// Loads each expected source's durable monitoring start, recording now for sources
    /// expected for the first time and forgetting sources no longer expected. A restart
    /// keeps the original start, so it cannot extend a never-seen source's deadline.
    /// </summary>
    public async Task InitializeAsync(IDurableEventStore store, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        DateTimeOffset now = clock.GetUtcNow();
        monitoring = await store.StartSourceMonitoringAsync(
            expectations?.Sources.Select(item => new SourceMonitoring(item.Application, item.Environment, now)).ToArray() ?? [],
            cancellationToken);
    }

    public IReadOnlyList<SourceSilenceStatus> Evaluate() =>
        expectations is null
            ? []
            : SourceSilenceEvaluator.Evaluate(
                expectations,
                telemetry.Sources(),
                monitoring,
                telemetry.StartedAt,
                clock.GetUtcNow());
}

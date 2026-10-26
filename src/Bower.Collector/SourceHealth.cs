using Bower.Abstractions;
using Bower.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.Collector;

/// <summary>Expected sources and their silence state. Empty when no expectations are configured.</summary>
public sealed partial class SourceHealth(
    SourceExpectations? expectations,
    PipelineTelemetry telemetry,
    TimeProvider clock,
    ILogger<SourceHealth>? logger = null)
{
    private readonly ILogger logger = logger ?? NullLogger<SourceHealth>.Instance;
    private IReadOnlyList<SourceMonitoring> monitoring = [];

    public bool IsConfigured => expectations is not null;

    /// <summary>
    /// Loads each expected source's durable monitoring start, recording now for sources
    /// expected for the first time and forgetting sources no longer expected. A restart
    /// keeps the original start, so it cannot extend a never-seen source's deadline.
    /// Returns, and logs, the starts it forgot.
    /// </summary>
    public async Task<IReadOnlyList<SourceMonitoring>> InitializeAsync(
        IDurableEventStore store,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        DateTimeOffset now = clock.GetUtcNow();
        IReadOnlyList<SourceMonitoring> previous = await store.GetSourceMonitoringAsync(cancellationToken);
        monitoring = await store.StartSourceMonitoringAsync(
            expectations?.Sources.Select(item => new SourceMonitoring(item.Application, item.Environment, now)).ToArray() ?? [],
            cancellationToken);
        HashSet<(string, string)> kept = [.. monitoring.Select(item => (item.Application, item.Environment))];
        SourceMonitoring[] forgotten = [.. previous.Where(item => !kept.Contains((item.Application, item.Environment)))];
        if (forgotten.Length > 0)
        {
            LogMonitoringForgotten(
                this.logger,
                forgotten.Length,
                string.Join(", ", forgotten.Select(item => $"{item.Application}/{item.Environment}")));
        }

        return forgotten;
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

    [LoggerMessage(
        EventId = 1321,
        Level = LogLevel.Warning,
        Message = "Forgot the monitoring start of {Count} source(s) no longer expected: {Sources}. " +
            "Expecting one again starts a fresh allowance.")]
    private static partial void LogMonitoringForgotten(ILogger logger, int count, string sources);
}

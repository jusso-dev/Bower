using Bower.Abstractions;

namespace Bower.Collector.Jobs;

/// <summary>Queue observations, never a claim of destination query verification.</summary>
public static class DeliveryHealth
{
    public const string DeadLetters = "dead-letters";
    public const string Backpressure = "backpressure";
    public const string Stalled = "stalled";
    public const string Retrying = "retrying";

    /// <summary>Queue pages in use (share of the intake page limit) at which new events are effectively refused.</summary>
    public const double PageBackpressurePercent = 95;

    /// <param name="intakePaused">The queue volume is below its critical free-space watermark.</param>
    /// <param name="pagesUsedPercent"><see cref="Bower.Persistence.QueuePageUsage.UsedPercent"/>, when known.</param>
    public static string Evaluate(
        string outputType, QueueSnapshot snapshot, long capacityBytes, DateTimeOffset now, bool intakePaused = false,
        double? pagesUsedPercent = null)
    {
        if (string.Equals(outputType, "none", StringComparison.OrdinalIgnoreCase)) return "disabled";
        if (HasDeadLetters(snapshot)) return "degraded";
        if (IsBackpressure(snapshot, capacityBytes, intakePaused, pagesUsedPercent)) return "backpressure";
        if (IsStalled(snapshot, now)) return "stalled";
        if (IsRetrying(snapshot)) return "retrying";
        if (snapshot.Uploading > 0 || snapshot.Queued > 0) return "pending";
        // Retained acknowledgements carry no freshness or destination-query proof.
        // Stay conservative rather than synthesising last-ack timestamps.
        // Output may have changed since these receipts. Do not infer API acceptance
        // or spool creation from a queue-wide historical count.
        return snapshot.Delivered > 0 ? "idle" : "waiting";
    }

    /// <summary>
    /// Every delivery condition that applies, each on its own: <see cref="Evaluate"/> reports
    /// only the first (dead letters hide backpressure, a stall and retries).
    /// </summary>
    public static IReadOnlyList<string> Conditions(
        QueueSnapshot snapshot, long capacityBytes, DateTimeOffset now, bool intakePaused = false, double? pagesUsedPercent = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        List<string> conditions = [];
        if (HasDeadLetters(snapshot)) conditions.Add(DeadLetters);
        if (IsBackpressure(snapshot, capacityBytes, intakePaused, pagesUsedPercent)) conditions.Add(Backpressure);
        if (IsStalled(snapshot, now)) conditions.Add(Stalled);
        if (IsRetrying(snapshot)) conditions.Add(Retrying);
        return conditions;
    }

    private static bool HasDeadLetters(QueueSnapshot snapshot) => snapshot.DeadLettered > 0;

    // The page limit binds long before the logical cap: a queued row takes about 2.2 times its payload.
    private static bool IsBackpressure(QueueSnapshot snapshot, long capacityBytes, bool intakePaused, double? pagesUsedPercent) =>
        intakePaused
        || pagesUsedPercent >= PageBackpressurePercent
        || snapshot.UndeliveredBytes >= capacityBytes - capacityBytes / 10;

    private static bool IsStalled(QueueSnapshot snapshot, DateTimeOffset now) =>
        snapshot.OldestUndelivered is { } oldest && oldest < now.AddMinutes(-5);

    private static bool IsRetrying(QueueSnapshot snapshot) => snapshot.Retrying > 0;
}

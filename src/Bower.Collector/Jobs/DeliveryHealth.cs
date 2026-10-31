using Bower.Abstractions;

namespace Bower.Collector.Jobs;

/// <summary>Queue observations, never a claim of destination query verification.</summary>
public static class DeliveryHealth
{
    public const string DeadLetters = "dead-letters";
    public const string Backpressure = "backpressure";
    public const string Stalled = "stalled";
    public const string Retrying = "retrying";

    public static string Evaluate(string outputType, QueueSnapshot snapshot, long capacityBytes, DateTimeOffset now)
    {
        if (string.Equals(outputType, "none", StringComparison.OrdinalIgnoreCase)) return "disabled";
        if (HasDeadLetters(snapshot)) return "degraded";
        if (IsBackpressure(snapshot, capacityBytes)) return "backpressure";
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
    public static IReadOnlyList<string> Conditions(QueueSnapshot snapshot, long capacityBytes, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        List<string> conditions = [];
        if (HasDeadLetters(snapshot)) conditions.Add(DeadLetters);
        if (IsBackpressure(snapshot, capacityBytes)) conditions.Add(Backpressure);
        if (IsStalled(snapshot, now)) conditions.Add(Stalled);
        if (IsRetrying(snapshot)) conditions.Add(Retrying);
        return conditions;
    }

    private static bool HasDeadLetters(QueueSnapshot snapshot) => snapshot.DeadLettered > 0;

    private static bool IsBackpressure(QueueSnapshot snapshot, long capacityBytes) =>
        snapshot.UndeliveredBytes >= capacityBytes - capacityBytes / 10;

    private static bool IsStalled(QueueSnapshot snapshot, DateTimeOffset now) =>
        snapshot.OldestUndelivered is { } oldest && oldest < now.AddMinutes(-5);

    private static bool IsRetrying(QueueSnapshot snapshot) => snapshot.Retrying > 0;
}

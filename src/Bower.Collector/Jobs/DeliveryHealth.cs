using Bower.Abstractions;

namespace Bower.Collector.Jobs;

/// <summary>Queue observations, never a claim of destination query verification.</summary>
public static class DeliveryHealth
{
    public static string Evaluate(string outputType, QueueSnapshot snapshot, long capacityBytes, DateTimeOffset now)
    {
        if (string.Equals(outputType, "none", StringComparison.OrdinalIgnoreCase)) return "disabled";
        if (snapshot.DeadLettered > 0) return "degraded";
        if (snapshot.UndeliveredBytes >= capacityBytes - capacityBytes / 10) return "backpressure";
        if (snapshot.OldestUndelivered is { } oldest && oldest < now.AddMinutes(-5)) return "stalled";
        if (snapshot.Retrying > 0) return "retrying";
        if (snapshot.Uploading > 0 || snapshot.Queued > 0) return "pending";
        // Retained acknowledgements carry no freshness or destination-query proof.
        // Stay conservative rather than synthesising last-ack timestamps.
        if (snapshot.Delivered == 0) return "waiting";
        return string.Equals(outputType, "ama-spool", StringComparison.OrdinalIgnoreCase)
            ? "spooled" : "api-accepted";
    }
}

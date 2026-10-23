using Bower.Abstractions;
using Bower.Collector.Jobs;

namespace Bower.UnitTests;

public sealed class DeliveryHealthTests
{
    [Theory]
    [InlineData("none", 0, 0, 0, 0, "disabled")]
    [InlineData("azure-logs-ingestion", 1, 0, 0, 0, "pending")]
    [InlineData("azure-logs-ingestion", 0, 1, 0, 0, "retrying")]
    [InlineData("azure-logs-ingestion", 0, 0, 1, 0, "degraded")]
    [InlineData("azure-logs-ingestion", 1, 0, 0, 950, "backpressure")]
    [InlineData("azure-logs-ingestion", 0, 0, 0, 0, "waiting")]
    public void Missing_delivery_progress_is_never_healthy(string output, long queued, long retrying,
        long dead, long bytes, string expected)
    {
        QueueSnapshot snapshot = new(queued, retrying, 0, 0, dead, bytes, null, bytes);
        Assert.Equal(expected, DeliveryHealth.Evaluate(output, snapshot, 1000, TestEvents.Now));
    }

    [Fact]
    public void Old_backlog_is_stalled_and_historical_acknowledgements_are_not_query_proof()
    {
        QueueSnapshot snapshot = new(1, 0, 0, 100, 0, 10, TestEvents.Now.AddMinutes(-6), 10);
        Assert.Equal("stalled", DeliveryHealth.Evaluate("azure-logs-ingestion", snapshot, 1000, TestEvents.Now));
        Assert.Equal("api-accepted", DeliveryHealth.Evaluate("azure-logs-ingestion",
            snapshot with { Queued = 0, OldestUndelivered = null }, 1000, TestEvents.Now));
    }
}

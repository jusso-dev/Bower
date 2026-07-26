using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;

namespace Bower.UnitTests;

public sealed class SecurityEventProcessorTests
{
    [Fact]
    public async Task Process_RedactsBeforePersistenceAndExplainsAcceptance()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(
            Path.Combine(directory.Path, "queue.db"),
            10 * 1024 * 1024,
            clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock);
        Dictionary<string, JsonElement> attributes = new()
        {
            ["password"] = JsonSerializer.SerializeToElement("never-persist")
        };
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Attributes = attributes
        };

        ProcessingResult result = await processor.ProcessAsync(
            JsonSerializer.Serialize(candidate, BowerJson.Options),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);
        IReadOnlyList<QueuedEvent> queued = await store.LeaseAsync(
            1,
            TimeSpan.FromMinutes(1),
            cancellationToken);

        Assert.Equal(DecisionAction.RedactAndAccept, result.Action);
        Assert.True(result.Queued);
        Assert.Contains(
            result.Reasons,
            reason => reason.StartsWith("Removed 1", StringComparison.Ordinal));
        QueuedEvent persisted = Assert.Single(queued);
        Assert.DoesNotContain("never-persist", persisted.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("\"password\"", persisted.Payload, StringComparison.Ordinal);
        Assert.Contains("\"policyId\":\"BWR-POL-AUTH-FAILURE\"", persisted.Payload);
    }

    [Fact]
    public async Task Process_DeduplicatesStableSourceEvent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(
            Path.Combine(directory.Path, "queue.db"),
            10 * 1024 * 1024,
            clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(
            new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]),
            store,
            clock);
        string json = JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(clock.UtcNow),
            BowerJson.Options);
        CollectorIdentity identity = new("collector-1", "0.1.0", "test", "sha256:configuration");

        ProcessingResult first = await processor.ProcessAsync(json, identity, cancellationToken);
        ProcessingResult second = await processor.ProcessAsync(json, identity, cancellationToken);

        Assert.True(first.Queued);
        Assert.True(second.Duplicate);
        Assert.False(second.Queued);
    }
}

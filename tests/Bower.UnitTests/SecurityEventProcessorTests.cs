using System.Text.Json;
using System.Text.Json.Nodes;
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
    public async Task Process_DuplicateNestedPropertiesAreQuarantinedWithoutRetryOrPersistence()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);
        string valid = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow) with { EventId = "synthetic-id" }, BowerJson.Envelope);
        string candidate = valid[..^1] + ",\"attributes\":{\"duplicate\":1,\"duplicate\":2}}";
        SecurityEventProcessor processor = new(new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        ProcessingResult result = await processor.ProcessAsync(candidate,
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"), cancellation);
        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.False(result.RedactionRetryRequired);
        Assert.Contains("redaction-invalid-input", result.Reasons);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Fact]
    public void IdentityComparison_BoundsBothDocumentsByUtf8Bytes()
    {
        const string small = "{\"eventId\":\"synthetic-id\"}";
        string oversized = "{\"eventId\":\"synthetic-id\",\"padding\":\"" + new string('é', 524_288) + "\"}";
        Assert.Equal(RedactedEventIdentity.Comparison.InvalidOriginal, RedactedEventIdentity.Compare(oversized, small));
        Assert.Equal(RedactedEventIdentity.Comparison.Changed, RedactedEventIdentity.Compare(small, oversized));
    }

    [Theory]
    [InlineData("throw", false)]
    [InlineData("throw", true)]
    [InlineData("failure", false)]
    [InlineData("failure", true)]
    [InlineData("missing", false)]
    [InlineData("missing", true)]
    public async Task Process_RedactorFailureOnInvalidOriginalIsSchemaFailure(string mode, bool invalidEnum)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);
        string valid = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow) with { EventId = "synthetic-id" }, BowerJson.Envelope);
        JsonObject original = invalidEnum ? JsonNode.Parse(valid)!.AsObject() : new JsonObject { ["eventId"] = "synthetic-id" };
        if (invalidEnum) original["eventResult"] = "invalid-enum";
        SecurityEventProcessor processor = new(new UnavailableTestRedactor(mode),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        ProcessingResult result = await processor.ProcessAsync(original.ToJsonString(),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"), cancellation);
        Assert.False(result.RedactionRetryRequired);
        Assert.Equal(ProcessingStage.Schema, result.Stage);
        Assert.Contains("schema-invalid", result.Reasons);
        Assert.DoesNotContain(UnavailableTestRedactor.SecretMarker, string.Join(' ', result.Reasons), StringComparison.Ordinal);
        Assert.Null(result.EventId);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Theory]
    [InlineData("{\"eventId\":\"x\",\"eventId\":\"y\"}")]
    [InlineData("{\"eventId\":\"x\"")]
    public async Task Process_AmbiguousOrMalformedOriginalDoesNotQueueEvenIfARedactorReturnsValidJson(string input)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);
        string valid = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow) with { EventId = "x" }, BowerJson.Envelope);
        SecurityEventProcessor processor = new(new FixedJsonRedactor(valid),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        ProcessingResult result = await processor.ProcessAsync(input,
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"), cancellation);
        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.Contains("schema-invalid", result.Reasons);
        Assert.Null(result.EventId);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    private sealed class FixedJsonRedactor(string output) : IEventRedactor
    {
        public RedactionResult Redact(string json) => new(true, output, [], [], null);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Process_InvalidRedactedEnvelopeRetriesOnlyWhenOriginalIsValid(bool originalValid)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);
        string valid = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow) with { EventId = "synthetic-id" }, BowerJson.Envelope);
        JsonObject invalid = JsonNode.Parse(valid)!.AsObject();
        invalid["timeGenerated"] = "not-a-date";
        string damaged = invalid.ToJsonString();
        SecurityEventProcessor processor = new(new FixedJsonRedactor(damaged),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        ProcessingResult result = await processor.ProcessAsync(originalValid ? valid : damaged,
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"), cancellation);
        Assert.Equal(originalValid, result.RedactionRetryRequired);
        Assert.Contains(originalValid ? "redaction-unavailable" : "schema-invalid", result.Reasons);
        Assert.Null(result.EventId);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Theory]
    [InlineData("{\"eventId\":\"x\",\"eventId\":\"y\"}")]
    [InlineData("{\"eventId\":\"x\"")]
    public async Task Process_AmbiguousOrMalformedRedactedOutputRequiresRetry(string output)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);
        string input = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow) with { EventId = "synthetic-id" }, BowerJson.Envelope);
        SecurityEventProcessor processor = new(new FixedJsonRedactor(output),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        ProcessingResult result = await processor.ProcessAsync(input,
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"), cancellation);
        Assert.True(result.RedactionRetryRequired);
        Assert.Null(result.EventId);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Process_RemovedOrNonStringRedactedIdRequiresRetryBeforeDeserialization(bool useNumber)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellation);
        string input = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow) with { EventId = "synthetic-id" }, BowerJson.Envelope);
        JsonObject redacted = JsonNode.Parse(input)!.AsObject();
        if (useNumber) redacted["eventId"] = 42;
        else redacted.Remove("eventId");
        SecurityEventProcessor processor = new(new FixedJsonRedactor(redacted.ToJsonString()),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]), store, clock);
        ProcessingResult result = await processor.ProcessAsync(input,
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"), cancellation);
        Assert.True(result.RedactionRetryRequired);
        Assert.Null(result.EventId);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

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
            new DeterministicPolicyEvaluator(
            [
                TestEvents.AuthenticationPolicy(),
                TestEvents.PrivacyDetectionPolicy()
            ]),
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
            10,
            TimeSpan.FromMinutes(1),
            cancellationToken);

        Assert.Equal(DecisionAction.RedactAndAccept, result.Action);
        Assert.True(result.Queued);
        Assert.Contains(
            result.Reasons,
            reason => reason.StartsWith("Removed 1", StringComparison.Ordinal));
        Assert.NotNull(result.PrivacyAlertEventId);
        Assert.Equal(2, queued.Count);
        QueuedEvent original = Assert.Single(
            queued,
            item => item.EventId == candidate.EventId);
        Assert.DoesNotContain("never-persist", original.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("\"password\"", original.Payload, StringComparison.Ordinal);
        Assert.Contains("\"policyId\":\"BWR-POL-AUTH-FAILURE\"", original.Payload);

        QueuedEvent alert = Assert.Single(
            queued,
            item => item.EventId == result.PrivacyAlertEventId);
        Assert.Contains(SecurityEventTypes.SensitiveDataDetected, alert.Payload, StringComparison.Ordinal);
        Assert.Contains("field-name-secret", alert.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("never-persist", alert.Payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Process_EmitsPrivacyAlertForRegulatedIdentifier()
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
            new DeterministicPolicyEvaluator(
            [
                TestEvents.AuthenticationPolicy(),
                TestEvents.PrivacyDetectionPolicy()
            ]),
            store,
            clock);

        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                ["note"] = JsonSerializer.SerializeToElement("TFN 100000001")
            }
        };

        ProcessingResult result = await processor.ProcessAsync(
            JsonSerializer.Serialize(candidate, BowerJson.Options),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);

        Assert.True(result.Queued);
        Assert.NotNull(result.PrivacyAlertEventId);
        IReadOnlyList<QueuedEvent> queued = await store.LeaseAsync(
            10,
            TimeSpan.FromMinutes(1),
            cancellationToken);
        QueuedEvent alert = Assert.Single(
            queued,
            item => item.EventId == result.PrivacyAlertEventId);
        Assert.Contains("au.tfn", alert.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("100000001", alert.Payload, StringComparison.Ordinal);
        Assert.Contains("privacy-control", alert.Payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Process_DoesNotEmitPrivacyAlertForEmailOnly()
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
            new DeterministicPolicyEvaluator(
            [
                TestEvents.AuthenticationPolicy(),
                TestEvents.PrivacyDetectionPolicy()
            ]),
            store,
            clock);

        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                ["contact"] = JsonSerializer.SerializeToElement("alice@example.test")
            }
        };

        ProcessingResult result = await processor.ProcessAsync(
            JsonSerializer.Serialize(candidate, BowerJson.Options),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);

        Assert.True(result.Queued);
        Assert.Null(result.PrivacyAlertEventId);
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
            new DeterministicPolicyEvaluator(
            [
                TestEvents.AuthenticationPolicy(),
                TestEvents.PrivacyDetectionPolicy()
            ]),
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

    [Fact]
    public async Task Process_NullApplicationWithSecretQuarantinesWithoutThrowing()
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
            new DeterministicPolicyEvaluator(
            [
                TestEvents.AuthenticationPolicy(),
                TestEvents.PrivacyDetectionPolicy()
            ]),
            store,
            clock);

        // Before the fix the privacy alert copied the null application and the processor
        // threw NullReferenceException. The alert is now built with an empty application,
        // which the privacy policy (application.name required) does not accept.
        ProcessingResult result = await processor.ProcessAsync(
            NullApplicationWithSecret(clock),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);

        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.False(result.Queued);
        Assert.Equal(["application.name and application.environment are required"], result.Reasons);
        Assert.Null(result.PrivacyAlertEventId);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken));
    }

    [Fact]
    public async Task Process_NullApplicationAlertCarriesAnEmptyApplication()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(
            Path.Combine(directory.Path, "queue.db"),
            10 * 1024 * 1024,
            clock);
        await store.InitializeAsync(cancellationToken);
        SecurityEventProcessor processor = new(new JsonEventRedactor(), new AcceptAlerts(), store, clock);

        ProcessingResult result = await processor.ProcessAsync(
            NullApplicationWithSecret(clock),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);
        IReadOnlyList<QueuedEvent> queued = await store.LeaseAsync(
            10,
            TimeSpan.FromMinutes(1),
            cancellationToken);

        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.Equal(["application.name and application.environment are required"], result.Reasons);
        QueuedEvent alert = Assert.Single(queued);
        Assert.Equal(result.PrivacyAlertEventId, alert.EventId);
        Assert.Contains("\"application\":{\"name\":\"\",\"environment\":\"\"}", alert.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("never-persist", alert.Payload, StringComparison.Ordinal);
    }

    private static string NullApplicationWithSecret(FakeClock clock)
    {
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                ["password"] = JsonSerializer.SerializeToElement("never-persist")
            }
        };
        JsonObject json =
            JsonNode.Parse(JsonSerializer.Serialize(candidate, BowerJson.Options))!.AsObject();
        json["application"] = null;
        return json.ToJsonString();
    }

    private sealed class AcceptAlerts : ITelemetryPolicyEvaluator
    {
        public PolicyDecision Evaluate(SecurityEventEnvelope candidate) => new(
            candidate.EventType == SecurityEventTypes.SensitiveDataDetected ? DecisionAction.Accept : DecisionAction.Reject,
            "test",
            "1.0.0",
            "sha256:test",
            80,
            [],
            []);
    }

    [Theory]
    [InlineData("eventResult", "7")]
    [InlineData("eventResult", "\"7\"")]
    [InlineData("eventResult", "-1")]
    [InlineData("eventSeverity", "5")]
    [InlineData("actor.type", "9")]
    public async Task Process_UndefinedEnumValueIsSchemaInvalid(string field, string value)
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
        JsonObject json = JsonNode.Parse(
            JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options))!.AsObject();
        string[] path = field.Split('.');
        JsonObject parent = path.Length == 1 ? json : json[path[0]]!.AsObject();
        parent[path[^1]] = JsonNode.Parse(value);

        ProcessingResult result = await processor.ProcessAsync(
            json.ToJsonString(),
            new CollectorIdentity("collector-1", "0.1.0", "test", "sha256:configuration"),
            cancellationToken);

        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.Equal(["schema-invalid"], result.Reasons);
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken));
    }
}

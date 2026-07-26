using Bower.Abstractions;
using Bower.Contracts;
using Bower.PolicyEngine;

namespace Bower.UnitTests;

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"bower-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}

internal sealed class FakeClock(DateTimeOffset value) : IClock
{
    public DateTimeOffset UtcNow { get; private set; } = value;

    public void Advance(TimeSpan duration)
    {
        UtcNow = UtcNow.Add(duration);
    }
}

internal static class TestEvents
{
    public static DateTimeOffset Now { get; } =
        new(2026, 7, 26, 2, 14, 19, TimeSpan.Zero);

    public static SecurityEventEnvelope AuthenticationFailure(
        DateTimeOffset now,
        string eventId = "event-1",
        string? originalId = "source-1")
    {
        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            EventOriginalId = originalId,
            TimeGenerated = now,
            EventCategory = SecurityEventCategories.Authentication,
            EventType = SecurityEventTypes.AuthenticationFailure,
            EventAction = "authentication.attempt",
            EventResult = EventResult.Failure,
            EventOutcomeReason = "InvalidPassword",
            Application = new ApplicationContext
            {
                Name = "TestApplication",
                Environment = "test"
            },
            Actor = new ActorContext { Username = "test-user" },
            Source = new SourceContext { IpAddress = "192.0.2.10" },
            Request = new RequestContext { CorrelationId = "correlation-1" }
        };
    }

    public static LoadedPolicy AuthenticationPolicy()
    {
        TelemetryPolicy policy = new()
        {
            ApiVersion = "bower.security/v1",
            Kind = "TelemetryPolicy",
            Metadata = new PolicyMetadata
            {
                Id = "BWR-POL-AUTH-FAILURE",
                Name = "Authentication failures",
                Version = "1.0.0",
                Owner = "Security Operations"
            },
            Match = new PolicyMatch
            {
                EventCategories = [SecurityEventCategories.Authentication],
                EventTypes = [SecurityEventTypes.AuthenticationFailure]
            },
            Requirements = new PolicyRequirements
            {
                RequiredFields =
                [
                    "timeGenerated",
                    "eventType",
                    "eventResult",
                    "application.name"
                ],
                AtLeastOne = ["actor.userId", "actor.username"],
                RecommendedFields =
                [
                    "source.ipAddress",
                    "eventOutcomeReason",
                    "request.correlationId"
                ]
            },
            Decision = new PolicyAction
            {
                Action = "accept",
                MinimumValueScore = 70,
                NeverSample = true
            }
        };
        return new LoadedPolicy(policy, "sha256:test-policy", "test");
    }
}

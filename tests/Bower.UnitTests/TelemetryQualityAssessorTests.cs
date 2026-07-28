using Bower.Analytics;
using Bower.Contracts;

namespace Bower.UnitTests;

public sealed class TelemetryQualityAssessorTests
{
    [Fact]
    public void Assess_HealthyFleet_ScoresHigh()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-28T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        QualityAssessmentInput input = new(
            [
                new SourceCoverageObservation("http", "http-collector", true, now.AddMinutes(-5), 100, true),
                new SourceCoverageObservation("sql", "sqlserver", true, now.AddMinutes(-10), 50, true)
            ],
            [
                new FieldCompletenessObservation("actor.username", 95, 100, true),
                new FieldCompletenessObservation("target.name", 90, 100, true),
                new FieldCompletenessObservation("request.correlationId", 88, 100, true)
            ],
            [
                new SecurityEventEnvelope
                {
                    SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
                    EventId = Guid.CreateVersion7().ToString(),
                    TimeGenerated = now,
                    EventCategory = SecurityEventCategories.Authentication,
                    EventType = SecurityEventTypes.AuthenticationFailure,
                    EventAction = "authentication.attempt",
                    EventResult = EventResult.Failure,
                    Application = new ApplicationContext { Name = "app", Environment = "test" },
                    Actor = new ActorContext { Username = "alice" },
                    Target = new TargetContext { Type = "account", Name = "alice" },
                    Request = new RequestContext { CorrelationId = "c1" }
                }
            ]);

        TelemetryQualityReport report = TelemetryQualityAssessor.Assess(input, now);

        Assert.True(report.OverallScore >= 85);
        Assert.True(report.Grade is "A" or "B");
        Assert.Equal(4, report.Components.Count);
    }

    [Fact]
    public void Assess_MissingSources_RecommendsCoverage()
    {
        TelemetryQualityReport report = TelemetryQualityAssessor.Assess(
            new QualityAssessmentInput([], []));

        Assert.Equal(0, report.Components.Single(item => item.Name == "coverage").Score);
        Assert.Contains(report.Recommendations, item => item.Contains("sources", StringComparison.OrdinalIgnoreCase));
    }
}

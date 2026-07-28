using Bower.Contracts;
using Bower.Detection;

namespace Bower.UnitTests;

public sealed class DetectionEngineTests
{
    [Fact]
    public void LoadDirectory_ParsesSampleSigmaRule()
    {
        string directory = Path.Combine(AppContext.BaseDirectory, "rules", "sigma");

        IReadOnlyList<DetectionRule> rules = SigmaRuleLoader.LoadDirectory(directory);

        Assert.Contains(rules, rule => rule.Id == "bower-auth-failure-001");
        DetectionRule auth = rules.Single(rule => rule.Id == "bower-auth-failure-001");
        Assert.Contains("T1110", auth.MitreTechniques);
        Assert.Equal("medium", auth.Level);
    }

    [Fact]
    public void Evaluate_RaisesAlertForAuthenticationFailure()
    {
        DetectionRule rule = SigmaRuleLoader.LoadYaml(
            """
            title: Auth Fail
            id: test-auth-1
            level: high
            version: 1.0.0
            detection:
              selection:
                EventType: authentication_failure
              condition: selection
            tags:
              - attack.t1110
            """);

        DetectionEngine engine = new([rule]);
        SecurityEventEnvelope envelope = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = Guid.CreateVersion7().ToString(),
            TimeGenerated = DateTimeOffset.UtcNow,
            EventCategory = SecurityEventCategories.Authentication,
            EventType = SecurityEventTypes.AuthenticationFailure,
            EventAction = "authentication.attempt",
            EventResult = EventResult.Failure,
            Application = new ApplicationContext { Name = "app", Environment = "test" },
            Actor = new ActorContext { Username = "alice" },
            Source = new SourceContext { IpAddress = "203.0.113.9" }
        };

        DetectionEvaluationResult result = engine.Evaluate(envelope);

        DetectionAlert alert = Assert.Single(result.Alerts);
        Assert.Equal("test-auth-1", alert.RuleId);
        Assert.Equal(75, alert.RiskScore);
        Assert.Contains("T1110", alert.MitreTechniques);
        Assert.Equal("alice", alert.Actor);
    }

    [Fact]
    public void Evaluate_SuppressesConfiguredRuleIds()
    {
        DetectionRule rule = SigmaRuleLoader.LoadYaml(
            """
            title: Auth Fail
            id: suppressed-1
            level: low
            detection:
              selection:
                EventType: authentication_failure
              condition: selection
            """);

        DetectionEngine engine = new([rule], ["suppressed-1"]);
        SecurityEventEnvelope envelope = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = Guid.CreateVersion7().ToString(),
            TimeGenerated = DateTimeOffset.UtcNow,
            EventCategory = SecurityEventCategories.Authentication,
            EventType = SecurityEventTypes.AuthenticationFailure,
            EventAction = "authentication.attempt",
            EventResult = EventResult.Failure,
            Application = new ApplicationContext { Name = "app", Environment = "test" }
        };

        DetectionEvaluationResult result = engine.Evaluate(envelope);

        Assert.Empty(result.Alerts);
        Assert.Contains("suppressed-1", result.SuppressedRuleIds);
    }
}

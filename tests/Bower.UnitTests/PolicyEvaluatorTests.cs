using System.Text.Json;
using Bower.Contracts;
using Bower.PolicyEngine;

namespace Bower.UnitTests;

public sealed class PolicyEvaluatorTests
{
    [Fact]
    public void Evaluate_AcceptsCompleteApprovedEventWithExplanation()
    {
        DateTimeOffset now = TestEvents.Now;
        DeterministicPolicyEvaluator evaluator = new([TestEvents.AuthenticationPolicy()]);

        Bower.Abstractions.PolicyDecision result = evaluator.Evaluate(
            TestEvents.AuthenticationFailure(now));

        Assert.Equal(DecisionAction.Accept, result.Action);
        Assert.Equal("BWR-POL-AUTH-FAILURE", result.PolicyId);
        Assert.True(result.Score >= 70);
        Assert.Contains(result.Reasons, reason => reason.Contains("meets minimum"));
    }

    [Fact]
    public void Evaluate_DefaultDeniesUnknownEvent()
    {
        DateTimeOffset now = TestEvents.Now;
        DeterministicPolicyEvaluator evaluator = new([TestEvents.AuthenticationPolicy()]);
        SecurityEventEnvelope unknown = TestEvents.AuthenticationFailure(now) with
        {
            EventType = "free_form_diagnostic",
            EventCategory = "diagnostic"
        };

        Bower.Abstractions.PolicyDecision result = evaluator.Evaluate(unknown);

        Assert.Equal(DecisionAction.Reject, result.Action);
        Assert.Equal("BWR-POL-DEFAULT-DENY", result.PolicyId);
    }

    [Fact]
    public void Evaluate_QuarantinesEventMissingActor()
    {
        DateTimeOffset now = TestEvents.Now;
        DeterministicPolicyEvaluator evaluator = new([TestEvents.AuthenticationPolicy()]);
        SecurityEventEnvelope incomplete = TestEvents.AuthenticationFailure(now) with
        {
            Actor = null
        };

        Bower.Abstractions.PolicyDecision result = evaluator.Evaluate(incomplete);

        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.Contains(
            result.Reasons,
            reason => reason.StartsWith("Missing required field", StringComparison.Ordinal));
    }

    [Fact]
    public void Evaluate_ReadsLabelAndAttributeFieldPaths()
    {
        DeterministicPolicyEvaluator evaluator = new([LabelAndAttributePolicy()]);
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(TestEvents.Now) with
        {
            Labels = new Dictionary<string, string>
            {
                ["sourceEventId"] = "event-0",
                ["blank"] = " "
            },
            Attributes = new Dictionary<string, JsonElement>
            {
                ["http.route"] = Json("\"/login\""),
                ["count"] = Json("0"),
                ["flag"] = Json("false"),
                ["empty"] = Json("\"\""),
                ["none"] = Json("null")
            }
        };

        Bower.Abstractions.PolicyDecision result = evaluator.Evaluate(candidate);

        Assert.Equal(DecisionAction.Accept, result.Action);
        // 40 + 30 required + 10 actor + 5 source + 10 correlation + 2 recommended present.
        Assert.Equal(97, result.Score);
        Assert.Equal(
            [
                "Missing recommended field: attributes.empty",
                "Missing recommended field: attributes.none",
                "Missing recommended field: labels.blank",
                "Missing recommended field: labels.absent"
            ],
            result.Warnings);
    }

    [Fact]
    public void Evaluate_QuarantinesWhenRequiredLabelOrAttributeIsMissing()
    {
        DeterministicPolicyEvaluator evaluator = new([LabelAndAttributePolicy()]);
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(TestEvents.Now) with
        {
            // Keys match ordinally: case differs, so neither required path is present.
            Labels = new Dictionary<string, string> { ["SourceEventId"] = "event-0" },
            Attributes = new Dictionary<string, JsonElement> { ["http"] = Json("{\"route\":\"/login\"}") }
        };

        Bower.Abstractions.PolicyDecision result = evaluator.Evaluate(candidate);

        Assert.Equal(DecisionAction.Quarantine, result.Action);
        Assert.Equal(
            [
                "Missing required field: labels.sourceEventId",
                "Missing required field: attributes.http.route"
            ],
            result.Reasons);
    }

    private static LoadedPolicy LabelAndAttributePolicy()
    {
        LoadedPolicy loaded = TestEvents.AuthenticationPolicy();
        return loaded with
        {
            Policy = loaded.Policy with
            {
                Requirements = new PolicyRequirements
                {
                    RequiredFields = ["labels.sourceEventId", "attributes.http.route"],
                    RecommendedFields =
                    [
                        "attributes.count",
                        "attributes.flag",
                        "attributes.empty",
                        "attributes.none",
                        "labels.blank",
                        "labels.absent"
                    ]
                }
            }
        };
    }

    private static JsonElement Json(string text)
    {
        using JsonDocument document = JsonDocument.Parse(text);
        return document.RootElement.Clone();
    }
}

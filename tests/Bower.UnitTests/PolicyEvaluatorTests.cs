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
}

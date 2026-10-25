using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.PolicyEngine;

namespace Bower.UnitTests;

/// <summary>
/// Pins suppression key resolution, key hashes, window boundaries and summary events for the
/// Rust port (<c>rust/crates/bower-core/tests/fixtures/suppression-vectors.json</c>). Set
/// <c>BOWER_SUPPRESSION_VECTOR_OUTPUT</c> to a file path to regenerate after an intended change.
/// </summary>
public sealed class SuppressionParityVectorTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "core-vectors", "suppression-vectors.json");

    private static readonly CollectorIdentity Collector =
        new("collector-parity", "0.1.0", "local-http:producer-a", "sha256:configuration");

    private static readonly string[] Events =
    [
        """{"schemaVersion":"1.0.0","eventId":"e1","eventOriginalId":"o1","timeGenerated":"2026-07-26T02:14:19+00:00","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","application":{"name":"FinanceApi","environment":"production"},"actor":{"username":"alice"},"source":{"ipAddress":"192.0.2.10"}}""",
        """{"schemaVersion":"1.0.0","eventId":"e2","timeGenerated":"2026-07-26T02:14:19+00:00","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","application":{"name":"FinanceApi","environment":"production","tenantId":"tenant-7"},"actor":{"username":"zoë 用户 \"q\""}}""",
        """{"schemaVersion":"1.0.0","eventId":"e3","timeGenerated":"2026-07-26T02:14:19+00:00","eventCategory":"authentication","eventType":"authentication_failure","eventAction":"authentication.attempt","eventResult":"failure","application":{"name":"Portal","environment":"test"},"actor":{"username":"bob"},"source":{"ipAddress":""},"labels":{"region":"au-east"}}"""
    ];

    private static readonly string[] ReceivedTimes =
    [
        "2026-07-26T02:14:19.1234567+00:00",
        "2026-07-26T02:14:59.9999999+00:00",
        "1970-01-01T00:00:00+00:00"
    ];

    [Fact]
    public void SuppressionVectors_MatchCSharpOutcomes()
    {
        using TemporaryDirectory directory = new();
        IReadOnlyList<LoadedPolicy> policies = SuppressionTests.LoadPolicies(
            directory,
            SuppressionTests.SuppressingPolicy,
            SuppressionTests.SummaryPolicy);
        DeterministicPolicyEvaluator evaluator = new(policies);

        JsonArray cases = [];
        for (int index = 0; index < Events.Length; index++)
        {
            SecurityEventEnvelope envelope = JsonSerializer.Deserialize(Events[index], BowerJson.Envelope)!;
            PolicyDecision decision = evaluator.Evaluate(envelope);
            SuppressionRequest request = Suppression.CreateRequest(envelope, decision, decision.Suppression!);
            DateTimeOffset received = DateTimeOffset.Parse(ReceivedTimes[index], CultureInfo.InvariantCulture);
            long seconds = received.ToUnixTimeSeconds();
            cases.Add(new JsonObject
            {
                ["event"] = Events[index],
                ["receivedAt"] = ReceivedTimes[index],
                ["keyValues"] = new JsonArray([.. request.KeyValues.Select(value => (JsonNode?)value)]),
                ["keyHash"] = request.KeyHash,
                ["windowStart"] = seconds - (seconds % request.WindowSeconds)
            });
        }

        SecurityEventEnvelope first = JsonSerializer.Deserialize(Events[1], BowerJson.Envelope)!;
        PolicyDecision firstDecision = evaluator.Evaluate(first);
        SuppressionRequest rule = Suppression.CreateRequest(first, firstDecision, firstDecision.Suppression!);
        DateTimeOffset start = new(2026, 7, 26, 2, 14, 0, TimeSpan.Zero);
        SuppressionWindow[] windows =
        [
            new(rule, start, start.AddSeconds(60), 2, 5,
                DateTimeOffset.Parse("2026-07-26T02:14:03.5000000+00:00", CultureInfo.InvariantCulture),
                DateTimeOffset.Parse("2026-07-26T02:14:58.0000001+00:00", CultureInfo.InvariantCulture)),
            new(rule with { TenantId = null, KeyValues = ["", "192.0.2.1"] }, start, start.AddSeconds(60), 1, 1, start, start)
        ];
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-26T02:16:00.0000001+00:00", CultureInfo.InvariantCulture);
        JsonArray summaries = [];
        foreach (SuppressionWindow window in windows)
        {
            SecurityEventEnvelope summary = Suppression.CreateSummary(window, Collector, now);
            PolicyDecision decision = evaluator.Evaluate(summary);
            SecurityEventEnvelope arranged = summary with
            {
                Security = new SecurityDecisionContext
                {
                    PolicyId = decision.PolicyId,
                    PolicyVersion = decision.PolicyVersion,
                    PolicyHash = decision.PolicyHash,
                    ValueScore = decision.Score,
                    Decision = DecisionAction.Aggregate,
                    ClassificationReasons = decision.Reasons
                }
            };
            summaries.Add(new JsonObject
            {
                ["keyValues"] = new JsonArray([.. window.Rule.KeyValues.Select(value => (JsonNode?)value)]),
                ["tenantId"] = window.Rule.TenantId,
                ["admitted"] = window.Admitted,
                ["suppressed"] = window.Suppressed,
                ["firstSuppressedAt"] = window.FirstSuppressedAt?.ToString("O", CultureInfo.InvariantCulture),
                ["lastSuppressedAt"] = window.LastSuppressedAt?.ToString("O", CultureInfo.InvariantCulture),
                ["decision"] = decision.Action.ToString(),
                ["eventId"] = arranged.EventId,
                ["fingerprint"] = EventFingerprint.Create(arranged),
                ["payload"] = JsonSerializer.Serialize(arranged, BowerJson.Envelope)
            });
        }

        JsonObject actual = new()
        {
            ["_comment"] = "Generated by SuppressionParityVectorTests (C#). Do not edit by hand.",
            ["policies"] = new JsonArray(SuppressionTests.SuppressingPolicy, SuppressionTests.SummaryPolicy),
            ["collector"] = new JsonObject
            {
                ["id"] = Collector.Id,
                ["version"] = Collector.Version,
                ["sourceAdapter"] = Collector.SourceAdapter,
                ["configurationHash"] = Collector.ConfigurationHash
            },
            ["windowStart"] = start.ToUnixTimeSeconds(),
            ["windowSeconds"] = 60,
            ["now"] = now.ToString("O", CultureInfo.InvariantCulture),
            ["cases"] = cases,
            ["summaries"] = summaries
        };
        string text = actual.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }) + "\n";

        if (Environment.GetEnvironmentVariable("BOWER_SUPPRESSION_VECTOR_OUTPUT") is { Length: > 0 } output)
        {
            File.WriteAllText(output, text);
        }

        Assert.Equal(File.ReadAllText(FixturePath), text);
    }
}

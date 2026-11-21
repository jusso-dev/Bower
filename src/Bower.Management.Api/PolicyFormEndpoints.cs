using System.Globalization;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;
using Microsoft.AspNetCore.Mvc;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Bower.Management.Api;

public sealed record PolicyTemplateItem(string Id, string Title, string Description, string Content);

public sealed record PolicySuppressionForm(
    bool Enabled,
    IReadOnlyList<string> KeyFields,
    int WindowSeconds,
    int AllowPerWindow);

public sealed record PolicyForm(
    string Id,
    string Name,
    string Version,
    string Owner,
    IReadOnlyList<string> EventCategories,
    IReadOnlyList<string> EventTypes,
    IReadOnlyList<string> RequiredFields,
    IReadOnlyList<string> AtLeastOne,
    IReadOnlyList<string> RecommendedFields,
    string Action,
    int MinimumValueScore,
    bool NeverSample,
    PolicySuppressionForm? Suppression);

public sealed record PolicyFormRequest(string Content, PolicyForm? Form);

public sealed record PolicyDiffEntry(string Change, string Detail);

public sealed record PolicyFormDiff(
    string BeforeHash,
    string AfterHash,
    bool SemanticallyIdentical,
    IReadOnlyList<PolicyDiffEntry> Changes);

public sealed record PolicyPreviewFinding(string DetectorId, string Action, string Path);

public sealed record PolicySamplePreview(
    bool Valid,
    string BeforeDecision,
    string AfterDecision,
    int ValueScore,
    string? RedactedEventJson,
    IReadOnlyList<PolicyPreviewFinding> Findings);

public sealed record PolicyFormResult(
    PolicyForm Form,
    string Content,
    bool Valid,
    IReadOnlyList<string> Errors,
    string? PolicyHash,
    PolicyFormDiff? Diff,
    PolicySamplePreview? Preview);

/// <summary>
/// No-code policy decision and suppression (<c>aggregate</c>) form editor backed by the
/// collector's own <see cref="PolicyLoader"/>, <see cref="DeterministicPolicyEvaluator"/>,
/// and <see cref="PrivacyEngine"/>. Only server-owned synthetic samples are previewed, and
/// only post-redaction output ever leaves the API.
/// </summary>
internal static class PolicyFormEndpoints
{
    private const long BodyLimit = 256 * 1024;

    private static readonly PolicyTemplateItem[] Templates =
    [
        new(
            "authentication-failure",
            "Authentication failures",
            "Accepts authentication failure and account lockout events without sampling.",
            """
            apiVersion: bower.security/v1
            kind: TelemetryPolicy
            metadata:
              id: BWR-POL-AUTH-FAILURE
              name: Authentication failures
              version: 1.0.0
              owner: Security Operations
            match:
              eventCategories:
                - authentication
              eventTypes:
                - authentication_failure
                - account_lockout
            requirements:
              requiredFields:
                - timeGenerated
                - eventType
                - eventResult
                - application.name
              atLeastOne:
                - actor.userId
                - actor.username
              recommendedFields:
                - source.ipAddress
                - eventOutcomeReason
            decision:
              action: accept
              minimumValueScore: 70
              neverSample: true
            routing:
              profile: authentication
              destination: security-events
            """),
        new(
            "rate-limit-aggregate",
            "Rate-limit flood aggregation",
            "Aggregates noisy rate-limit hits into per-window summary events using the aggregate action.",
            """
            apiVersion: bower.security/v1
            kind: TelemetryPolicy
            metadata:
              id: BWR-POL-RATE-LIMIT
              name: Rate-limit flood aggregation
              version: 1.0.0
              owner: Application Security
            match:
              eventCategories:
                - anti-automation
              eventTypes:
                - rate_limit_exceeded
            requirements:
              requiredFields:
                - timeGenerated
                - eventType
                - eventResult
                - application.name
              atLeastOne:
                - source.ipAddress
                - actor.username
              recommendedFields:
                - request.correlationId
            decision:
              action: aggregate
              minimumValueScore: 50
              neverSample: false
            suppression:
              keyFields:
                - application.name
                - eventType
                - source.ipAddress
              windowSeconds: 60
              allowPerWindow: 0
            routing:
              profile: application-security
              destination: security-events
            """)
    ];

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/policies/templates", () => Results.Ok(Templates))
            .RequireAuthorization("View");

        api.MapPost(
                "/policies/form",
                (PolicyFormRequest request) =>
                {
                    if (string.IsNullOrWhiteSpace(request.Content))
                    {
                        return Results.BadRequest(new ErrorResponse("Policy YAML content is required."));
                    }

                    LoadedPolicy baseline;
                    try
                    {
                        baseline = PolicyLoader.LoadYaml(request.Content, "policy.yaml");
                    }
                    catch (Exception exception) when (exception is InvalidDataException or YamlException)
                    {
                        return Results.BadRequest(new ErrorResponse(
                            $"Baseline policy YAML is invalid: {exception.Message}"));
                    }

                    string editedYaml = request.Content;
                    if (request.Form is { } form)
                    {
                        if (!TryApplyForm(request.Content, form, out editedYaml, out string? formError))
                        {
                            return Results.Ok(new PolicyFormResult(
                                form, request.Content, false, [formError!], null, null, null));
                        }
                    }

                    LoadedPolicy candidate;
                    try
                    {
                        candidate = PolicyLoader.LoadYaml(editedYaml, "policy.yaml");
                    }
                    catch (Exception exception) when (exception is InvalidDataException or YamlException)
                    {
                        return Results.Ok(new PolicyFormResult(
                            request.Form ?? ToForm(baseline.Policy),
                            editedYaml,
                            false,
                            [exception.Message],
                            null,
                            null,
                            null));
                    }

                    PolicyFormDiff diff = ComputeDiff(baseline, candidate);
                    PolicySamplePreview preview = BuildRedactedPreview(baseline, candidate);
                    return Results.Ok(new PolicyFormResult(
                        ToForm(candidate.Policy),
                        editedYaml,
                        true,
                        [],
                        candidate.Hash,
                        diff,
                        preview));
                })
            .WithMetadata(new RequestSizeLimitAttribute(BodyLimit))
            .RequireAuthorization("Operate");
    }

    private static bool TryApplyForm(
        string originalYaml,
        PolicyForm form,
        out string updatedYaml,
        out string? error)
    {
        updatedYaml = originalYaml;
        error = null;

        if (string.IsNullOrWhiteSpace(form.Id) || form.Id.Length > 128
            || string.IsNullOrWhiteSpace(form.Name) || form.Name.Length > 200
            || string.IsNullOrWhiteSpace(form.Version) || form.Version.Length > 64
            || string.IsNullOrWhiteSpace(form.Owner) || form.Owner.Length > 200)
        {
            error = "Policy id, name, version and owner are required.";
            return false;
        }

        string action = (form.Action ?? string.Empty).Trim().ToLowerInvariant();
        if (action is not ("accept" or "redact-and-accept" or "quarantine" or "reject" or "aggregate"))
        {
            error = "Choose a supported decision action: accept, redact-and-accept, aggregate, quarantine or reject.";
            return false;
        }

        if (form.MinimumValueScore is < 0 or > 100)
        {
            error = "Minimum value score must be between 0 and 100.";
            return false;
        }

        string[] eventTypes = CleanList(form.EventTypes);
        if (eventTypes.Length == 0 || eventTypes.Length > 64)
        {
            error = "List between 1 and 64 event types.";
            return false;
        }

        YamlStream stream = new();
        stream.Load(new StringReader(originalYaml));
        YamlMappingNode root = (YamlMappingNode)stream.Documents[0].RootNode;

        YamlMappingNode metadata = EnsureMapping(root, "metadata");
        metadata.Children[new YamlScalarNode("id")] = Scalar(form.Id.Trim());
        metadata.Children[new YamlScalarNode("name")] = Scalar(form.Name.Trim());
        metadata.Children[new YamlScalarNode("version")] = Scalar(form.Version.Trim());
        metadata.Children[new YamlScalarNode("owner")] = Scalar(form.Owner.Trim());

        YamlMappingNode match = EnsureMapping(root, "match");
        match.Children[new YamlScalarNode("eventCategories")] = Sequence(CleanList(form.EventCategories));
        match.Children[new YamlScalarNode("eventTypes")] = Sequence(eventTypes);

        YamlMappingNode requirements = EnsureMapping(root, "requirements");
        requirements.Children[new YamlScalarNode("requiredFields")] = Sequence(CleanList(form.RequiredFields));
        requirements.Children[new YamlScalarNode("atLeastOne")] = Sequence(CleanList(form.AtLeastOne));
        requirements.Children[new YamlScalarNode("recommendedFields")] = Sequence(CleanList(form.RecommendedFields));

        YamlMappingNode decision = EnsureMapping(root, "decision");
        decision.Children[new YamlScalarNode("action")] = Scalar(action);
        decision.Children[new YamlScalarNode("minimumValueScore")] =
            new YamlScalarNode(form.MinimumValueScore.ToString(CultureInfo.InvariantCulture));
        decision.Children[new YamlScalarNode("neverSample")] =
            new YamlScalarNode(form.NeverSample ? "true" : "false");

        YamlScalarNode suppressionKey = new("suppression");
        if (form.Suppression is { Enabled: true } suppression)
        {
            string[] keyFields = CleanList(suppression.KeyFields);
            YamlMappingNode suppressionNode = new()
            {
                { "keyFields", Sequence(keyFields) },
                { "windowSeconds", new YamlScalarNode(suppression.WindowSeconds.ToString(CultureInfo.InvariantCulture)) },
                { "allowPerWindow", new YamlScalarNode(suppression.AllowPerWindow.ToString(CultureInfo.InvariantCulture)) }
            };
            root.Children[suppressionKey] = suppressionNode;
        }
        else
        {
            root.Children.Remove(suppressionKey);
        }

        using StringWriter writer = new(CultureInfo.InvariantCulture);
        stream.Save(writer, assignAnchors: false);
        updatedYaml = writer.ToString();
        return true;
    }

    private static PolicyForm ToForm(TelemetryPolicy policy) => new(
        policy.Metadata.Id,
        policy.Metadata.Name,
        policy.Metadata.Version,
        policy.Metadata.Owner,
        policy.Match.EventCategories,
        policy.Match.EventTypes,
        policy.Requirements.RequiredFields,
        policy.Requirements.AtLeastOne,
        policy.Requirements.RecommendedFields,
        policy.Decision.Action,
        policy.Decision.MinimumValueScore,
        policy.Decision.NeverSample,
        policy.Suppression is null
            ? new PolicySuppressionForm(false, ["application.name", "eventType", "source.ipAddress"], 60, 0)
            : new PolicySuppressionForm(
                true,
                policy.Suppression.KeyFields,
                policy.Suppression.WindowSeconds,
                policy.Suppression.AllowPerWindow));

    private static PolicyFormDiff ComputeDiff(LoadedPolicy before, LoadedPolicy after)
    {
        List<PolicyDiffEntry> changes = [];
        TelemetryPolicy a = before.Policy;
        TelemetryPolicy b = after.Policy;

        foreach (string added in b.Match.EventTypes.Except(a.Match.EventTypes, StringComparer.Ordinal))
        {
            changes.Add(new("event-type-added", $"Now accepts event type '{added}'."));
        }

        foreach (string removed in a.Match.EventTypes.Except(b.Match.EventTypes, StringComparer.Ordinal))
        {
            changes.Add(new("event-type-removed", $"No longer accepts event type '{removed}' (falls back to default-deny)."));
        }

        foreach (string added in b.Requirements.RequiredFields.Except(a.Requirements.RequiredFields, StringComparer.Ordinal))
        {
            changes.Add(new("required-field-added", $"Requires '{added}' (events without it will be quarantined)."));
        }

        foreach (string removed in a.Requirements.RequiredFields.Except(b.Requirements.RequiredFields, StringComparer.Ordinal))
        {
            changes.Add(new("required-field-removed", $"No longer requires '{removed}'."));
        }

        if (!string.Equals(a.Decision.Action, b.Decision.Action, StringComparison.OrdinalIgnoreCase))
        {
            changes.Add(new("action-changed", $"Decision action changes from {a.Decision.Action} to {b.Decision.Action}."));
        }

        if (a.Decision.MinimumValueScore != b.Decision.MinimumValueScore)
        {
            changes.Add(new("minimum-score-changed", $"Minimum value score changes from {a.Decision.MinimumValueScore} to {b.Decision.MinimumValueScore}."));
        }

        if (a.Decision.NeverSample != b.Decision.NeverSample)
        {
            changes.Add(new("never-sample-changed", $"neverSample changes from {a.Decision.NeverSample} to {b.Decision.NeverSample}."));
        }

        string beforeSup = FormatSuppression(a.Suppression);
        string afterSup = FormatSuppression(b.Suppression);
        if (!string.Equals(beforeSup, afterSup, StringComparison.Ordinal))
        {
            changes.Add(new("suppression-changed", $"Suppression changes from {beforeSup} to {afterSup}."));
        }

        if (string.Equals(a.Metadata.Version, b.Metadata.Version, StringComparison.Ordinal)
            && !string.Equals(before.Hash, after.Hash, StringComparison.Ordinal))
        {
            changes.Add(new("version-not-bumped", "Policy rules changed without bumping metadata.version."));
        }

        return new PolicyFormDiff(
            before.Hash,
            after.Hash,
            string.Equals(before.Hash, after.Hash, StringComparison.Ordinal),
            changes);
    }

    private static PolicySamplePreview BuildRedactedPreview(LoadedPolicy before, LoadedPolicy after)
    {
        string sampleEventType = after.Policy.Match.EventTypes.FirstOrDefault() ?? "authentication_failure";
        string sampleCategory = after.Policy.Match.EventCategories.FirstOrDefault() ?? "authentication";
        string syntheticRaw = BuildSyntheticSampleJson(sampleCategory, sampleEventType);

        // Always enforce Bower's built-in privacy protection before showing any preview.
        PrivacyScanResult scan = new PrivacyEngine(PrivacyPolicy.CreateDefault()).RedactJson(syntheticRaw);
        if (!scan.Succeeded || scan.RedactedJson is null)
        {
            return new PolicySamplePreview(false, "quarantine", "quarantine", 0, null, []);
        }

        SecurityEventEnvelope envelope = JsonSerializer.Deserialize(scan.RedactedJson, BowerJson.Envelope)!;
        PolicyDecision beforeDecision = new DeterministicPolicyEvaluator([before]).Evaluate(envelope);
        PolicyDecision afterDecision = new DeterministicPolicyEvaluator([after]).Evaluate(envelope);

        PolicyPreviewFinding[] findings = scan.Findings
            .Select(finding => new PolicyPreviewFinding(finding.DetectorId, finding.Action.ToString(), finding.Path))
            .ToArray();

        return new PolicySamplePreview(
            true,
            FormatPreviewDecision(beforeDecision),
            FormatPreviewDecision(afterDecision),
            afterDecision.Score,
            scan.RedactedJson,
            findings);
    }

    private static string FormatPreviewDecision(PolicyDecision decision) =>
        decision.Action == DecisionAction.Accept && decision.Suppression is { AllowPerWindow: 0 }
            ? "aggregate"
            : decision.Action switch
            {
                DecisionAction.RedactAndAccept => "redact-and-accept",
                _ => decision.Action.ToString().ToLowerInvariant()
            };

    private static string BuildSyntheticSampleJson(string category, string eventType)
    {
        StringBuilder json = new();
        json.Append('{');
        json.Append("\"schemaVersion\":\"1.0\",");
        json.Append("\"eventId\":\"00000000-0000-4000-8000-000000000001\",");
        json.Append("\"timeGenerated\":\"2026-11-22T00:00:00Z\",");
        json.Append("\"eventCategory\":").Append(JsonSerializer.Serialize(category, ManagementJsonContext.Default.String)).Append(',');
        json.Append("\"eventType\":").Append(JsonSerializer.Serialize(eventType, ManagementJsonContext.Default.String)).Append(',');
        json.Append("\"eventAction\":\"synthetic.check\",");
        json.Append("\"eventResult\":\"failure\",");
        json.Append("\"eventOutcomeReason\":\"synthetic_sample\",");
        json.Append("\"severity\":\"medium\",");
        json.Append("\"application\":{\"name\":\"sample-app\",\"environment\":\"production\"},");
        json.Append("\"actor\":{\"userId\":\"usr-42\",\"username\":\"alex.example@example.com\"},");
        json.Append("\"source\":{\"ipAddress\":\"192.0.2.10\"},");
        json.Append("\"request\":{\"correlationId\":\"corr-synthetic-001\"},");
        json.Append("\"attributes\":{\"password\":\"synthetic-secret-value\",\"tfn\":\"123456782\",\"note\":\"Synthetic preview only\"}");
        json.Append('}');
        return json.ToString();
    }

    private static string FormatSuppression(PolicySuppression? suppression) =>
        suppression is null
            ? "none"
            : $"allow {suppression.AllowPerWindow} per {suppression.WindowSeconds}s keyed by [{string.Join(", ", suppression.KeyFields)}]";

    private static string[] CleanList(IReadOnlyList<string>? values) =>
        values is null
            ? []
            : values.Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

    private static YamlMappingNode EnsureMapping(YamlMappingNode parent, string key)
    {
        YamlScalarNode keyNode = new(key);
        if (parent.Children.TryGetValue(keyNode, out YamlNode? existing) && existing is YamlMappingNode mapping)
        {
            return mapping;
        }

        YamlMappingNode created = new();
        parent.Children[keyNode] = created;
        return created;
    }

    private static YamlScalarNode Scalar(string value) => new(value);

    private static YamlSequenceNode Sequence(IEnumerable<string> items)
    {
        YamlSequenceNode node = new();
        foreach (string item in items)
        {
            node.Add(new YamlScalarNode(item));
        }

        return node;
    }
}

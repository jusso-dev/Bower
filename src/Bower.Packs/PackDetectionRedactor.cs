using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Detection;

namespace Bower.Packs;

/// <summary>Local detection on selected, redacted semantic events. Evidence travels in the same durable row.</summary>
public sealed class PackDetectionRedactor(
    IEventRedactor inner,
    ITelemetryPolicyEvaluator policies,
    IReadOnlyList<DetectionRule> rules) : IEventRedactor
{
    public const string EvidenceAttribute = "bowerDetections";

    public RedactionResult Redact(string json)
    {
        RedactionResult result = inner.Redact(json);
        if (!result.Succeeded || result.RedactedJson is null)
        {
            return result;
        }

        try
        {
            SecurityEventEnvelope envelope = JsonSerializer.Deserialize(result.RedactedJson, BowerJson.Envelope)
                ?? throw new JsonException();
            Dictionary<string, JsonElement> attributes = new(envelope.Attributes ?? new Dictionary<string, JsonElement>(), StringComparer.Ordinal);
            // Producers cannot forge local engine evidence. Also strip it when no rules are active.
            foreach (string key in attributes.Keys.Where(key => key.Equals(EvidenceAttribute, StringComparison.OrdinalIgnoreCase)).ToArray())
            {
                attributes.Remove(key);
            }
            envelope = envelope with { Attributes = attributes.Count == 0 ? null : attributes };
            if (rules.Count > 0 && policies.Evaluate(envelope).Action is DecisionAction.Accept or DecisionAction.RedactAndAccept)
            {
                DetectionEvidence[] evidence = new DetectionEngine(rules).Evaluate(envelope).Alerts
                    .Select(alert => new DetectionEvidence(alert.RuleId, alert.RuleVersion, alert.RuleHash, alert.MitreTechniques))
                    .OrderBy(item => item.RuleId, StringComparer.Ordinal).ToArray();
                if (evidence.Length > 0)
                {
                    attributes[EvidenceAttribute] = JsonSerializer.SerializeToElement(evidence, DetectionEvidenceJson.Default.DetectionEvidenceArray);
                    envelope = envelope with { Attributes = attributes };
                }
            }

            return result with { RedactedJson = JsonSerializer.Serialize(envelope, BowerJson.Envelope) };
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
        {
            return new RedactionResult(false, null, [], [], "pack-detection-failed");
        }
    }
}

internal sealed record DetectionEvidence(string RuleId, string RuleVersion, string RuleHash, IReadOnlyList<string> MitreTechniques);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(DetectionEvidence[]))]
internal sealed partial class DetectionEvidenceJson : JsonSerializerContext;

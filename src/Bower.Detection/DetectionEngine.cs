using System.Text.Json;
using Bower.Contracts;

namespace Bower.Detection;

public sealed class DetectionEngine
{
    private readonly System.Collections.ObjectModel.ReadOnlyCollection<DetectionRule> rules;
    private readonly HashSet<string> suppressedRuleIds;
    private const int MaximumFingerprints = 4096;
    private readonly HashSet<string> seenFingerprints = new(StringComparer.Ordinal);
    private readonly Queue<string> fingerprintOrder = new();
    private readonly object gate = new();
    private readonly DetectionSemantics[] semantics;

    private readonly TimeProvider clock;

    public DetectionEngine(
        IEnumerable<DetectionRule> rules,
        IEnumerable<string>? suppressedRuleIds = null,
        TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        this.rules = Array.AsReadOnly(rules.ToArray());
        semantics = this.rules.Select(rule => new DetectionSemantics(rule.DetectionFields, rule.Condition)).ToArray();
        this.suppressedRuleIds = new HashSet<string>(
            suppressedRuleIds ?? [],
            StringComparer.OrdinalIgnoreCase);
    }

    public static DetectionEngine FromDirectory(
        string directory,
        IEnumerable<string>? suppressedRuleIds = null)
    {
        return new DetectionEngine(SigmaRuleLoader.LoadDirectory(directory), suppressedRuleIds);
    }

    public IReadOnlyList<DetectionRule> Rules => rules;

    public DetectionEvaluationResult Evaluate(SecurityEventEnvelope envelope, DateTimeOffset? now = null)
    {
        lock (gate)
        {
            return EvaluateLocked(envelope, now);
        }
    }

    private DetectionEvaluationResult EvaluateLocked(SecurityEventEnvelope envelope, DateTimeOffset? now)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        DateTimeOffset detectedAt = now ?? clock.GetUtcNow();
        List<DetectionAlert> alerts = [];
        List<string> suppressed = [];

        if (envelope.Labels?.Count > 256 || envelope.Attributes?.Count > 256) { return new DetectionEvaluationResult([], []); }
        if (envelope.Labels is not null && envelope.Labels.Keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() != envelope.Labels.Count
            || envelope.Attributes is not null && envelope.Attributes.Keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() != envelope.Attributes.Count)
        {
            return new DetectionEvaluationResult([], []);
        }
        Dictionary<string, string> haystack = BuildHaystack(envelope);
        if (haystack.Any(pair => pair.Key.Length > 128 || pair.Value.Length > 65538))
        {
            return new DetectionEvaluationResult([], []);
        }
        for (int index = 0; index < rules.Count; index++)
        {
            DetectionRule rule = rules[index];
            if (suppressedRuleIds.Contains(rule.Id))
            {
                suppressed.Add(rule.Id);
                continue;
            }

            if (!semantics[index].Matches(haystack, out List<string> matchedFields))
            {
                continue;
            }

            string fingerprint = Fingerprint(rule, envelope.EventId);
            if (!seenFingerprints.Add(fingerprint))
            {
                continue;
            }

            fingerprintOrder.Enqueue(fingerprint);
            if (fingerprintOrder.Count > MaximumFingerprints) { seenFingerprints.Remove(fingerprintOrder.Dequeue()); }

            alerts.Add(
                new DetectionAlert(
                    Guid.CreateVersion7().ToString(),
                    rule.Id,
                    rule.Title,
                    rule.Version,
                    rule.RuleHash,
                    rule.Level,
                    RiskScore(rule.Level),
                    detectedAt,
                    envelope.EventId,
                    envelope.EventType,
                    envelope.Actor?.Username ?? envelope.Actor?.UserId,
                    envelope.Source?.IpAddress,
                    rule.MitreTechniques,
                    matchedFields,
                    $"{rule.Title} matched event {envelope.EventType} ({envelope.EventAction})"));
        }

        return new DetectionEvaluationResult(alerts, suppressed.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    public DetectionEvaluationResult EvaluateJson(string eventJson, DateTimeOffset? now = null)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(eventJson) > 1024 * 1024) { throw DetectionSemantics.Invalid(); }
        SecurityEventEnvelope? envelope = JsonSerializer.Deserialize(eventJson, BowerJson.Envelope);
        if (envelope is null)
        {
            throw new InvalidDataException("Event JSON did not deserialize to SecurityEventEnvelope.");
        }

        return Evaluate(envelope, now);
    }

    private static string Fingerprint(DetectionRule rule, string eventId)
    {
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (string value in new[] { rule.Id, eventId, rule.RuleHash })
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static Dictionary<string, string> BuildHaystack(SecurityEventEnvelope envelope)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase)
        {
            ["EventType"] = envelope.EventType,
            ["EventAction"] = envelope.EventAction,
            ["EventCategory"] = envelope.EventCategory,
            ["EventResult"] = envelope.EventResult.ToString(),
            ["EventOutcomeReason"] = envelope.EventOutcomeReason ?? string.Empty,
            ["ActorUsername"] = envelope.Actor?.Username ?? string.Empty,
            ["ActorUserId"] = envelope.Actor?.UserId ?? string.Empty,
            ["SourceIp"] = envelope.Source?.IpAddress ?? string.Empty,
            ["TargetName"] = envelope.Target?.Name ?? string.Empty,
            ["TargetType"] = envelope.Target?.Type ?? string.Empty,
            ["Application"] = envelope.Application.Name
        };

        if (envelope.Labels is not null)
        {
            foreach ((string key, string value) in envelope.Labels)
            {
                if (!key.StartsWith("attributes.", StringComparison.OrdinalIgnoreCase)) { values.TryAdd(key, value); }
            }
        }

        foreach (string key in values.Keys.ToArray()) { values[key] = "s:" + values[key]; }
        // Attributes use an explicit namespace and retain their JSON scalar type.
        // Label keys cannot shadow typed attributes.
        if (envelope.Attributes is not null)
        {
            foreach ((string key, JsonElement value) in envelope.Attributes)
            {
                string field = "attributes." + key;
                values.Remove(field);
                string? scalar = value.ValueKind switch
                {
                    JsonValueKind.String => "s:" + value.GetString(),
                    JsonValueKind.True => "b:true",
                    JsonValueKind.False => "b:false",
                    JsonValueKind.Number when value.TryGetInt64(out long number) => "n:" + number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    _ => null
                };
                if (scalar is not null) { values[field] = scalar; }
            }
        }
        return values;
    }

    private static int RiskScore(string level)
    {
        return level.ToLowerInvariant() switch
        {
            "informational" => 10,
            "low" => 25,
            "medium" => 50,
            "high" => 75,
            "critical" => 95,
            _ => 40
        };
    }
}

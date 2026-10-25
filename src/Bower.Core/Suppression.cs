using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;

namespace Bower.Core;

/// <summary>
/// Suppression key and summary event construction. Both are pure functions of their inputs
/// so every runtime derives the same key hash, event id and fingerprint.
/// </summary>
public static class Suppression
{
    public const string SummaryAction = "telemetry.suppressed";
    public const string SummarySourceAdapter = "suppression";

    public static SuppressionRequest CreateRequest(
        SecurityEventEnvelope arranged,
        PolicyDecision decision,
        SuppressionDirective directive)
    {
        ArgumentNullException.ThrowIfNull(arranged);
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(directive);

        List<string> parts =
        [
            "bower-suppression-v1",
            decision.PolicyId,
            arranged.Application.Name,
            arranged.Application.Environment,
            arranged.Application.TenantId ?? string.Empty,
            arranged.EventType
        ];
        for (int index = 0; index < directive.KeyFields.Count; index++)
        {
            parts.Add(directive.KeyFields[index]);
            parts.Add(directive.KeyValues[index]);
        }

        return new SuppressionRequest(
            decision.PolicyId,
            decision.PolicyVersion,
            decision.PolicyHash,
            FramedHash(parts),
            directive.KeyFields,
            directive.KeyValues,
            directive.WindowSeconds,
            directive.AllowPerWindow,
            arranged.EventCategory,
            arranged.EventType,
            arranged.Application.Name,
            arranged.Application.Environment,
            arranged.Application.TenantId);
    }

    /// <summary>
    /// Summary for a closed window, before policy evaluation. Ids and times derive from the
    /// window row, so a retried close cannot create a second summary.
    /// </summary>
    public static SecurityEventEnvelope CreateSummary(
        SuppressionWindow window,
        CollectorIdentity collector,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(collector);

        SuppressionRequest rule = window.Rule;
        string windowStart = Seconds(window.WindowStart);
        // The first suppressed time distinguishes a window recreated after the host clock
        // stepped back from the one already summarised; a retried close keeps the same id.
        string firstSuppressed = window.FirstSuppressedAt?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
            ?? string.Empty;
        string eventId = "suppression-" + FramedHash(
            ["bower-suppression-summary-v1", rule.PolicyId, rule.KeyHash, windowStart, firstSuppressed])[..32];

        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            TimeGenerated = window.WindowEnd,
            TimeObserved = window.WindowEnd,
            EventCategory = rule.EventCategory,
            EventType = SecurityEventTypes.TelemetryAggregationSummary,
            EventAction = SummaryAction,
            EventResult = EventResult.Success,
            EventSeverity = EventSeverity.Medium,
            EventOutcomeReason = string.Create(
                CultureInfo.InvariantCulture,
                $"{window.Suppressed} {rule.EventType} event(s) beyond {rule.AllowPerWindow} per {rule.WindowSeconds}s"),
            Application = new ApplicationContext
            {
                Name = rule.Application,
                Environment = rule.Environment,
                TenantId = rule.TenantId
            },
            Actor = new ActorContext
            {
                Type = ActorType.System,
                Username = "bower.suppression",
                DisplayName = "Bower suppression"
            },
            Target = new TargetContext
            {
                Type = "telemetry_event_type",
                Id = rule.EventType,
                Name = rule.PolicyId
            },
            Request = new RequestContext { CorrelationId = eventId },
            Labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["suppressedEventType"] = rule.EventType,
                ["suppressionPolicyId"] = rule.PolicyId,
                ["suppressionKeyHash"] = rule.KeyHash
            },
            Attributes = SummaryAttributes(window),
            Collector = new CollectorContext
            {
                Id = collector.Id,
                Version = collector.Version,
                SourceAdapter = SummarySourceAdapter,
                ConfigurationHash = collector.ConfigurationHash,
                ReceivedAt = now
            }
        };
    }

    private static Dictionary<string, JsonElement> SummaryAttributes(SuppressionWindow window)
    {
        SuppressionRequest rule = window.Rule;
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("suppressedCount", window.Suppressed);
            writer.WriteNumber("admittedCount", window.Admitted);
            writer.WriteNumber("allowPerWindow", rule.AllowPerWindow);
            writer.WriteNumber("windowSeconds", rule.WindowSeconds);
            writer.WriteString("windowStart", Seconds(window.WindowStart));
            writer.WriteString("windowEnd", Seconds(window.WindowEnd));
            WriteTime(writer, "firstSuppressedAt", window.FirstSuppressedAt);
            WriteTime(writer, "lastSuppressedAt", window.LastSuppressedAt);
            writer.WriteStartObject("suppressionKey");
            for (int index = 0; index < rule.KeyFields.Count; index++)
            {
                writer.WriteString(rule.KeyFields[index], rule.KeyValues[index]);
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        using JsonDocument document = JsonDocument.Parse(stream.ToArray());
        Dictionary<string, JsonElement> attributes = new(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            attributes[property.Name] = property.Value.Clone();
        }

        return attributes;
    }

    private static void WriteTime(Utf8JsonWriter writer, string name, DateTimeOffset? value)
    {
        if (value is { } time)
        {
            writer.WriteString(name, time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        }
        else
        {
            writer.WriteNull(name);
        }
    }

    private static string Seconds(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Length-framed SHA-256 (as <c>EventIdentity</c>), lower-case hex.</summary>
    private static string FramedHash(IEnumerable<string> parts)
    {
        string material = string.Concat(parts.Select(part =>
            Encoding.UTF8.GetByteCount(part).ToString(CultureInfo.InvariantCulture) + ":" + part));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }
}

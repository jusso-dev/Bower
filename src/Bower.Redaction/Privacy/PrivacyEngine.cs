using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;

namespace Bower.Redaction.Privacy;

/// <summary>
/// High-performance privacy &amp; secret protection engine.
/// Operates after parse / before persistence and normalisation.
/// Deterministic: regex, checksum, structure — no AI at runtime.
/// </summary>
public sealed class PrivacyEngine : IEventRedactor
{
    public const int MaximumPayloadBytes = 1_048_576;

    private readonly PrivacyPolicy policy;
    private readonly IReadOnlyList<ISensitiveDetector> detectors;
    private readonly IFieldNameDetector fieldNameDetector;
    private readonly PolicyApplicator applicator;

    public PrivacyEngine(
        PrivacyPolicy? policy = null,
        IEnumerable<ISensitiveDetector>? detectors = null,
        IFieldNameDetector? fieldNameDetector = null)
    {
        this.policy = policy ?? PrivacyPolicy.CreateDefault();
        this.detectors = (detectors ?? DetectorCatalog.CreateDefaultValueDetectors()).ToArray();
        this.fieldNameDetector = fieldNameDetector ?? DetectorCatalog.CreateDefaultFieldNameDetector();
        applicator = new PolicyApplicator(this.policy);
    }

    public PrivacyPolicy Policy => policy;

    public IReadOnlyList<ISensitiveDetector> Detectors => detectors;

    public RedactionResult Redact(string json) => RedactJson(json).ToRedactionResult();

    /// <summary>
    /// Detector ids that warrant a first-class SOC security event when observed.
    /// High-risk regulated AU identifiers, secrets and crypto — not routine email mask noise.
    /// </summary>
    public static bool IsSecurityEventWorthy(string detectorId)
    {
        if (string.IsNullOrEmpty(detectorId))
        {
            return false;
        }

        // SubKind suffixes appear as "secret.api-key:OpenAI" in metadata Detected list.
        string root = detectorId;
        int colon = detectorId.IndexOf(':', StringComparison.Ordinal);
        if (colon > 0)
        {
            root = detectorId[..colon];
        }

        return root is DetectorIds.FieldNameSecret
            or DetectorIds.Tfn
            or DetectorIds.Crn
            or DetectorIds.Medicare
            or DetectorIds.Ihi
            or DetectorIds.Passport
            or DetectorIds.DriverLicence
            or DetectorIds.Dva
            or DetectorIds.CreditCard
            or DetectorIds.BsbAccount
            or DetectorIds.Iban
            or DetectorIds.PayId
            or DetectorIds.Aws
            or DetectorIds.Azure
            or DetectorIds.Entra
            or DetectorIds.Gcp
            or DetectorIds.Jwt
            or DetectorIds.OAuth
            or DetectorIds.ApiKey
            or DetectorIds.Kubernetes
            or DetectorIds.Docker
            or DetectorIds.Database
            or DetectorIds.EnvVar
            or DetectorIds.CryptoMaterial
            or DetectorIds.SecurityMarking;
    }

    public PrivacyScanResult RedactJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return PrivacyScanResult.Fail("empty-payload");
        }

        if (Encoding.UTF8.GetByteCount(json) > MaximumPayloadBytes)
        {
            return PrivacyScanResult.Fail("payload-too-large");
        }

        try
        {
            JsonNode? root = JsonNode.Parse(
                json,
                documentOptions: new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });

            if (root is not JsonObject rootObject)
            {
                return PrivacyScanResult.Fail("root-must-be-object");
            }

            List<AppliedFinding> findings = [];
            WalkObject(rootObject, "$", findings);

            PrivacyMetadata metadata = BuildMetadata(findings);
            if (policy.EmitMetadata && metadata.HasFindings)
            {
                rootObject["privacy"] = MetadataToNode(metadata);
            }

            List<string> removed = findings
                .Where(f => f.Action is PrivacyAction.Remove)
                .Select(f => f.Path)
                .Distinct(StringComparer.Ordinal)
                .ToList();
            List<string> masked = findings
                .Where(f => f.Action is PrivacyAction.Mask or PrivacyAction.Sha256
                    or PrivacyAction.Hmac or PrivacyAction.Encrypt or PrivacyAction.Replace)
                .Select(f => f.Path)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            return new PrivacyScanResult(
                true,
                rootObject.ToJsonString(),
                findings,
                metadata,
                removed,
                masked,
                null);
        }
        catch (JsonException)
        {
            return PrivacyScanResult.Fail("invalid-json");
        }
    }

    /// <summary>Scan and sanitise a raw text payload (syslog, CSV cell, etc.).</summary>
    public PrivacyTextResult RedactText(string text)
    {
        if (text is null)
        {
            return new PrivacyTextResult(false, null, [], PrivacyMetadata.Empty, "empty-payload");
        }

        if (Encoding.UTF8.GetByteCount(text) > MaximumPayloadBytes)
        {
            return new PrivacyTextResult(false, null, [], PrivacyMetadata.Empty, "payload-too-large");
        }

        List<AppliedFinding> findings = [];
        string redacted = ApplyDetectorsToValue(text, "$", findings);
        PrivacyMetadata metadata = BuildMetadata(findings);
        return new PrivacyTextResult(true, redacted, findings, metadata, null);
    }

    private void WalkObject(JsonObject value, string parentPath, List<AppliedFinding> findings)
    {
        foreach ((string propertyName, JsonNode? child) in value.ToArray())
        {
            string path = $"{parentPath}.{propertyName}";
            string normalized = NormalizeFieldName(propertyName);

            if (policy.IsDetectorEnabled(fieldNameDetector.Id) &&
                fieldNameDetector.MatchesFieldName(normalized))
            {
                PrivacyAction action = policy.ResolveAction(fieldNameDetector.Id);
                findings.Add(new AppliedFinding(
                    fieldNameDetector.Id,
                    fieldNameDetector.Category,
                    path,
                    action,
                    Validated: true,
                    SubKind: null));

                if (action is not (PrivacyAction.Allow or PrivacyAction.AlertOnly))
                {
                    value.Remove(propertyName);
                }

                continue;
            }

            if (child is JsonValue jsonValue && jsonValue.TryGetValue(out string? text) && text is not null)
            {
                string redacted = ApplyDetectorsToValue(text, path, findings);
                if (!ReferenceEquals(redacted, text) && redacted != text)
                {
                    value[propertyName] = redacted;
                }

                continue;
            }

            if (child is JsonObject childObject)
            {
                WalkObject(childObject, path, findings);
            }
            else if (child is JsonArray array)
            {
                WalkArray(array, path, findings);
            }
        }
    }

    private void WalkArray(JsonArray array, string path, List<AppliedFinding> findings)
    {
        for (int index = 0; index < array.Count; index++)
        {
            string itemPath = $"{path}[{index}]";
            if (array[index] is JsonObject nested)
            {
                WalkObject(nested, itemPath, findings);
            }
            else if (array[index] is JsonValue arrayValue &&
                     arrayValue.TryGetValue(out string? arrayText) &&
                     arrayText is not null)
            {
                string redacted = ApplyDetectorsToValue(arrayText, itemPath, findings);
                if (redacted != arrayText)
                {
                    array[index] = redacted;
                }
            }
        }
    }

    private string ApplyDetectorsToValue(string text, string path, List<AppliedFinding> findings)
    {
        List<DetectionMatch> matches = [];
        ReadOnlySpan<char> span = text.AsSpan();
        foreach (ISensitiveDetector detector in detectors)
        {
            if (!policy.IsDetectorEnabled(detector.Id))
            {
                continue;
            }

            detector.Detect(span, path, matches);
        }

        if (matches.Count == 0)
        {
            return text;
        }

        // Resolve overlaps: prefer longer validated matches, then earlier start.
        List<DetectionMatch> ordered = matches
            .OrderByDescending(m => m.Length)
            .ThenBy(m => m.Start)
            .ToList();

        List<DetectionMatch> selected = [];
        foreach (DetectionMatch candidate in ordered)
        {
            if (selected.Any(existing => Overlaps(existing, candidate)))
            {
                continue;
            }

            selected.Add(candidate);
        }

        // Apply right-to-left so indices remain valid.
        selected.Sort((a, b) => b.Start.CompareTo(a.Start));
        string result = text;
        foreach (DetectionMatch match in selected)
        {
            PrivacyAction action = policy.ResolveAction(match.DetectorId);
            findings.Add(new AppliedFinding(
                match.DetectorId,
                match.Category,
                path,
                action,
                match.Validated,
                match.SubKind));

            if (action is PrivacyAction.Allow or PrivacyAction.AlertOnly)
            {
                continue;
            }

            string replacement = applicator.Apply(result, match, action);
            result = string.Concat(
                result.AsSpan(0, match.Start),
                replacement,
                result.AsSpan(match.End));
        }

        return result;
    }

    private static bool Overlaps(DetectionMatch a, DetectionMatch b) =>
        a.Start < b.End && b.Start < a.End;

    private static PrivacyMetadata BuildMetadata(List<AppliedFinding> findings)
    {
        if (findings.Count == 0)
        {
            return PrivacyMetadata.Empty;
        }

        List<string> detected = findings
            .Select(f => f.SubKind is null ? f.DetectorId : $"{f.DetectorId}:{f.SubKind}")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        Dictionary<string, string> actions = new(StringComparer.Ordinal);
        foreach (AppliedFinding finding in findings)
        {
            string key = finding.DetectorId;
            string label = PolicyApplicator.ActionLabel(finding.Action);
            if (!actions.ContainsKey(key))
            {
                actions[key] = label;
            }
        }

        return new PrivacyMetadata(detected, actions);
    }

    private static JsonObject MetadataToNode(PrivacyMetadata metadata)
    {
        JsonArray detected = new();
        foreach (string id in metadata.Detected)
        {
            detected.Add(id);
        }

        JsonObject actions = new();
        foreach ((string key, string value) in metadata.Actions)
        {
            actions[key] = value;
        }

        return new JsonObject
        {
            ["detected"] = detected,
            ["actions"] = actions
        };
    }

    private static string NormalizeFieldName(string value) =>
        string.Concat(value.Where(char.IsLetterOrDigit)).ToLowerInvariant();
}

public sealed record AppliedFinding(
    string DetectorId,
    string Category,
    string Path,
    PrivacyAction Action,
    bool Validated,
    string? SubKind);

public sealed record PrivacyScanResult(
    bool Succeeded,
    string? RedactedJson,
    IReadOnlyList<AppliedFinding> Findings,
    PrivacyMetadata Metadata,
    IReadOnlyList<string> RemovedPaths,
    IReadOnlyList<string> MaskedPaths,
    string? FailureCode)
{
    public static PrivacyScanResult Fail(string code) =>
        new(false, null, [], PrivacyMetadata.Empty, [], [], code);

    public RedactionResult ToRedactionResult() =>
        new(
            Succeeded,
            RedactedJson,
            RemovedPaths,
            MaskedPaths,
            FailureCode,
            Metadata.Detected,
            Metadata.Actions);
}

public sealed record PrivacyTextResult(
    bool Succeeded,
    string? RedactedText,
    IReadOnlyList<AppliedFinding> Findings,
    PrivacyMetadata Metadata,
    string? FailureCode);

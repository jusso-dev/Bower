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
public sealed partial class PrivacyEngine : IEventRedactor
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
        applicator = new PolicyApplicator(this.policy);
        // Defaults follow the policy: built-ins plus its custom detectors, and the
        // field-name detector extended with its secret field names. Explicit detectors
        // are used as given.
        this.detectors = (detectors ?? DetectorCatalog.CreateValueDetectors(this.policy)).ToArray();
        this.fieldNameDetector = fieldNameDetector ?? DetectorCatalog.CreateFieldNameDetector(this.policy);
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
            SanitizeChange(rootObject, findings);
            WalkObject(rootObject, "$", findings);
            ApplyFieldRules(rootObject, findings);
            EnforceFieldLength(rootObject, "$", findings);

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
                    or PrivacyAction.Hmac or PrivacyAction.Encrypt or PrivacyAction.Replace
                    or PrivacyAction.Truncate)
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
        catch (Exception)
        {
            // Detector timeouts, malformed structures (for example duplicate keys) and any
            // other failure are security failures: the payload must be quarantined, never
            // persisted, and the caller must never see an exception instead of a verdict.
            return PrivacyScanResult.Fail("redaction-failed");
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

        try
        {
            List<AppliedFinding> findings = [];
            string redacted = ApplyDetectorsToValue(text, "$", findings);
            PrivacyMetadata metadata = BuildMetadata(findings);
            return new PrivacyTextResult(true, redacted, findings, metadata, null);
        }
        catch (Exception)
        {
            // Same contract as RedactJson: quarantine, never throw or return the original.
            return new PrivacyTextResult(false, null, [], PrivacyMetadata.Empty, "redaction-failed");
        }
    }

    private void WalkObject(JsonObject value, string parentPath, List<AppliedFinding> findings)
    {
        int redactedKeyIndex = 0;
        string keyPath = $"{parentPath}.[key]";
        foreach ((string originalName, JsonNode? originalChild) in value.ToArray())
        {
            string propertyName = originalName;
            JsonNode? child = originalChild;
            string normalized = NormalizeFieldName(propertyName);

            if (policy.IsDetectorEnabled(fieldNameDetector.Id) &&
                fieldNameDetector.MatchesFieldName(normalized))
            {
                PrivacyAction action = policy.ResolveAction(fieldNameDetector.Id);
                findings.Add(new AppliedFinding(
                    fieldNameDetector.Id,
                    fieldNameDetector.Category,
                    $"{parentPath}.{propertyName}",
                    action,
                    Validated: true,
                    SubKind: null));

                if (action is not (PrivacyAction.Allow or PrivacyAction.AlertOnly))
                {
                    value.Remove(propertyName);
                }

                continue;
            }

            // Property names are attacker-controlled too: scan them with value detectors and
            // rename the property when a key carries sensitive data.
            string redactedName = ApplyDetectorsToValue(
                propertyName,
                keyPath,
                findings);
            if (!string.Equals(redactedName, propertyName, StringComparison.Ordinal))
            {
                // Compare names as they will be written: System.Text.Json writes every
                // unpaired surrogate as U+FFFD, so two names differing only there would
                // otherwise both survive and serialise as duplicate keys.
                redactedName = ReplaceUnpairedSurrogates(redactedName);
                value.Remove(propertyName);
                do
                {
                    redactedName = string.IsNullOrEmpty(redactedName) || value.ContainsKey(redactedName)
                        ? $"redacted-key-{++redactedKeyIndex}"
                        : redactedName;
                }
                while (value.ContainsKey(redactedName));

                value[redactedName] = child;
                propertyName = redactedName;
            }

            string path = $"{parentPath}.{propertyName}";
            if (child is JsonValue jsonValue && TryGetScannableText(jsonValue, out string? text))
            {
                string redacted = ApplyDetectorsToValue(text, path, findings);
                if (!string.Equals(redacted, text, StringComparison.Ordinal))
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
            else if (array[index] is JsonArray nestedArray)
            {
                WalkArray(nestedArray, itemPath, findings);
            }
            else if (array[index] is JsonValue arrayValue &&
                     TryGetScannableText(arrayValue, out string? arrayText))
            {
                string redacted = ApplyDetectorsToValue(arrayText, itemPath, findings);
                if (!string.Equals(redacted, arrayText, StringComparison.Ordinal))
                {
                    array[index] = redacted;
                }
            }
        }
    }

    /// <summary>
    /// Strings are scanned as-is; numbers are scanned by their exact JSON text so card
    /// numbers, TFNs and account numbers sent as numbers cannot bypass detectors.
    /// A redacted number becomes a string.
    /// </summary>
    private static bool TryGetScannableText(
        JsonValue value,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? text)
    {
        switch (value.GetValueKind())
        {
            case JsonValueKind.String:
                text = value.GetValue<string>();
                return true;
            case JsonValueKind.Number:
                text = value.ToJsonString();
                return true;
            default:
                text = null;
                return false;
        }
    }

    private void ApplyFieldRules(JsonObject root, List<AppliedFinding> findings)
    {
        foreach (PrivacyFieldRule rule in policy.FieldRules)
        {
            ApplyFieldRule(root, rule, 0, "$", findings);
        }
    }

    private void ApplyFieldRule(
        JsonObject node,
        PrivacyFieldRule rule,
        int depth,
        string path,
        List<AppliedFinding> findings)
    {
        string segment = rule.Segments[depth];
        IEnumerable<string> names = segment == "*"
            ? node.Select(property => property.Key).ToArray()
            : node.ContainsKey(segment) ? [segment] : [];
        foreach (string name in names)
        {
            string childPath = $"{path}.{name}";
            JsonNode? child = node[name];
            if (depth < rule.Segments.Length - 1)
            {
                if (child is JsonObject nested)
                {
                    ApplyFieldRule(nested, rule, depth + 1, childPath, findings);
                }

                continue;
            }

            if (child is not JsonValue value || !TryGetScannableText(value, out string? text))
            {
                continue;
            }

            string? replaced = applicator.ApplyToValue(text, rule.Action, rule.MaxLength);
            if (replaced is null)
            {
                node.Remove(name);
            }
            else if (!string.Equals(replaced, text, StringComparison.Ordinal))
            {
                node[name] = replaced;
            }

            findings.Add(new AppliedFinding(
                DetectorIds.FieldRule,
                DetectorCategories.FieldName,
                childPath,
                rule.Action,
                Validated: true,
                SubKind: null));
        }
    }

    private void EnforceFieldLength(JsonNode? node, string path, List<AppliedFinding> findings)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach ((string name, JsonNode? child) in obj.ToArray())
                {
                    if (child is JsonValue value
                        && value.GetValueKind() == JsonValueKind.String
                        && value.GetValue<string>() is { } text
                        && text.Length > policy.MaximumFieldLength)
                    {
                        obj[name] = PolicyApplicator.Truncate(text, policy.MaximumFieldLength);
                        findings.Add(new AppliedFinding(
                            DetectorIds.FieldLength, DetectorCategories.FieldName, $"{path}.{name}",
                            PrivacyAction.Truncate, Validated: true, SubKind: null));
                    }
                    else
                    {
                        EnforceFieldLength(child, $"{path}.{name}", findings);
                    }
                }

                break;
            case JsonArray array:
                for (int index = 0; index < array.Count; index++)
                {
                    if (array[index] is JsonValue value
                        && value.GetValueKind() == JsonValueKind.String
                        && value.GetValue<string>() is { } text
                        && text.Length > policy.MaximumFieldLength)
                    {
                        array[index] = PolicyApplicator.Truncate(text, policy.MaximumFieldLength);
                        findings.Add(new AppliedFinding(
                            DetectorIds.FieldLength, DetectorCategories.FieldName, $"{path}[{index}]",
                            PrivacyAction.Truncate, Validated: true, SubKind: null));
                    }
                    else
                    {
                        EnforceFieldLength(array[index], $"{path}[{index}]", findings);
                    }
                }

                break;
        }
    }

    private string ApplyDetectorsToValue(string text, string path, List<AppliedFinding> findings)
    {
        string safeUrl = SafeUrl(text, path);
        if (!string.Equals(text, safeUrl, StringComparison.Ordinal))
        {
            findings.Add(new AppliedFinding(
                DetectorIds.FieldNameSecret, DetectorCategories.FieldName, path,
                PrivacyAction.Replace, Validated: true, SubKind: null));
            text = safeUrl;
        }

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
        List<DetectionMatch> ordered = matches.Count == 1
            ? matches
            : matches
                .OrderByDescending(m => m.Length)
                .ThenBy(m => m.Start)
                .ToList();

        List<DetectionMatch> selected = SelectNonOverlapping(ordered);

        // Apply right-to-left so indices remain valid.
        selected.Sort((a, b) => b.Start.CompareTo(a.Start));
        return selected.Exists(match => match.Length == 0)
            ? ApplySequentially(text, path, selected, findings)
            : ApplyInOnePass(text, path, selected, findings);
    }

    /// <summary>
    /// Greedy selection in candidate order: a candidate is kept unless it overlaps an
    /// already kept span. Kept spans never overlap each other, so ordered by (Start, End)
    /// their ends never decrease and only the last kept span starting before the
    /// candidate's end can overlap it. Binary search keeps this O(n log n) for values
    /// carrying thousands of matches (the previous pairwise scan was O(n^2)).
    /// </summary>
    private static List<DetectionMatch> SelectNonOverlapping(List<DetectionMatch> ordered)
    {
        List<DetectionMatch> selected = [];
        if (ordered.Count == 1)
        {
            selected.Add(ordered[0]);
            return selected;
        }

        List<(int Start, int End)> kept = [];
        foreach (DetectionMatch candidate in ordered)
        {
            // Index of the first kept span starting at or after the candidate's end.
            int low = 0;
            int high = kept.Count;
            while (low < high)
            {
                int middle = low + ((high - low) / 2);
                if (kept[middle].Start < candidate.End)
                {
                    low = middle + 1;
                }
                else
                {
                    high = middle;
                }
            }

            if (low > 0 && candidate.Start < kept[low - 1].End)
            {
                continue;
            }

            // Insert after every kept span that sorts at or before (Start, End).
            int position = low;
            while (position > 0
                && (kept[position - 1].Start > candidate.Start
                    || (kept[position - 1].Start == candidate.Start && kept[position - 1].End > candidate.End)))
            {
                position--;
            }

            kept.Insert(position, (candidate.Start, candidate.End));
            selected.Add(candidate);
        }

        return selected;
    }

    /// <summary>
    /// Spans are non-empty and disjoint and visited right-to-left, so every replacement
    /// sees exactly the original text of its span. Builds the result once instead of
    /// re-concatenating the whole value per match.
    /// </summary>
    private string ApplyInOnePass(
        string text,
        string path,
        List<DetectionMatch> selected,
        List<AppliedFinding> findings)
    {
        string?[] replacements = new string?[selected.Count];
        bool changed = false;
        for (int index = 0; index < selected.Count; index++)
        {
            DetectionMatch match = selected[index];
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

            replacements[index] = applicator.Apply(text, match, action);
            changed = true;
        }

        if (!changed)
        {
            return text;
        }

        StringBuilder builder = new(text.Length);
        int position = 0;
        for (int index = selected.Count - 1; index >= 0; index--)
        {
            if (replacements[index] is not { } replacement)
            {
                continue;
            }

            DetectionMatch match = selected[index];
            builder.Append(text, position, match.Start - position);
            builder.Append(replacement);
            position = match.End;
        }

        builder.Append(text, position, text.Length - position);
        return builder.ToString();
    }

    /// <summary>Original per-match splice, kept for zero-length matches from custom detectors.</summary>
    private string ApplySequentially(
        string text,
        string path,
        List<DetectionMatch> selected,
        List<AppliedFinding> findings)
    {
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
            detected.Add((JsonNode)id);
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

    /// <summary>
    /// Replaces each unpaired surrogate with U+FFFD, exactly as System.Text.Json (and the
    /// UTF-8 encoder's replacement fallback) writes it. Valid strings are returned as-is.
    /// </summary>
    private static string ReplaceUnpairedSurrogates(string value) =>
        value.AsSpan().ContainsAnyInRange('\uD800', '\uDFFF')
            ? Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(value))
            : value;

    private static string NormalizeFieldName(string value) => FieldNameNormalizer.Normalize(value);
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

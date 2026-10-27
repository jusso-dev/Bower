using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Pipeline;

public enum CustomLogFormat
{
    Json,
    Csv,
    KeyValue,
    Regex
}

public enum CustomLogValueType
{
    Text,
    DateTime,
    IpAddress,
    WholeNumber,
    Boolean
}

public sealed record CustomLogInput(string? Sample, string? Path);

public sealed record CustomLogField(
    string SourceName,
    CustomLogValueType Type,
    string? OcsfPath,
    string? AsimField,
    bool Sensitive);

public sealed record CustomLogParserConfiguration(
    string Version,
    CustomLogFormat Format,
    IReadOnlyList<CustomLogField> Fields,
    string? Delimiter = null,
    string? KeyValueSeparator = null,
    string? Pattern = null,
    CustomLogRuntimeMapping? Runtime = null);

/// <summary>Explicit signed semantic mapping; absent means preview-only, never active ingest.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CustomLogRuntimeMapping(
    string ApplicationName,
    string Environment,
    string EventCategory,
    string EventType,
    string EventAction,
    string EventResult,
    IReadOnlyDictionary<string, string> Match,
    IReadOnlyDictionary<string, string> Fields);

public sealed record CustomLogSchemaField(
    string Name,
    CustomLogValueType Type,
    bool Required,
    string? OcsfPath,
    string? AsimField);

public sealed record CustomLogSchema(
    string Version,
    IReadOnlyList<CustomLogSchemaField> Fields);

public sealed record CustomLogParserTest(
    string Name,
    int? SourceLine,
    bool ShouldParse,
    IReadOnlyList<string> ExpectedFields,
    IReadOnlyList<string> ExpectedOcsfMappings,
    IReadOnlyList<string> ExpectedAsimMappings);

public sealed record CustomLogPreviewValue(
    CustomLogValueType Type,
    string Value,
    string? OcsfPath,
    string? AsimField,
    bool Redacted);

public sealed record CustomLogPreviewRow(
    int SourceLine,
    IReadOnlyDictionary<string, CustomLogPreviewValue> Fields);

public sealed record CustomLogPreviewResult(
    bool IsValid,
    int ParsedLineCount,
    int RejectedLineCount,
    IReadOnlyList<string> Issues,
    IReadOnlyList<CustomLogPreviewRow> Rows);

public sealed record CustomLogGenerationResult(
    CustomLogFormat Format,
    double Confidence,
    IReadOnlyList<string> Rationale,
    CustomLogParserConfiguration Configuration,
    CustomLogSchema Schema,
    IReadOnlyList<CustomLogParserTest> Tests,
    CustomLogPreviewResult Preview);

public static partial class CustomLogParser
{
    public const int MaximumSampleBytes = 256 * 1024;
    public const int MaximumLines = 200;
    public const int MaximumLineBytes = 32 * 1024;

    private const int MaximumFields = 64;
    private const int MaximumPreviewRows = 20;
    private const string ConfigurationVersion = "1.0";

    private static readonly HashSet<string> ProhibitedFieldNames = new(
        [
            "authorization",
            "authorizationheader",
            "body",
            "cookie",
            "credentials",
            "password",
            "payload",
            "rawpayload",
            "secret",
            "token"
        ],
        StringComparer.Ordinal);

    private const int MaximumPreviewTokenLength = 64;

    private const string ApachePattern =
        "^(?<source_ip>\\S+)\\s+\\S+\\s+(?<identity>\\S+)\\s+\\[(?<timestamp>[^\\]]+)\\]\\s+\"(?<method>[A-Z]+)\\s+(?<path>\\S+)(?:\\s+[^\"]+)?\"\\s+(?<status>\\d{3})(?:\\s+(?<bytes>\\d+|-))?.*$";

    private const string TimestampSeverityPattern =
        "^(?<timestamp>\\d{4}-\\d{2}-\\d{2}[T ][^\\s]+)\\s+(?<severity>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\\s+(?<message>.*)$";

    private const string SyslogPattern =
        "^(?:<\\d+>)?(?<timestamp>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(?<host>\\S+)\\s+(?<application>[\\w.-]+)(?:\\[(?<process_id>\\d+)\\])?:\\s*(?<message>.*)$";

    // Closed vocabulary a regex text capture may preview: severities, HTTP methods and
    // outcome words. Anything else a capture holds could be arbitrary line content.
    private static readonly HashSet<string> PreviewVocabulary = new(
        [
            "trace", "debug", "info", "information", "notice", "warn", "warning", "error", "err",
            "fatal", "critical", "crit", "alert", "emerg", "emergency",
            "get", "head", "post", "put", "patch", "delete", "options", "connect",
            "success", "succeeded", "successful", "failure", "failed", "fail", "allow", "allowed",
            "deny", "denied", "accept", "accepted", "reject", "rejected", "block", "blocked",
            "ok", "pass", "passed", "drop", "dropped"
        ],
        StringComparer.OrdinalIgnoreCase);

    // Server-owned preview floor: every built-in detector, opt-in ones included, whatever
    // the submitted configuration says. Public identifiers the default policy allows (ABN,
    // ACN, SWIFT BIC) are skipped so severities such as CRITICAL still preview. Detectors
    // are stateless and safe to share.
    private static readonly ISensitiveDetector[] PreviewDetectors =
    [
        .. DetectorCatalog.CreateDefaultValueDetectors().Where(detector =>
            PrivacyPolicy.CreateDefault().ResolveAction(detector.Id) != PrivacyAction.Allow)
    ];

    private static readonly IFieldNameDetector PreviewFieldNameDetector =
        DetectorCatalog.CreateDefaultFieldNameDetector();

    // Name fragments that mark identity, network or account data in any value type.
    private static readonly string[] SensitiveNameFragments =
    [
        "user", "email", "mail", "phone", "mobile", "ip", "addr", "host", "url", "uri", "path",
        "message", "msg", "description", "account", "session", "auth", "key", "principal",
        "identity", "actor", "subject", "owner", "firstname", "lastname", "fullname", "surname",
        "givenname", "displayname", "birth", "dob", "ssn", "tfn", "medicare", "passport",
        "licence", "license", "card", "iban", "bsb", "location", "gps", "device", "computer"
    ];

    public static CustomLogGenerationResult Generate(string sample)
    {
        IReadOnlyList<SourceRecord> records = ReadSourceRecords(sample, null, out Detection detection);
        if (records.Count == 0)
        {
            throw new InvalidDataException("Sample contains no parseable log records.");
        }

        List<CustomLogField> fields = InferFields(records);
        if (fields.Count == 0)
        {
            throw new InvalidDataException(
                "Sample contains no safe fields suitable for parser generation.");
        }

        CustomLogParserConfiguration configuration = new(
            ConfigurationVersion,
            detection.Format,
            fields,
            detection.Delimiter,
            detection.KeyValueSeparator,
            detection.Pattern);
        IReadOnlyList<string> configurationIssues = ValidateConfiguration(configuration);
        if (configurationIssues.Count != 0)
        {
            throw new InvalidDataException(string.Join(" ", configurationIssues));
        }

        CustomLogPreviewResult preview = Preview(configuration, sample);
        IReadOnlyList<string> required = records
            .Select(record => record.Values.Keys.ToHashSet(StringComparer.Ordinal))
            .Aggregate((left, right) =>
            {
                left.IntersectWith(right);
                return left;
            })
            .Where(name => fields.Any(field => field.SourceName == name))
            .ToArray();
        CustomLogSchema schema = new(
            ConfigurationVersion,
            fields.Select(field => new CustomLogSchemaField(
                field.SourceName,
                field.Type,
                required.Contains(field.SourceName, StringComparer.Ordinal),
                field.OcsfPath,
                field.AsimField)).ToArray());

        List<string> rationale = [detection.Rationale];
        int excluded = records
            .SelectMany(record => record.Values.Keys)
            .Distinct(StringComparer.Ordinal)
            .Count(IsProhibited);
        if (excluded > 0)
        {
            rationale.Add(
                $"{excluded} prohibited field name(s) excluded from generated configuration.");
        }

        return new CustomLogGenerationResult(
            detection.Format,
            detection.Confidence,
            rationale,
            configuration,
            schema,
            CreateTests(configuration, preview),
            preview);
    }

    public static CustomLogPreviewResult Preview(
        CustomLogParserConfiguration configuration,
        string sample)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        IReadOnlyList<string> issues = ValidateConfiguration(configuration);
        if (issues.Count != 0)
        {
            return new CustomLogPreviewResult(false, 0, 0, issues, []);
        }

        IReadOnlyList<SourceRecord> records;
        try
        {
            records = ReadSourceRecords(
                sample,
                new Detection(
                    configuration.Format,
                    1,
                    "Configuration supplied by operator.",
                    configuration.Delimiter,
                    configuration.KeyValueSeparator,
                    configuration.Pattern),
                out _);
        }
        catch (Exception exception) when (
            exception is ArgumentException
            or InvalidDataException
            or JsonException)
        {
            return new CustomLogPreviewResult(false, 0, 0, [exception.Message], []);
        }

        Dictionary<string, CustomLogField> fieldLookup = configuration.Fields.ToDictionary(
            field => field.SourceName,
            StringComparer.Ordinal);
        List<CustomLogPreviewRow> rows = [];
        int rejected = 0;
        bool operatorRegex = configuration.Format == CustomLogFormat.Regex
            && configuration.Pattern is not (ApachePattern or TimestampSeverityPattern or SyslogPattern);

        foreach (SourceRecord record in records)
        {
            List<DetectionMatch>? lineMatches = record.Line is null
                ? null
                : FindSensitiveSpans(record.Line);
            Dictionary<string, CustomLogPreviewValue> values = new(StringComparer.Ordinal);
            foreach ((string sourceName, CustomLogField field) in fieldLookup)
            {
                if (!record.Values.TryGetValue(sourceName, out string? value))
                {
                    if (operatorRegex)
                    {
                        values[sourceName] = new CustomLogPreviewValue(
                            field.Type,
                            RedactionMarker(field.Type),
                            field.OcsfPath,
                            field.AsimField,
                            true);
                    }
                    continue;
                }

                if (!ValueMatchesType(value, field.Type))
                {
                    rejected++;
                    values.Clear();
                    break;
                }

                bool redacted = operatorRegex
                    || field.Sensitive
                    || IsFreeText(field)
                    || RequiresPreviewMasking(field, value, record, lineMatches);
                values[sourceName] = new CustomLogPreviewValue(
                    field.Type,
                    redacted ? RedactionMarker(field.Type) : value,
                    field.OcsfPath,
                    field.AsimField,
                    redacted);
            }

            if (values.Count > 0 && rows.Count < MaximumPreviewRows)
            {
                rows.Add(new CustomLogPreviewRow(record.SourceLine, values));
            }
        }

        int parsed = Math.Max(0, records.Count - rejected);
        List<string> previewIssues = [];
        if (records.Count == 0)
        {
            previewIssues.Add("No records matched generated parser configuration.");
        }
        if (rejected > 0)
        {
            previewIssues.Add($"{rejected} record(s) failed inferred field type validation.");
        }

        return new CustomLogPreviewResult(
            parsed > 0 && rejected == 0,
            parsed,
            rejected,
            previewIssues,
            rows);
    }

    public static IReadOnlyList<string> ValidateConfiguration(
        CustomLogParserConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        List<string> issues = [];
        if (!string.Equals(configuration.Version, ConfigurationVersion, StringComparison.Ordinal))
        {
            issues.Add($"Unsupported parser configuration version '{configuration.Version}'.");
        }
        if (configuration.Fields is null)
        {
            return ["Parser fields are required."];
        }
        if (configuration.Fields.Count is < 1 or > MaximumFields)
        {
            issues.Add($"Parser configuration needs 1 to {MaximumFields} fields.");
        }

        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (CustomLogField field in configuration.Fields)
        {
            if (field is null || !Enum.IsDefined(field.Type))
            {
                issues.Add("Parser field type is unsupported.");
                continue;
            }
            if (!IsValidFieldName(field.SourceName))
            {
                issues.Add($"Invalid source field name '{field.SourceName}'.");
            }
            else if (!names.Add(field.SourceName))
            {
                issues.Add($"Duplicate source field name '{field.SourceName}'.");
            }
            if (IsProhibited(field.SourceName))
            {
                issues.Add($"Prohibited source field name '{field.SourceName}'.");
            }
        }

        switch (configuration.Format)
        {
            case CustomLogFormat.Csv when configuration.Delimiter is not ("," or "\t" or ";"):
                issues.Add("CSV delimiter must be comma, tab or semicolon.");
                break;
            case CustomLogFormat.KeyValue
                when configuration.KeyValueSeparator is not ("=" or ":"):
                issues.Add("Key/value separator must be '=' or ':'.");
                break;
            case CustomLogFormat.Regex:
                ValidateRegex(configuration, issues);
                break;
            default:
                if (!Enum.IsDefined(configuration.Format))
                {
                    issues.Add("Parser format is unsupported.");
                }
                break;
        }

        if (configuration.Runtime is { } runtime)
        {
            string[] metadata = [runtime.ApplicationName, runtime.Environment, runtime.EventCategory,
                runtime.EventType, runtime.EventAction];
            string[] targets = ["eventId", "timeGenerated", "actor.username", "actor.userId",
                "source.ipAddress", "request.correlationId", "eventOutcomeReason"];
            if (configuration.Format != CustomLogFormat.Json
                || metadata.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 128)
                || runtime.EventResult is not ("success" or "failure" or "denied" or "unknown")
                || runtime.Match is null || runtime.Match.Count is < 1 or > 16
                || runtime.Fields is null || runtime.Fields.Count is < 2 or > 7
                || !runtime.Fields.ContainsKey("eventId") || !runtime.Fields.ContainsKey("timeGenerated")
                || runtime.Fields.Keys.Any(target => !targets.Contains(target, StringComparer.Ordinal))
                || runtime.Fields.Values.Any(source => !names.Contains(source))
                || runtime.Match.Any(pair => !names.Contains(pair.Key) || string.IsNullOrEmpty(pair.Value) || pair.Value.Length > 2048))
            {
                issues.Add("Invalid runtime semantic mapping; only bounded, filtered JSON mappings are supported.");
            }
        }

        return issues;
    }

    private static IReadOnlyList<SourceRecord> ReadSourceRecords(
        string sample,
        Detection? requested,
        out Detection detection)
    {
        ValidateSample(sample);
        string normalized = sample.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');
        string[] lines = normalized
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(MaximumLines + 1)
            .ToArray();
        if (lines.Length > MaximumLines)
        {
            throw new InvalidDataException($"Sample cannot exceed {MaximumLines} non-empty lines.");
        }
        foreach (string line in lines)
        {
            if (Encoding.UTF8.GetByteCount(line) > MaximumLineBytes)
            {
                throw new InvalidDataException(
                    $"A sample line exceeds {MaximumLineBytes} bytes.");
            }
        }

        detection = requested ?? Detect(normalized, lines);
        IReadOnlyList<SourceRecord> records = detection.Format switch
        {
            CustomLogFormat.Json => ParseJson(normalized, lines),
            CustomLogFormat.Csv => ParseCsv(lines, detection.Delimiter!),
            CustomLogFormat.KeyValue => ParseKeyValue(lines, detection.KeyValueSeparator!),
            CustomLogFormat.Regex => ParseRegex(lines, detection.Pattern!),
            _ => throw new InvalidDataException("Unsupported custom log format.")
        };
        return AliasValueLikeNames(records);
    }

    /// <summary>
    /// Field names come from the sample (JSON keys, key/value keys, CSV headers), so a
    /// name can carry data. Names that look like data become neutral <c>field_N</c>
    /// aliases, in order of first appearance, and are never echoed.
    /// </summary>
    private static IReadOnlyList<SourceRecord> AliasValueLikeNames(IReadOnlyList<SourceRecord> records)
    {
        HashSet<string> taken = records
            .SelectMany(record => record.Values.Keys)
            .ToHashSet(StringComparer.Ordinal);
        Dictionary<string, string> aliases = new(StringComparer.Ordinal);
        int next = 0;
        foreach (string name in records.SelectMany(record => record.Values.Keys).Distinct(StringComparer.Ordinal))
        {
            if (!IsValueLikeName(name))
            {
                continue;
            }
            string alias;
            do
            {
                alias = $"field_{++next}";
            }
            while (!taken.Add(alias));
            aliases[name] = alias;
        }
        if (aliases.Count == 0)
        {
            return records;
        }

        return records
            .Select(record => record with
            {
                Values = record.Values.ToDictionary(
                    pair => aliases.GetValueOrDefault(pair.Key, pair.Key),
                    pair => pair.Value,
                    StringComparer.Ordinal),
                Spans = record.Spans?.ToDictionary(
                    pair => aliases.GetValueOrDefault(pair.Key, pair.Key),
                    pair => pair.Value,
                    StringComparer.Ordinal)
            })
            .ToArray();
    }

    private static bool IsValueLikeName(string name) =>
        ContainsIpAddress(name)
        || name.Split('.').Any(segment => segment.Length > 0 && segment.All(char.IsAsciiDigit))
        || FindSensitiveSpans(name).Count > 0;

    /// <summary>A header cell that parses as a typed value means the first row is data.</summary>
    private static bool LooksLikeData(string cell) =>
        long.TryParse(cell, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)
        || bool.TryParse(cell, out _)
        || (cell.Any(char.IsAsciiDigit) && DateTimeOffset.TryParse(
            cell,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal,
            out _))
        || IsValueLikeName(cell);

    private static Detection Detect(string sample, string[] lines)
    {
        if (TryParseJson(sample, lines, out IReadOnlyList<SourceRecord>? jsonRecords))
        {
            return new Detection(
                CustomLogFormat.Json,
                1,
                $"All {jsonRecords.Count} sampled record(s) are JSON objects.");
        }

        foreach (string delimiter in new[] { ",", "\t", ";" })
        {
            if (TryParseCsv(lines, delimiter, out IReadOnlyList<SourceRecord>? csvRecords))
            {
                return new Detection(
                    CustomLogFormat.Csv,
                    0.95,
                    $"Header and {csvRecords.Count} data record(s) share a stable {DisplayDelimiter(delimiter)} column count.",
                    delimiter);
            }
        }

        foreach (string separator in new[] { "=", ":" })
        {
            if (TryParseKeyValue(lines, separator, out IReadOnlyList<SourceRecord>? keyValueRecords))
            {
                return new Detection(
                    CustomLogFormat.KeyValue,
                    0.9,
                    $"{keyValueRecords.Count} sampled record(s) contain stable key{separator}value pairs.",
                    KeyValueSeparator: separator);
            }
        }

        if (TryDetectRegex(lines, out string pattern, out string rationale))
        {
            return new Detection(CustomLogFormat.Regex, 0.8, rationale, Pattern: pattern);
        }

        throw new InvalidDataException(
            "Could not infer JSON, CSV, key/value or a supported common-log regex format.");
    }

    private static IReadOnlyList<SourceRecord> ParseJson(
        string sample,
        IReadOnlyList<string> lines)
    {
        if (!TryParseJson(sample, lines, out IReadOnlyList<SourceRecord>? records))
        {
            throw new InvalidDataException("One or more records do not match JSON configuration.");
        }
        return records;
    }

    private static bool TryParseJson(
        string sample,
        IReadOnlyList<string> lines,
        out IReadOnlyList<SourceRecord> records)
    {
        List<SourceRecord> parsed = [];
        try
        {
            using JsonDocument document = JsonDocument.Parse(
                sample,
                new JsonDocumentOptions { MaxDepth = 16 });
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                int line = 1;
                foreach (JsonElement element in document.RootElement.EnumerateArray())
                {
                    if (element.ValueKind != JsonValueKind.Object)
                    {
                        records = [];
                        return false;
                    }
                    parsed.Add(new SourceRecord(line++, FlattenJson(element)));
                }
                records = parsed;
                return parsed.Count > 0;
            }
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                records = [new SourceRecord(1, FlattenJson(document.RootElement))];
                return true;
            }
        }
        catch (JsonException)
        {
            // JSON Lines is checked below.
        }

        parsed.Clear();
        for (int index = 0; index < lines.Count; index++)
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(
                    lines[index],
                    new JsonDocumentOptions { MaxDepth = 16 });
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    records = [];
                    return false;
                }
                parsed.Add(new SourceRecord(index + 1, FlattenJson(document.RootElement)));
            }
            catch (JsonException)
            {
                records = [];
                return false;
            }
        }

        records = parsed;
        return parsed.Count > 0;
    }

    private static ReadOnlyDictionary<string, string> FlattenJson(JsonElement root)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal);
        FlattenJson(root, null, 0, values);
        return new ReadOnlyDictionary<string, string>(values);
    }

    private static void FlattenJson(
        JsonElement element,
        string? prefix,
        int depth,
        Dictionary<string, string> values)
    {
        if (depth > 4 || values.Count >= MaximumFields)
        {
            return;
        }

        foreach (JsonProperty property in element.EnumerateObject())
        {
            string name = prefix is null ? property.Name : $"{prefix}.{property.Name}";
            if (!IsValidFieldName(name) || IsProhibited(name))
            {
                continue;
            }

            switch (property.Value.ValueKind)
            {
                case JsonValueKind.Object:
                    FlattenJson(property.Value, name, depth + 1, values);
                    break;
                case JsonValueKind.String:
                    values[name] = property.Value.GetString() ?? string.Empty;
                    break;
                case JsonValueKind.Number:
                case JsonValueKind.True:
                case JsonValueKind.False:
                    values[name] = property.Value.GetRawText();
                    break;
            }
        }
    }

    private static IReadOnlyList<SourceRecord> ParseCsv(
        IReadOnlyList<string> lines,
        string delimiter)
    {
        if (!TryParseCsv(lines, delimiter, out IReadOnlyList<SourceRecord>? records))
        {
            throw new InvalidDataException("One or more records do not match CSV configuration.");
        }
        return records;
    }

    private static bool TryParseCsv(
        IReadOnlyList<string> lines,
        string delimiter,
        out IReadOnlyList<SourceRecord> records)
    {
        records = [];
        if (lines.Count < 2)
        {
            return false;
        }

        List<string> headers = SplitDelimited(lines[0], delimiter[0]);
        if (headers.Count is < 2 or > MaximumFields
            || headers.Any(header => !IsValidFieldName(header) || LooksLikeData(header))
            || headers.Distinct(StringComparer.Ordinal).Count() != headers.Count)
        {
            return false;
        }

        List<SourceRecord> parsed = [];
        for (int index = 1; index < lines.Count; index++)
        {
            List<string> row = SplitDelimited(lines[index], delimiter[0]);
            if (row.Count != headers.Count)
            {
                records = [];
                return false;
            }

            Dictionary<string, string> values = new(StringComparer.Ordinal);
            for (int column = 0; column < headers.Count; column++)
            {
                if (!IsProhibited(headers[column]))
                {
                    values[headers[column]] = row[column];
                }
            }
            parsed.Add(new SourceRecord(index + 1, values));
        }

        records = parsed;
        return parsed.Count > 0;
    }

    private static List<string> SplitDelimited(string line, char delimiter)
    {
        List<string> values = [];
        StringBuilder value = new();
        bool quoted = false;
        for (int index = 0; index < line.Length; index++)
        {
            char current = line[index];
            if (current == '"')
            {
                if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                {
                    value.Append('"');
                    index++;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (current == delimiter && !quoted)
            {
                values.Add(value.ToString().Trim());
                value.Clear();
            }
            else
            {
                value.Append(current);
            }
        }
        if (quoted)
        {
            return [];
        }
        values.Add(value.ToString().Trim());
        return values;
    }

    private static IReadOnlyList<SourceRecord> ParseKeyValue(
        IReadOnlyList<string> lines,
        string separator)
    {
        if (!TryParseKeyValue(lines, separator, out IReadOnlyList<SourceRecord>? records))
        {
            throw new InvalidDataException(
                "One or more records do not match key/value configuration.");
        }
        return records;
    }

    private static bool TryParseKeyValue(
        IReadOnlyList<string> lines,
        string separator,
        out IReadOnlyList<SourceRecord> records)
    {
        List<SourceRecord> parsed = [];
        Regex regex = separator == "=" ? EqualsPairRegex() : ColonPairRegex();
        for (int index = 0; index < lines.Count; index++)
        {
            MatchCollection matches = regex.Matches(lines[index]);
            if (matches.Count < 2)
            {
                records = [];
                return false;
            }

            Dictionary<string, string> values = new(StringComparer.Ordinal);
            foreach (Match match in matches)
            {
                string key = match.Groups["key"].Value;
                if (!IsValidFieldName(key) || IsProhibited(key))
                {
                    continue;
                }
                string value = match.Groups["value"].Value.Trim('"', '\'');
                values[key] = value;
            }
            if (values.Count == 0)
            {
                records = [];
                return false;
            }
            parsed.Add(new SourceRecord(index + 1, values));
        }

        records = parsed;
        return parsed.Count > 0;
    }

    private static bool TryDetectRegex(
        string[] lines,
        out string pattern,
        out string rationale)
    {
        if (AllMatch(lines, ApachePattern))
        {
            pattern = ApachePattern;
            rationale = "Records match a bounded common HTTP access-log expression.";
            return true;
        }

        if (AllMatch(lines, TimestampSeverityPattern))
        {
            pattern = TimestampSeverityPattern;
            rationale = "Records share timestamp, severity and message positions.";
            return true;
        }

        if (AllMatch(lines, SyslogPattern))
        {
            pattern = SyslogPattern;
            rationale = "Records match a bounded RFC 3164-style syslog expression.";
            return true;
        }

        pattern = string.Empty;
        rationale = string.Empty;
        return false;
    }

    private static bool AllMatch(string[] lines, string pattern)
    {
        Regex regex = CreateSafeRegex(pattern);
        return lines.Length > 0 && lines.All(line => regex.IsMatch(line));
    }

    private static List<SourceRecord> ParseRegex(
        string[] lines,
        string pattern)
    {
        Regex regex;
        try
        {
            regex = CreateSafeRegex(pattern);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException("Regex configuration is invalid.", exception);
        }

        string[] groups = regex.GetGroupNames()
            .Where(name => name != "0" && !int.TryParse(name, out _))
            .ToArray();
        List<SourceRecord> parsed = [];
        for (int index = 0; index < lines.Length; index++)
        {
            Match match = regex.Match(lines[index]);
            if (!match.Success)
            {
                throw new InvalidDataException(
                    "One or more records do not match regex configuration.");
            }
            Dictionary<string, string> values = new(StringComparer.Ordinal);
            Dictionary<string, (int Start, int Length)> spans = new(StringComparer.Ordinal);
            foreach (string group in groups)
            {
                // A zero-length capture is indistinguishable from a group that did not take part.
                if (!IsProhibited(group) && match.Groups[group].Success && match.Groups[group].Length > 0)
                {
                    values[group] = match.Groups[group].Value;
                    spans[group] = (match.Groups[group].Index, match.Groups[group].Length);
                }
            }
            parsed.Add(new SourceRecord(index + 1, values, spans, lines[index]));
        }
        return parsed;
    }

    /// <summary>
    /// The non-backtracking engine is linear in input length, and input is bounded
    /// (<see cref="MaximumSampleBytes"/>, <see cref="MaximumLineBytes"/>, 2048-character
    /// patterns), so no match timeout is used. A wall-clock timeout made the result depend
    /// on machine load: the engine builds its automaton lazily, so a cold first match on a
    /// busy host timed out and valid input failed preview. The Rust engine has no timeout
    /// either. The timeout is explicit so a host-wide default cannot reintroduce one.
    /// </summary>
    private static Regex CreateSafeRegex(string pattern) =>
        new(
            pattern,
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
            Regex.InfiniteMatchTimeout);

    private static void ValidateRegex(
        CustomLogParserConfiguration configuration,
        List<string> issues)
    {
        if (string.IsNullOrWhiteSpace(configuration.Pattern)
            || configuration.Pattern.Length > 2048)
        {
            issues.Add("Regex pattern is required and cannot exceed 2048 characters.");
            return;
        }

        try
        {
            Regex regex = CreateSafeRegex(configuration.Pattern);
            HashSet<string> groups = regex.GetGroupNames()
                .Where(name => name != "0" && !int.TryParse(name, out _))
                .ToHashSet(StringComparer.Ordinal);
            foreach (CustomLogField field in configuration.Fields)
            {
                if (!groups.Contains(field.SourceName))
                {
                    issues.Add(
                        $"Regex has no named capture for field '{field.SourceName}'.");
                }
            }
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException)
        {
            issues.Add("Regex pattern is unsupported by the non-backtracking engine.");
        }
    }

    private static List<CustomLogField> InferFields(
        IReadOnlyList<SourceRecord> records)
    {
        string[] names = records
            .SelectMany(record => record.Values.Keys)
            .Distinct(StringComparer.Ordinal)
            .Where(name => !IsProhibited(name))
            .Take(MaximumFields)
            .ToArray();
        List<CustomLogField> fields = [];
        foreach (string name in names)
        {
            string[] values = records
                .Select(record => record.Values.TryGetValue(name, out string? value) ? value : null)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Cast<string>()
                .ToArray();
            CustomLogValueType type = InferType(name, values);
            (string? ocsf, string? asim, bool sensitive) = MapField(name);
            fields.Add(new CustomLogField(name, type, ocsf, asim, sensitive));
        }
        return fields;
    }

    private static CustomLogValueType InferType(string name, string[] values)
    {
        string canonical = Canonical(name);
        if (canonical.Contains("ip", StringComparison.Ordinal)
            && values.Length > 0
            && values.All(value => IPAddress.TryParse(value, out _)))
        {
            return CustomLogValueType.IpAddress;
        }
        if ((canonical.Contains("time", StringComparison.Ordinal)
                || canonical.Contains("date", StringComparison.Ordinal))
            && values.Length > 0
            && values.All(value => DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal,
                out _)))
        {
            return CustomLogValueType.DateTime;
        }
        if (values.Length > 0
            && values.All(value => long.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out _)))
        {
            return CustomLogValueType.WholeNumber;
        }
        if (values.Length > 0 && values.All(value => bool.TryParse(value, out _)))
        {
            return CustomLogValueType.Boolean;
        }
        return CustomLogValueType.Text;
    }

    private static (string? Ocsf, string? Asim, bool Sensitive) MapField(string name)
    {
        string canonical = Canonical(name);
        if (IsAlias(canonical, "timestamp", "time", "datetime", "eventtime", "eventtimestamp", "ts"))
        {
            return ("time", "TimeGenerated", false);
        }
        if (IsAlias(canonical, "severity", "level", "loglevel", "severityname"))
        {
            return ("severity", "EventSeverity", false);
        }
        if (IsAlias(
            canonical,
            "user",
            "username",
            "userid",
            "identity",
            "principal",
            "principalname",
            "actor",
            "email"))
        {
            return ("actor.user.name", "ActorUsername", true);
        }
        if (IsAlias(canonical, "sourceip", "srcip", "clientip", "remoteaddr", "ip"))
        {
            return ("src_endpoint.ip", "SrcIpAddr", true);
        }
        if (IsAlias(canonical, "destinationip", "dstip", "serverip"))
        {
            return ("dst_endpoint.ip", "DstIpAddr", true);
        }
        if (IsAlias(canonical, "action", "activity", "operation", "event", "eventname", "method"))
        {
            return ("activity_name", "EventType", false);
        }
        if (IsAlias(canonical, "result", "outcome", "status"))
        {
            return ("status_detail", "EventResultDetails", false);
        }
        if (IsAlias(canonical, "host", "hostname", "computer", "device"))
        {
            return ("device.hostname", "DvcHostname", true);
        }
        if (IsAlias(canonical, "application", "app", "service", "component"))
        {
            return ("metadata.product.name", "EventProduct", false);
        }
        if (IsAlias(canonical, "message", "eventmessage", "description"))
        {
            return ("message", "EventMessage", true);
        }
        if (IsAlias(canonical, "processid", "pid"))
        {
            return ("actor.process.pid", "ActorProcessId", false);
        }
        if (IsAlias(canonical, "path", "url", "requesturi"))
        {
            return ("http_request.url.path", "Url", true);
        }
        return (null, null, true);
    }

    private static bool ValueMatchesType(string value, CustomLogValueType type) =>
        type switch
        {
            CustomLogValueType.DateTime => DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal,
                out _),
            CustomLogValueType.IpAddress => IPAddress.TryParse(value, out _),
            CustomLogValueType.WholeNumber => long.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out _),
            CustomLogValueType.Boolean => bool.TryParse(value, out _),
            _ => true
        };

    private static List<CustomLogParserTest> CreateTests(
        CustomLogParserConfiguration configuration,
        CustomLogPreviewResult preview)
    {
        CustomLogPreviewRow? first = preview.Rows.Count == 0 ? null : preview.Rows[0];
        List<CustomLogParserTest> tests = [];
        if (first is not null)
        {
            tests.Add(new CustomLogParserTest(
                "parses representative record",
                first.SourceLine,
                true,
                first.Fields.Keys.Order(StringComparer.Ordinal).ToArray(),
                first.Fields.Values
                    .Select(value => value.OcsfPath)
                    .Where(value => value is not null)
                    .Cast<string>()
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray(),
                first.Fields.Values
                    .Select(value => value.AsimField)
                    .Where(value => value is not null)
                    .Cast<string>()
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray()));
        }
        tests.Add(new CustomLogParserTest(
            "rejects malformed record",
            null,
            false,
            [],
            [],
            []));
        tests.Add(new CustomLogParserTest(
            "does not emit prohibited fields",
            null,
            true,
            configuration.Fields
                .Select(field => field.SourceName)
                .Where(IsProhibited)
                .ToArray(),
            [],
            []));
        return tests;
    }

    private static void ValidateSample(string sample)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sample);
        if (Encoding.UTF8.GetByteCount(sample) > MaximumSampleBytes)
        {
            throw new InvalidDataException(
                $"Sample cannot exceed {MaximumSampleBytes} UTF-8 bytes.");
        }
    }

    private static bool IsValidFieldName(string value) =>
        value.Length is > 0 and <= 128
        && value.All(character =>
            char.IsAsciiLetterOrDigit(character)
            || character is '_' or '-' or '.' or '@');

    private static bool IsProhibited(string name) =>
        ProhibitedFieldNames.Contains(Canonical(name))
        || Canonical(name).Contains("password", StringComparison.Ordinal)
        || Canonical(name).Contains("secret", StringComparison.Ordinal)
        || Canonical(name).Contains("token", StringComparison.Ordinal)
        || Canonical(name).Contains("cookie", StringComparison.Ordinal);

    private static bool IsFreeText(CustomLogField field) =>
        field.Type == CustomLogValueType.Text
        && field.OcsfPath is null
        && field.AsimField is null;

    /// <summary>
    /// Minimum preview privacy owned by the server. Submitted sensitivity flags and
    /// mappings can add masking but never remove it: IP types and values, any field
    /// outside the known non-sensitive names, sensitive field names, text that is not a
    /// short token, regex text outside the closed vocabulary and anything a built-in
    /// detector finds stay masked.
    /// </summary>
    private static bool RequiresPreviewMasking(
        CustomLogField field,
        string value,
        SourceRecord record,
        List<DetectionMatch>? lineMatches)
    {
        if (field.Type == CustomLogValueType.IpAddress
            || MapField(field.SourceName).Sensitive
            || IsSensitiveFieldName(field.SourceName)
            || ContainsIpAddress(value))
        {
            return true;
        }
        if (field.Type == CustomLogValueType.Text
            && (!IsPreviewToken(value)
                || (record.Spans is not null && !IsPreviewVocabulary(value))))
        {
            return true;
        }
        // Regex captures can slice a sensitive span so no single value looks sensitive;
        // check each capture against detections over the whole source line.
        if (lineMatches is not null
            && record.Spans is not null
            && record.Spans.TryGetValue(field.SourceName, out (int Start, int Length) span)
            && lineMatches.Any(match => match.Start < span.Start + span.Length
                && span.Start < match.End))
        {
            return true;
        }
        return FindSensitiveSpans(value).Count > 0;
    }

    private static bool IsSensitiveFieldName(string name)
    {
        string canonical = Canonical(name);
        return PreviewFieldNameDetector.MatchesFieldName(canonical)
            || SensitiveNameFragments.Any(fragment =>
                canonical.Contains(fragment, StringComparison.Ordinal));
    }

    private static bool IsPreviewToken(string value) =>
        value.Length <= MaximumPreviewTokenLength
        && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-' or ':' or '+');

    private static bool IsPreviewVocabulary(string value) =>
        PreviewVocabulary.Contains(value)
        || (value.Length == 3 && value.All(char.IsAsciiDigit));

    /// <summary>
    /// Strict IPv4 (dotted quad) or IPv6 anywhere in <paramref name="text"/>. Plain
    /// integers, which <see cref="IPAddress.TryParse(string, out IPAddress)"/> also accepts,
    /// do not count.
    /// </summary>
    private static bool ContainsIpAddress(string text)
    {
        foreach (Match token in AddressTokenRegex().Matches(text))
        {
            string value = token.Value;
            foreach (string candidate in new[] { value, value.Trim('.', ':') })
            {
                if (!IPAddress.TryParse(candidate, out IPAddress? address))
                {
                    continue;
                }
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    && candidate.Count(character => character == ':') >= 2)
                {
                    return true;
                }
                string[] octets = candidate.Split('.');
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    && octets.Length == 4
                    && octets.All(octet => octet.Length is > 0 and <= 3 && octet.All(char.IsAsciiDigit)))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<DetectionMatch> FindSensitiveSpans(string text)
    {
        List<DetectionMatch> matches = [];
        try
        {
            foreach (ISensitiveDetector detector in PreviewDetectors)
            {
                detector.Detect(text, "$", matches);
            }
        }
        catch (Exception)
        {
            // Fail closed: an unscanned value is treated as sensitive over its whole length.
            matches.Add(new DetectionMatch("preview.scan-failed", "preview", 0, text.Length, false));
        }
        return matches;
    }

    private static string RedactionMarker(CustomLogValueType type) =>
        type == CustomLogValueType.IpAddress ? "[redacted:ip]" : "[redacted]";

    private static string Canonical(string value) =>
        new(value
            .Where(char.IsAsciiLetterOrDigit)
            .Select(char.ToLowerInvariant)
            .ToArray());

    private static bool IsAlias(string value, params string[] aliases) =>
        aliases.Contains(value, StringComparer.Ordinal);

    private static string DisplayDelimiter(string delimiter) =>
        delimiter == "\t" ? "tab-delimited" : $"'{delimiter}'-delimited";

    [GeneratedRegex(
        """(?<key>[A-Za-z_][\w.@-]*)=(?<value>"[^"]*"|'[^']*'|[^\s]+)""",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        Timeout.Infinite)]
    private static partial Regex EqualsPairRegex();

    [GeneratedRegex(
        """(?<key>[A-Za-z_][\w.@-]*):(?<value>"[^"]*"|'[^']*'|[^\s]+)""",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        Timeout.Infinite)]
    private static partial Regex ColonPairRegex();

    // Runs of characters an IPv4 or IPv6 literal can contain.
    [GeneratedRegex(
        "[0-9A-Fa-f.:]+",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        Timeout.Infinite)]
    private static partial Regex AddressTokenRegex();

    private sealed record SourceRecord(
        int SourceLine,
        IReadOnlyDictionary<string, string> Values,
        Dictionary<string, (int Start, int Length)>? Spans = null,
        string? Line = null);

    private sealed record Detection(
        CustomLogFormat Format,
        double Confidence,
        string Rationale,
        string? Delimiter = null,
        string? KeyValueSeparator = null,
        string? Pattern = null);
}

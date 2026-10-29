using System.Buffers;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Integrity;
using Bower.Redaction.Privacy;

namespace Bower.Management.Api;

/// <summary>One field of a source type plus its server-only text rule.</summary>
internal sealed record SourceFieldRule(SourceFieldDefinition Definition, Regex? Pattern = null, string? PatternFix = null);

/// <summary>What a source type generates from validated values.</summary>
internal sealed record SourceSetupBuild(
    IReadOnlyList<SourceSetupFile> Files,
    IReadOnlyList<SourceSetupVariable> Variables,
    IReadOnlyList<SourceSetupSnippet> Snippets,
    SourceSetupVerification Verification);

/// <summary>
/// A guided source type. To add one (for example Windows Event Log), subclass this, describe its
/// fields and add it to <see cref="SourceSetupRegistry"/>; the console renders it with no change.
/// Generators see only values that passed <see cref="SourceSetupRegistry.Normalise"/> and must
/// build files with JSON writers, never string concatenation of free text.
/// </summary>
internal abstract class SourceSetupType
{
    public abstract string Id { get; }

    public abstract string Title { get; }

    public abstract string Summary { get; }

    public abstract string Why { get; }

    public abstract IReadOnlyList<string> Needs { get; }

    public abstract IReadOnlyList<SourceFieldRule> Fields { get; }

    public abstract string CheckDescription { get; }

    public abstract string Guide { get; }

    public SourceTypeDefinition Definition => new(
        Id, Title, Summary, Why, Needs, [.. Fields.Select(rule => rule.Definition)], CheckDescription, Guide);

    /// <summary>Cross-field checks after every field passed on its own. Adds failing checks only.</summary>
    public virtual void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
    }

    public abstract SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId);

    /// <summary>A synthetic event as the collector would queue it. Fake values only.</summary>
    public abstract JsonObject Sample(IReadOnlyDictionary<string, string> values);
}

/// <summary>
/// The guided source types, field validation, plan hashing and the redacted preview. Every
/// value is checked here; the console's field kinds only guide input.
/// </summary>
internal static partial class SourceSetupRegistry
{
    public const int MaximumValues = 64;
    public const int MaximumListItems = 64;

    private static readonly SourceSetupType[] Types =
    [
        new SyslogSourceSetup(),
        new WindowsEventLogSourceSetup(),
        new DockerSourceSetup(),
        new AwsSourceSetup(),
        new GcpSourceSetup(),
        new AmaSourceSetup(),
        new SdkSourceSetup()
    ];

    public static SourceTypeDefinition[] Definitions { get; } = [.. Types.Select(type => type.Definition)];

    public static SourceSetupType? Find(string? id) =>
        Types.FirstOrDefault(type => string.Equals(type.Id, id, StringComparison.Ordinal));

    /// <summary>
    /// Trims, applies defaults and checks every field. Unknown fields fail; fields hidden by
    /// another field's value are dropped. Returns only known, valid values.
    /// </summary>
    public static (Dictionary<string, string> Values, List<SetupCheck> Checks) Normalise(
        SourceSetupType type,
        IReadOnlyDictionary<string, string>? raw)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal);
        List<SetupCheck> checks = [];
        raw ??= new Dictionary<string, string>();
        if (raw.Count > MaximumValues)
        {
            checks.Add(Fail("values", "The form sent too many values.", "Reload the page and fill in the form again."));
            return (values, checks);
        }

        HashSet<string> known = [.. type.Fields.Select(rule => rule.Definition.Id)];
        if (raw.Keys.Any(key => !known.Contains(key)))
        {
            checks.Add(Fail(
                "values",
                "The form sent a value this source type does not use.",
                "Reload the page so the form matches this version of Bower."));
        }

        // Choices first, so fields shown only for a choice see the chosen value.
        foreach (SourceFieldRule rule in type.Fields.OrderBy(rule => rule.Definition.Kind == SourceFieldKinds.Choice ? 0 : 1))
        {
            SourceFieldDefinition field = rule.Definition;
            if (field.ShownWhenField is { } controller
                && !(values.TryGetValue(controller, out string? chosen) && field.ShownWhenValues!.Contains(chosen)))
            {
                continue;
            }

            string text = (raw.TryGetValue(field.Id, out string? supplied) ? supplied : null)?.Trim() ?? string.Empty;
            if (text.Length == 0 && field.DefaultValue is not null)
            {
                text = field.DefaultValue;
            }

            if (text.Length == 0)
            {
                if (field.Required)
                {
                    checks.Add(Fail(field.Id, $"{field.Label} is required.", field.Help));
                }

                continue;
            }

            if (text.Length > field.MaximumLength)
            {
                checks.Add(Fail(field.Id, $"{field.Label} is longer than {field.MaximumLength} characters.", field.Help));
                continue;
            }

            if (Check(rule, text) is { } problem)
            {
                checks.Add(Fail(field.Id, $"{field.Label}: {problem.Message}", problem.Fix));
                continue;
            }

            values[field.Id] = Canonical(field, text);
        }

        if (checks.Count == 0)
        {
            type.Validate(values, checks);
        }

        return (values, checks);
    }

    /// <summary>Builds the plan and its content hash (sha256 over the canonical JSON of what is approved).</summary>
    public static SourceSetupPlan Plan(SourceSetupType type, string collectorId, IReadOnlyDictionary<string, string> values)
    {
        SourceSetupBuild build = type.Build(values, collectorId);
        JsonObject hashed = new()
        {
            ["kind"] = SourceSetupSigner.Kind,
            ["sourceType"] = type.Id,
            ["collectorId"] = collectorId,
            ["files"] = new JsonArray([.. build.Files.Select(file => (JsonNode)new JsonObject
            {
                ["name"] = file.Name,
                ["installPath"] = file.InstallPath,
                ["content"] = file.Content
            })]),
            ["variables"] = Variables(build.Variables),
            ["snippets"] = new JsonArray([.. build.Snippets.Select(snippet => (JsonNode)new JsonObject
            {
                ["title"] = snippet.Title,
                ["content"] = snippet.Content
            })]),
            ["verification"] = new JsonObject
            {
                ["kind"] = build.Verification.Kind,
                ["reportId"] = build.Verification.ReportId
            }
        };
        string hash = "sha256:" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(CanonicalJson.Bytes(hashed)));
        return new SourceSetupPlan(build.Files, build.Variables, build.Snippets, build.Verification, hash);
    }

    internal static JsonArray Variables(IReadOnlyList<SourceSetupVariable> variables) =>
        new([.. variables.Select(variable => (JsonNode)new JsonObject
        {
            ["component"] = variable.Component,
            ["name"] = variable.Name,
            ["value"] = variable.Value
        })]);

    /// <summary>
    /// Redacts the type's synthetic sample with the collector's assigned privacy profile when it
    /// has one, otherwise Bower's built-in rules. Only the redacted form is returned.
    /// </summary>
    public static SourceSetupPreview Preview(
        SourceSetupType type,
        IReadOnlyDictionary<string, string> values,
        string? assignedProfileContent,
        string? assignedProfileLabel)
    {
        string sample = Json(type.Sample(values));
        if (assignedProfileContent is not null)
        {
            PrivacyProfilePreview profile = PrivacyProfileInspector.Preview(assignedProfileContent, sample);
            return new SourceSetupPreview(
                profile.Valid,
                profile.Redacted,
                profile.Findings,
                $"Privacy profile {assignedProfileLabel} assigned to this collector, plus Bower's built-in rules.");
        }

        PrivacyScanResult result = new PrivacyEngine().RedactJson(sample);
        return result.Succeeded
            ? new SourceSetupPreview(
                true,
                result.RedactedJson,
                [.. result.Findings.Select(finding => new PrivacyProfilePreviewFinding(
                    finding.DetectorId, PolicyApplicator.ActionLabel(finding.Action), finding.Path))],
                "Bower's built-in privacy rules. Packs and an assigned privacy profile can protect more.")
            : new SourceSetupPreview(false, null, [], "Bower's built-in privacy rules.");
    }

    /// <summary>Indented JSON with a trailing newline, written by the JSON writer (values are escaped).</summary>
    internal static string Json(JsonNode node)
    {
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { Indented = true }))
        {
            node.WriteTo(writer);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan) + "\n";
    }

    internal static string Quoted(string value) => Json(JsonValue.Create(value)!).TrimEnd();

    internal static SetupCheck Fail(string id, string message, string fix) =>
        new(id, SetupCheckStates.Fail, message, fix);

    internal static SetupCheck Warn(string id, string message, string fix) =>
        new(id, SetupCheckStates.Warn, message, fix);

    internal static string? Optional(IReadOnlyDictionary<string, string> values, string id) =>
        values.TryGetValue(id, out string? value) ? value : null;

    internal static IReadOnlyList<string> List(IReadOnlyDictionary<string, string> values, string id) =>
        Optional(values, id) is { } text ? text.Split(',') : [];

    /// <summary>The source expectations document that makes the collector report this source on its heartbeat.</summary>
    internal static SourceSetupFile Expectations(string application, string environment, string minutes) =>
        new(
            "source-expectations.json",
            "/etc/bower/source-expectations.json",
            "Tells the collector to expect this source and report it on its heartbeat. If the collector already has a "
            + "BOWER_SOURCE_EXPECTATIONS file, add this entry to its sources list instead.",
            Json(new JsonObject
            {
                ["apiVersion"] = "bower.security/v1",
                ["kind"] = "SourceExpectations",
                ["sources"] = new JsonArray(new JsonObject
                {
                    ["application"] = application,
                    ["environment"] = environment,
                    ["maximumSilenceMinutes"] = int.Parse(minutes, System.Globalization.CultureInfo.InvariantCulture)
                })
            }));

    internal static SourceSetupVariable ExpectationsVariable() =>
        new("collector", "BOWER_SOURCE_EXPECTATIONS", "/etc/bower/source-expectations.json");

    internal static SourceSetupVerification ApplicationVerification(string application, string environment) =>
        new(
            "source",
            $"{application}/{environment}",
            $"The collector's heartbeat reports source {application}/{environment} as receiving events.");

    // ----- common fields -----

    internal static SourceFieldRule Application(string defaultValue, string help) => new(
        new SourceFieldDefinition("application", "Application name", SourceFieldKinds.Text, true, help, defaultValue, MaximumLength: 128),
        IdentifierPattern(),
        "Use letters, digits, dots, hyphens and underscores only.");

    internal static SourceFieldRule Environment() => new(
        new SourceFieldDefinition(
            "environment", "Environment", SourceFieldKinds.Text, true,
            "The environment name events carry, for example production.", "production", MaximumLength: 64),
        IdentifierPattern(),
        "Use letters, digits, dots, hyphens and underscores only.");

    internal static SourceFieldRule Silence() => new(new SourceFieldDefinition(
        "maximumSilenceMinutes", "Longest quiet time (minutes)", SourceFieldKinds.Number, true,
        "Bower flags the source when no event arrives for this long. 1 to 10080 minutes (one week).",
        "60", Minimum: 1, Maximum: 10_080, MaximumLength: 5));

    internal static SourceFieldRule CollectorUrl(string defaultValue) => new(new SourceFieldDefinition(
        "collectorUrl", "Collector address", SourceFieldKinds.Url, true,
        "Where the forwarder sends events. Use HTTPS; plain HTTP is allowed only for loopback or a single-label Compose service name.",
        defaultValue, "https://collector.example.org:4319", MaximumLength: 512));

    internal static SourceFieldRule IngestTokenFile() => new(new SourceFieldDefinition(
        "ingestTokenFile", "Ingest token file", SourceFieldKinds.SecretReference, true,
        "The path of a file that holds the collector ingest token on the forwarder's host. Enter the path, never the token.",
        Placeholder: "/run/secrets/bower-ingest-token", MaximumLength: 260));

    internal static SourceFieldRule AgentId(string help) => new(
        new SourceFieldDefinition("agentId", "Forwarder name", SourceFieldKinds.Text, false, help, MaximumLength: 128),
        IdentifierPattern(),
        "Use letters, digits, dots, hyphens and underscores only.");

    // ----- field checks -----

    private static (string Message, string Fix)? Check(SourceFieldRule rule, string text)
    {
        SourceFieldDefinition field = rule.Definition;
        if (field.Kind != SourceFieldKinds.AddressList && text.AsSpan().ContainsAny(ControlCharacters))
        {
            return ("must be a single line of text.", "Remove line breaks and tabs.");
        }

        switch (field.Kind)
        {
            case SourceFieldKinds.Number:
                return int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int number)
                    && number >= (field.Minimum ?? int.MinValue) && number <= (field.Maximum ?? int.MaxValue)
                    ? null
                    : ($"must be a whole number from {field.Minimum} to {field.Maximum}.", field.Help);
            case SourceFieldKinds.Choice:
                return field.Options!.Any(option => option.Value == text)
                    ? null
                    : ("is not one of the choices.", $"Choose one of: {string.Join(", ", field.Options!.Select(option => option.Label))}.");
            case SourceFieldKinds.Boolean:
                return text is "true" or "false" ? null : ("must be yes or no.", field.Help);
            case SourceFieldKinds.AddressList:
                return CheckAddresses(text);
            case SourceFieldKinds.NameList:
                string[] names = Items(text);
                return names.Length > MaximumListItems
                    ? ($"has more than {MaximumListItems} entries.", "List fewer entries.")
                    : names.All(name => rule.Pattern?.IsMatch(name) ?? true)
                        ? null
                        : ("contains an entry that is not valid.", rule.PatternFix ?? field.Help);
            case SourceFieldKinds.FilePath:
                return AbsolutePath(text) ? null : ("must be an absolute file path.", PathFix);
            case SourceFieldKinds.SecretReference:
                return AbsolutePath(text) || (field.KeyVaultAllowed && KeyVaultSecretUrl().IsMatch(text))
                    ? null
                    : (
                        "must say where the secret is stored, not the secret itself.",
                        field.KeyVaultAllowed
                            ? "Enter an absolute file path or a Key Vault secret URL (https://<vault>.vault.azure.net/secrets/<name>). Never paste the secret."
                            : "Enter the absolute path of the file that holds it. Never paste the secret.");
            case SourceFieldKinds.Url:
                return CollectorUrlValid(text)
                    ? null
                    : (
                        "must be an HTTPS address (HTTP only for loopback or a single-label service name) without a user name, query or fragment.",
                        field.Help);
            default:
                return rule.Pattern is null || rule.Pattern.IsMatch(text)
                    ? null
                    : ("contains characters that are not allowed.", rule.PatternFix ?? field.Help);
        }
    }

    private const string PathFix =
        "Enter a full path such as /etc/bower/server.pem or C:\\ProgramData\\Bower\\server.pem, without '..'.";

    private static (string Message, string Fix)? CheckAddresses(string text)
    {
        string[] items = Items(text);
        if (items.Length == 0)
        {
            return ("needs at least one address or range.", "Enter one IP address or CIDR range per line, for example 10.20.0.0/24.");
        }

        if (items.Length > MaximumListItems)
        {
            return ($"has more than {MaximumListItems} entries.", "Combine addresses into CIDR ranges.");
        }

        foreach (string item in items)
        {
            if (!(item.Contains('/', StringComparison.Ordinal) ? NetworkWithoutHostBits(item) : IPAddress.TryParse(item, out _))
                || item.Contains('%', StringComparison.Ordinal))
            {
                return (
                    "contains an entry that is not an IP address or a CIDR range with its host bits zero.",
                    "Enter addresses like 10.20.0.5 or ranges like 10.20.0.0/24, one per line.");
            }
        }

        return null;
    }

    // The syslog loader refuses ranges with host bits set, so they are refused here too.
    private static bool NetworkWithoutHostBits(string item) =>
        IPNetwork.TryParse(item, out IPNetwork network)
        && IPAddress.TryParse(item.AsSpan(0, item.IndexOf('/', StringComparison.Ordinal)), out IPAddress? address)
        && network.BaseAddress.Equals(address);

    private static string Canonical(SourceFieldDefinition field, string text) =>
        field.Kind switch
        {
            SourceFieldKinds.AddressList => string.Join(
                ',',
                Items(text).Select(item => item.Contains('/', StringComparison.Ordinal)
                    ? IPNetwork.Parse(item).ToString()
                    : IPAddress.Parse(item).ToString()).Distinct(StringComparer.Ordinal)),
            SourceFieldKinds.NameList => string.Join(',', Items(text).Distinct(StringComparer.Ordinal)),
            SourceFieldKinds.Number => int.Parse(text, System.Globalization.CultureInfo.InvariantCulture)
                .ToString(System.Globalization.CultureInfo.InvariantCulture),
            _ => text
        };

    private static string[] Items(string text) =>
        text.Split([',', '\n', '\r', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static bool AbsolutePath(string text) =>
        (PosixPath().IsMatch(text) || WindowsPath().IsMatch(text))
        && !text.Split('/', '\\').Any(segment => segment == "..");

    internal static bool CollectorUrlValid(string text)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? uri)
            || uri.UserInfo.Length > 0
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || !SafeUrl().IsMatch(text))
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps
            || (uri.Scheme == Uri.UriSchemeHttp && (uri.IsLoopback
                || (uri.HostNameType == UriHostNameType.Dns && !uri.Host.Contains('.', StringComparison.Ordinal))));
    }

    private static readonly SearchValues<char> ControlCharacters = SearchValues.Create(
        [.. Enumerable.Range(0, 32).Select(value => (char)value), '\u007f']);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$")]
    internal static partial Regex IdentifierPattern();

    [GeneratedRegex("^/[A-Za-z0-9._/ -]*$")]
    private static partial Regex PosixPath();

    [GeneratedRegex(@"^[A-Za-z]:\\[A-Za-z0-9._\\ ()-]*$")]
    private static partial Regex WindowsPath();

    [GeneratedRegex("^https://[a-z0-9-]{3,24}\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]{1,127}(/[a-f0-9]{32})?$")]
    internal static partial Regex KeyVaultSecretUrl();

    [GeneratedRegex("^https?://[A-Za-z0-9.:\\[\\]-]+(/[A-Za-z0-9._~/-]*)?$")]
    private static partial Regex SafeUrl();
}

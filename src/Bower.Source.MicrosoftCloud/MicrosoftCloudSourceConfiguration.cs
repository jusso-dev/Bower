using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.MicrosoftCloud;

/// <summary>
/// BOWER_MICROSOFT_CONFIG: the Microsoft cloud sources an operator selected for security
/// signal, each routed to one signed pack parser. There is no collect-everything form:
/// every input names one source kind, one tenant and one parser.
/// </summary>
/// <param name="PollIntervalSeconds">Wait between polls once an input has caught up.</param>
public sealed record MicrosoftCloudSourceConfiguration(
    string ApiVersion,
    string Kind,
    IReadOnlyList<MicrosoftCloudInputOptions> Inputs,
    int PollIntervalSeconds = 300);

/// <summary>The active parser of a loaded signed pack that maps this input's records.</summary>
public sealed record MicrosoftCloudRoute(string Pack, int Parser);

/// <summary>
/// An app registration that reads one tenant with a certificate (for example an MSP reading
/// a customer tenant). Client secrets are not supported: the certificate file is the only
/// credential, and it stays on disk with the collector's own file permissions.
/// </summary>
public sealed record MicrosoftCloudCertificateCredential(string ClientId, string CertificatePath);

/// <param name="Id">1 to 63 lowercase letters, digits or hyphens; names the cursor (<c>mscloud:&lt;id&gt;</c>).</param>
/// <param name="SourceKind">One of <see cref="MicrosoftCloudKinds"/>.</param>
/// <param name="TenantId">The Entra tenant the input reads (a GUID).</param>
/// <param name="Credential">Null: the collector's own Azure credential (BOWER_AZURE_CREDENTIAL).</param>
/// <param name="StartLookbackHours">How far back the first poll reads (no cursor yet).</param>
/// <param name="SettleDelaySeconds">A window ends this long before now, so late-written records are in the next one.</param>
/// <param name="OverlapSeconds">Each window starts this long before the last committed bound; re-read records deduplicate.</param>
/// <param name="MaxRecordsPerPoll">Records handed to the pack parser per poll before the cursor is committed.</param>
/// <param name="ComplianceStates">intune-device-compliance only: the device compliance states that become records.</param>
/// <param name="EnvironmentUrl">dataverse-audit only: the environment's Web API host (https://org.crm6.dynamics.com).</param>
/// <param name="AuditActions">dataverse-audit only: Dataverse audit action codes to request (default security-relevant).</param>
/// <param name="RecordTypes">power-platform-activity only: Office 365 audit record types to keep (default all Power Platform types).</param>
/// <param name="PublisherIdentifier">power-platform-activity only: the publisher GUID sent for throttling quota.</param>
/// <param name="StartSubscription">power-platform-activity only: start the Audit.General subscription if it is missing. Never stopped.</param>
public sealed record MicrosoftCloudInputOptions(
    string Id,
    string SourceKind,
    string TenantId,
    MicrosoftCloudRoute Route,
    MicrosoftCloudCertificateCredential? Credential = null,
    int StartLookbackHours = 24,
    int SettleDelaySeconds = 300,
    int OverlapSeconds = 600,
    int MaxRecordsPerPoll = 1_000,
    IReadOnlyList<string>? ComplianceStates = null,
    string? EnvironmentUrl = null,
    IReadOnlyList<int>? AuditActions = null,
    IReadOnlyList<int>? RecordTypes = null,
    string? PublisherIdentifier = null,
    bool StartSubscription = false)
{
    /// <summary>Durable cursor key in the queue database's source cursor table.</summary>
    [JsonIgnore]
    public string SourceId => "mscloud:" + Id;
}

/// <summary>Source kinds. Each kind names one API and one record shape.</summary>
public static class MicrosoftCloudKinds
{
    /// <summary>Microsoft Graph <c>deviceManagement/auditEvents</c>.</summary>
    public const string IntuneAudit = "intune-audit";

    /// <summary>Daily Microsoft Graph <c>deviceManagement/managedDevices</c> compliance snapshot.</summary>
    public const string IntuneDeviceCompliance = "intune-device-compliance";

    public static readonly IReadOnlyList<string> All = [IntuneAudit, IntuneDeviceCompliance];
}

public static class MicrosoftCloudSourceConfigurationLoader
{
    public const int MaximumInputs = 16;
    private const int MaximumBytes = 262_144;

    /// <summary>Default compliance states kept by the compliance snapshot: everything that needs attention.</summary>
    public static readonly IReadOnlyList<string> DefaultComplianceStates = ["noncompliant", "inGracePeriod", "conflict", "error"];

    private static readonly HashSet<string> ComplianceStateNames = new(
        ["unknown", "compliant", "noncompliant", "conflict", "error", "inGracePeriod", "configManager"],
        StringComparer.Ordinal);

    public static MicrosoftCloudSourceConfiguration LoadFile(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Microsoft cloud source configuration file does not exist.", path);
        }

        if (info.Length > MaximumBytes)
        {
            throw new InvalidDataException("Microsoft cloud source configuration file exceeds 256 KiB.");
        }

        return Parse(File.ReadAllText(path));
    }

    public static MicrosoftCloudSourceConfiguration Parse(string json)
    {
        MicrosoftCloudSourceConfiguration? configuration;
        try
        {
            configuration = JsonSerializer.Deserialize(json, MicrosoftCloudJsonContext.Default.MicrosoftCloudSourceConfiguration);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Microsoft cloud source configuration is invalid: {exception.Message}", exception);
        }

        if (configuration is null
            || !string.Equals(configuration.ApiVersion, "bower.security/v1", StringComparison.Ordinal)
            || !string.Equals(configuration.Kind, "MicrosoftCloudSource", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Microsoft cloud source configuration needs apiVersion bower.security/v1 and kind MicrosoftCloudSource.");
        }

        if (configuration.Inputs is not { Count: >= 1 and <= MaximumInputs })
        {
            throw new InvalidDataException($"Microsoft cloud source configuration must list 1 to {MaximumInputs} inputs.");
        }

        if (configuration.PollIntervalSeconds is < 60 or > 86_400)
        {
            throw new InvalidDataException("Microsoft cloud pollIntervalSeconds must be between 60 and 86400.");
        }

        HashSet<string> ids = new(StringComparer.Ordinal);
        foreach (MicrosoftCloudInputOptions input in configuration.Inputs)
        {
            Validate(input);
            if (!ids.Add(input.Id))
            {
                throw new InvalidDataException($"Microsoft cloud input {input.Id} is listed more than once.");
            }
        }

        return configuration;
    }

    private static void Validate(MicrosoftCloudInputOptions input)
    {
        if (input is null || !IsInputId(input.Id))
        {
            throw new InvalidDataException(
                "Microsoft cloud input id must be 1 to 63 lowercase letters, digits or hyphens and start with a letter or digit.");
        }

        string id = input.Id;
        if (!MicrosoftCloudKinds.All.Contains(input.SourceKind, StringComparer.Ordinal))
        {
            throw Invalid(id, $"sourceKind must be one of {string.Join(", ", MicrosoftCloudKinds.All)}.");
        }

        if (!Guid.TryParseExact(input.TenantId, "D", out Guid tenant) || tenant == Guid.Empty
            || !string.Equals(input.TenantId, tenant.ToString("D"), StringComparison.Ordinal))
        {
            throw Invalid(id, "tenantId must be a lowercase GUID.");
        }

        if (input.Route is null || string.IsNullOrWhiteSpace(input.Route.Pack) || input.Route.Parser < 0)
        {
            throw Invalid(id, "route needs a pack and a parser index of 0 or more.");
        }

        if (input.Credential is { } credential)
        {
            if (!Guid.TryParseExact(credential.ClientId, "D", out Guid client) || client == Guid.Empty)
            {
                throw Invalid(id, "credential.clientId must be a GUID.");
            }

            if (string.IsNullOrWhiteSpace(credential.CertificatePath) || !Path.IsPathFullyQualified(credential.CertificatePath))
            {
                throw Invalid(id, "credential.certificatePath must be an absolute path to a PEM or PFX certificate with its private key.");
            }
        }

        if (input.StartLookbackHours is < 1 or > 168)
        {
            throw Invalid(id, "startLookbackHours must be between 1 and 168.");
        }

        if (input.SettleDelaySeconds is < 0 or > 86_400)
        {
            throw Invalid(id, "settleDelaySeconds must be between 0 and 86400.");
        }

        if (input.OverlapSeconds is < 0 or > 86_400)
        {
            throw Invalid(id, "overlapSeconds must be between 0 and 86400.");
        }

        if (input.MaxRecordsPerPoll is < 1 or > 10_000)
        {
            throw Invalid(id, "maxRecordsPerPoll must be between 1 and 10000.");
        }

        bool compliance = input.SourceKind == MicrosoftCloudKinds.IntuneDeviceCompliance;
        if (input.ComplianceStates is not null)
        {
            if (!compliance)
            {
                throw Invalid(id, "complianceStates applies to intune-device-compliance only.");
            }

            if (input.ComplianceStates.Count is < 1 or > 7
                || input.ComplianceStates.Any(state => state is null || !ComplianceStateNames.Contains(state))
                || input.ComplianceStates.Distinct(StringComparer.Ordinal).Count() != input.ComplianceStates.Count)
            {
                throw Invalid(id, $"complianceStates must list distinct values from {string.Join(", ", ComplianceStateNames.Order(StringComparer.Ordinal))}.");
            }
        }

        if (input.EnvironmentUrl is not null || input.AuditActions is not null)
        {
            throw Invalid(id, "environmentUrl and auditActions apply to dataverse-audit only.");
        }

        if (input.RecordTypes is not null || input.PublisherIdentifier is not null || input.StartSubscription)
        {
            throw Invalid(id, "recordTypes, publisherIdentifier and startSubscription apply to power-platform-activity only.");
        }
    }

    internal static IReadOnlyList<string> ComplianceStates(MicrosoftCloudInputOptions input) =>
        input.ComplianceStates ?? DefaultComplianceStates;

    private static bool IsInputId(string? id) =>
        id is { Length: >= 1 and <= 63 }
        && (char.IsAsciiLetterLower(id[0]) || char.IsAsciiDigit(id[0]))
        && id.All(character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character) || character == '-');

    private static InvalidDataException Invalid(string id, string message) => new($"Microsoft cloud input {id}: {message}");

    internal static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffff'Z'", CultureInfo.InvariantCulture);
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    NumberHandling = JsonNumberHandling.Strict,
    PropertyNameCaseInsensitive = false,
    AllowDuplicateProperties = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(MicrosoftCloudSourceConfiguration))]
[JsonSerializable(typeof(IReadOnlyList<MicrosoftCloudInputStatus>))]
internal sealed partial class MicrosoftCloudJsonContext : JsonSerializerContext;

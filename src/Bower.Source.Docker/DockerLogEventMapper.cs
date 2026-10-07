using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Contracts;

namespace Bower.Source.Docker;

public enum DockerMappingKind
{
    /// <summary>Line was not security-relevant; dropped at the sidecar.</summary>
    Unrecognised,

    /// <summary>The application printed a Bower event envelope as JSON.</summary>
    SemanticEvent,

    /// <summary>A recognised authentication line mapped to a typed event.</summary>
    RecognisedSignal
}

public sealed record DockerMappedEvent(DockerMappingKind Kind, string? Json, string? Detector);

public sealed record DockerMapperOptions
{
    public required string SidecarId { get; init; }

    public string Version { get; init; } = "0.1.0";

    public string DefaultEnvironment { get; init; } = "production";
}

/// <summary>
/// Turns container log lines into Bower candidate events. Opinionated on purpose: only
/// Bower JSON events and recognised authentication signals leave the sidecar. Every
/// event is then redacted and policy-checked by the collector.
/// </summary>
public sealed partial class DockerLogEventMapper(DockerMapperOptions options)
{
    public const string SourceAdapter = "docker.json-file";

    private static readonly JsonSerializerOptions EnvelopeOptions = BowerJson.Options;

    private readonly string configurationHash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(
        Encoding.UTF8.GetBytes($"{options.SidecarId}\u001f{options.Version}\u001f{options.DefaultEnvironment}")));

    public DockerMappedEvent Map(DockerContainer container, DockerLogRecord record, DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(container);
        ArgumentNullException.ThrowIfNull(record);

        string text = record.Text.Trim();
        if (text.Length == 0)
        {
            return new DockerMappedEvent(DockerMappingKind.Unrecognised, null, null);
        }

        if (text[0] == '{' && TryMapSemantic(container, text) is { } semantic)
        {
            return new DockerMappedEvent(DockerMappingKind.SemanticEvent, semantic, "bower-envelope");
        }

        foreach (AuthenticationPattern pattern in Patterns)
        {
            Match match;
            try
            {
                match = pattern.Regex.Match(text);
            }
            catch (RegexMatchTimeoutException)
            {
                continue;
            }

            if (!match.Success)
            {
                continue;
            }

            string json = JsonSerializer.Serialize(
                BuildSignal(container, record, observedAt, pattern, match),
                EnvelopeOptions);
            return new DockerMappedEvent(DockerMappingKind.RecognisedSignal, json, pattern.Id);
        }

        return new DockerMappedEvent(DockerMappingKind.Unrecognised, null, null);
    }

    /// <summary>
    /// Accepts a line that is already a Bower envelope and adds container labels.
    /// Validation, redaction and policy stay with the collector.
    /// </summary>
    private static string? TryMapSemantic(DockerContainer container, string text)
    {
        JsonObject? envelope;
        try
        {
            envelope = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { MaxDepth = 32 }) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }

        if (envelope is null
            || envelope["schemaVersion"] is not JsonValue
            || envelope["eventType"] is not JsonValue
            || envelope["eventId"] is not JsonValue)
        {
            return null;
        }

        JsonObject labels = envelope["labels"] as JsonObject ?? [];
        labels["docker.containerId"] = container.ShortId;
        labels["docker.containerName"] = container.Name;
        labels["docker.image"] = container.Image;
        envelope["labels"] = labels;
        return envelope.ToJsonString();
    }

    private SecurityEventEnvelope BuildSignal(
        DockerContainer container,
        DockerLogRecord record,
        DateTimeOffset observedAt,
        AuthenticationPattern pattern,
        Match match)
    {
        // Deterministic id: re-reading the same bytes yields the same event, so the
        // collector queue deduplicates replays after restarts or rotation.
        string originalId = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{container.Id}\u001f{record.FileFingerprint}\u001f{record.StartOffset}")))[..32];
        string lineDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(record.Text)));
        string? user = Group(match, "user");
        string? address = Group(match, "ip");
        DateTimeOffset generated = record.Time ?? observedAt;

        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = $"docker-{originalId}",
            EventOriginalId = originalId,
            TimeGenerated = generated,
            TimeObserved = observedAt,
            EventCategory = SecurityEventCategories.Authentication,
            EventType = pattern.EventType,
            EventAction = pattern.Action,
            EventResult = EventResult.Failure,
            EventSeverity = pattern.EventType == SecurityEventTypes.AccountLockout
                ? EventSeverity.High
                : EventSeverity.Medium,
            EventOutcomeReason = pattern.Reason,
            Application = new ApplicationContext
            {
                Name = Label(container, "bower.application") ?? container.Name,
                Environment = Label(container, "bower.environment") ?? options.DefaultEnvironment,
                Instance = container.Name
            },
            Actor = user is null ? null : new ActorContext { Username = user },
            Source = address is not null && IPAddress.TryParse(address, out _)
                ? new SourceContext { IpAddress = address }
                : null,
            Target = new TargetContext { Type = "container", Id = container.ShortId, Name = container.Name },
            Request = new RequestContext { CorrelationId = $"docker-{originalId}" },
            Collector = new CollectorContext
            {
                Id = options.SidecarId,
                Version = options.Version,
                SourceAdapter = SourceAdapter,
                ConfigurationHash = configurationHash,
                ReceivedAt = observedAt
            },
            // No raw line: the digest lets analysts find it in the container log.
            Labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["docker.containerId"] = container.ShortId,
                ["docker.containerName"] = container.Name,
                ["docker.image"] = container.Image,
                ["docker.stream"] = record.Stream,
                ["docker.lineSha256"] = lineDigest,
                ["bower.detector"] = pattern.Id
            }
        };
    }

    private static string? Label(DockerContainer container, string name) =>
        container.Labels.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? (value.Length <= 128 ? value : value[..128])
            : null;

    private static string? Group(Match match, string name)
    {
        Group group = match.Groups[name];
        if (!group.Success || group.Value.Length == 0)
        {
            return null;
        }

        string value = group.Value.Trim('\'', '"', '[', ']');
        return value.Length is > 0 and <= 256 ? value : null;
    }

    private sealed record AuthenticationPattern(
        string Id,
        Regex Regex,
        string EventType,
        string Action,
        string Reason);

    private static readonly AuthenticationPattern[] Patterns =
    [
        new("sshd.max-attempts", MaxAttemptsRegex(), SecurityEventTypes.AccountLockout,
            "authentication.lockout", "MaximumAttemptsExceeded"),
        new("sshd.failed-password", FailedPasswordRegex(), SecurityEventTypes.AuthenticationFailure,
            "authentication.attempt", "InvalidCredentials"),
        new("sshd.invalid-user", InvalidUserRegex(), SecurityEventTypes.AuthenticationFailure,
            "authentication.attempt", "UnknownUser"),
        new("pam.auth-failure", PamFailureRegex(), SecurityEventTypes.AuthenticationFailure,
            "authentication.attempt", "InvalidCredentials"),
        new("nginx.basic-auth-mismatch", NginxMismatchRegex(), SecurityEventTypes.AuthenticationFailure,
            "authentication.attempt", "InvalidCredentials"),
        new("nginx.basic-auth-unknown-user", NginxUnknownUserRegex(), SecurityEventTypes.AuthenticationFailure,
            "authentication.attempt", "UnknownUser")
    ];

    [GeneratedRegex(
        @"maximum authentication attempts exceeded for (?:invalid user )?(?<user>\S+) from (?<ip>[0-9a-fA-F:.]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 50)]
    private static partial Regex MaxAttemptsRegex();

    [GeneratedRegex(
        @"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?<user>\S+) from (?<ip>[0-9a-fA-F:.]+)",
        RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 50)]
    private static partial Regex FailedPasswordRegex();

    [GeneratedRegex(
        @"Invalid user (?<user>\S+) from (?<ip>[0-9a-fA-F:.]+)",
        RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 50)]
    private static partial Regex InvalidUserRegex();

    [GeneratedRegex(
        @"pam_unix\([^)]*:auth\): authentication failure;.*?(?:rhost=(?<ip>[0-9a-fA-F:.]*))?\s+user=(?<user>\S+)",
        RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 50)]
    private static partial Regex PamFailureRegex();

    [GeneratedRegex(
        @"user ""(?<user>[^""]{1,128})"": password mismatch, client: (?<ip>[0-9a-fA-F:.]+)",
        RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 50)]
    private static partial Regex NginxMismatchRegex();

    [GeneratedRegex(
        @"user ""(?<user>[^""]{1,128})"" was not found in "".*?"", client: (?<ip>[0-9a-fA-F:.]+)",
        RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 50)]
    private static partial Regex NginxUnknownUserRegex();
}

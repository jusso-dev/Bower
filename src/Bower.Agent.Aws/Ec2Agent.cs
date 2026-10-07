using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Redaction.Privacy;

namespace Bower.Agent.Aws;

public sealed record Ec2InstanceMetadata(
    string InstanceId,
    string AccountId,
    string Region,
    string AvailabilityZone,
    string? VpcId,
    string? SubnetId,
    string? AmiId,
    IReadOnlyList<string> SecurityGroups,
    IReadOnlyDictionary<string, string> Tags,
    string? AutoScalingGroup,
    string? EcsCluster,
    string? EksCluster);

public enum HostLogKind
{
    WindowsEvent,
    Sysmon,
    PowerShell,
    Syslog,
    Journald,
    Auditd,
    Auth,
    Docker,
    Custom
}

public sealed record HostLogSource(
    string Id,
    HostLogKind Kind,
    string Path,
    bool Enabled = true);

public sealed record Ec2AgentOptions
{
    public required string AgentId { get; init; }

    public string Environment { get; init; } = "production";

    public string ApplicationName { get; init; } = "bower-ec2-agent";

    public IReadOnlyList<HostLogSource> Sources { get; init; } = [];

    public int MaximumLineBytes { get; init; } = 65_536;

    public int MaximumBatchLines { get; init; } = 1_000;

    /// <summary>
    /// Adds a privacy-redacted, 256-character preview of each line to labels. Off by default:
    /// host lines are raw payloads and may hold data no detector recognises.
    /// </summary>
    public bool IncludeRedactedLinePreview { get; init; }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(AgentId);
        if (AgentId.Length > 128)
        {
            throw new ArgumentException("Agent id cannot exceed 128 characters.");
        }

        if (MaximumLineBytes is < 256 or > 1_048_576)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumLineBytes));
        }

        if (MaximumBatchLines is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumBatchLines));
        }

        foreach (HostLogSource source in Sources)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(source.Id);
            ArgumentException.ThrowIfNullOrWhiteSpace(source.Path);
            if (source.Path.Contains("..", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Source path for '{source.Id}' must not contain '..'.");
            }
        }
    }
}

public sealed class Ec2MetadataClient
{
    private readonly Func<string, Task<string?>> fetch;

    public Ec2MetadataClient(Func<string, Task<string?>>? fetch = null)
    {
        this.fetch = fetch ?? (_ => Task.FromResult<string?>(null));
    }

    /// <summary>Creates a client that reads the local instance metadata service with IMDSv2.</summary>
    public static Ec2MetadataClient CreateImdsV2(ImdsV2Client imds) =>
        new(key => imds.FetchAsync(key, CancellationToken.None));

    public async Task<Ec2InstanceMetadata?> GetAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? instanceId = await fetch("instance-id").ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(instanceId))
        {
            return null;
        }

        string accountId = await fetch("identity-account-id").ConfigureAwait(false) ?? "000000000000";
        string region = await fetch("region").ConfigureAwait(false) ?? "unknown";
        string az = await fetch("availability-zone").ConfigureAwait(false) ?? region;
        string? vpc = await fetch("vpc-id").ConfigureAwait(false);
        string? subnet = await fetch("subnet-id").ConfigureAwait(false);
        string? ami = await fetch("ami-id").ConfigureAwait(false);
        string? securityGroupsRaw = await fetch("security-groups").ConfigureAwait(false);
        string? tagsRaw = await fetch("tags").ConfigureAwait(false);
        string? asg = await fetch("auto-scaling-group").ConfigureAwait(false);
        string? ecs = await fetch("ecs-cluster").ConfigureAwait(false);
        string? eks = await fetch("eks-cluster").ConfigureAwait(false);

        Dictionary<string, string> tags = new(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(tagsRaw))
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(tagsRaw);
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty property in document.RootElement.EnumerateObject())
                    {
                        tags[property.Name] = property.Value.ToString();
                    }
                }
            }
            catch (JsonException)
            {
                // ignore malformed tags payload
            }
        }

        string[] securityGroups = string.IsNullOrWhiteSpace(securityGroupsRaw)
            ? []
            : securityGroupsRaw.Split(
                [',', '\n', ' '],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return new Ec2InstanceMetadata(
            instanceId,
            accountId,
            region,
            az,
            vpc,
            subnet,
            ami,
            securityGroups,
            tags,
            asg,
            ecs,
            eks);
    }
}

public sealed class Ec2HostCollector
{
    private readonly Ec2AgentOptions options;
    private readonly Ec2InstanceMetadata? metadata;
    private readonly TimeProvider clock;
    private readonly string configurationHash;
    private readonly PrivacyEngine? previewRedactor;

    public Ec2HostCollector(
        Ec2AgentOptions options,
        Ec2InstanceMetadata? metadata = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        this.options = options;
        this.metadata = metadata;
        this.clock = clock ?? TimeProvider.System;
        configurationHash = HashConfiguration(options);
        previewRedactor = options.IncludeRedactedLinePreview ? new PrivacyEngine() : null;
    }

    /// <summary>
    /// Maps host log lines to events. <paramref name="firstLineNumber"/> is the position of
    /// the first line in its source (for example the file line number), so re-reading the
    /// same lines yields the same event ids and the queue deduplicates them.
    /// Oversized lines become flagged events without content instead of failing the batch.
    /// </summary>
    public IReadOnlyList<SecurityEventEnvelope> CollectLines(
        string sourceId,
        IEnumerable<string> lines,
        DateTimeOffset? observedAt = null,
        long firstLineNumber = 0)
    {
        HostLogSource source = options.Sources.FirstOrDefault(item =>
            string.Equals(item.Id, sourceId, StringComparison.Ordinal))
            ?? throw new ArgumentException($"Unknown host source '{sourceId}'.");

        if (!source.Enabled)
        {
            return [];
        }

        ArgumentOutOfRangeException.ThrowIfNegative(firstLineNumber);
        DateTimeOffset observed = observedAt ?? clock.GetUtcNow();
        List<SecurityEventEnvelope> events = [];
        long lineNumber = firstLineNumber - 1;
        foreach (string line in lines)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (events.Count >= options.MaximumBatchLines)
            {
                throw new InvalidOperationException(
                    $"Host source '{sourceId}' exceeded maximum batch of {options.MaximumBatchLines} lines.");
            }

            int size = Encoding.UTF8.GetByteCount(line);
            bool oversized = size > options.MaximumLineBytes;
            string lineDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(line)));
            string originalId = Convert.ToHexStringLower(
                    SHA256.HashData(Encoding.UTF8.GetBytes(
                        $"{sourceId}\u001f{source.Path}\u001f{lineNumber}\u001f{lineDigest}")))[..24];

            // Raw host lines never go into labels by default; the digest lets analysts match
            // the event to the source line on the host.
            Dictionary<string, string> labels = new(StringComparer.Ordinal)
            {
                ["host.sourceId"] = source.Id,
                ["host.kind"] = source.Kind.ToString(),
                ["host.path"] = source.Path,
                ["host.lineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["host.lineSha256"] = lineDigest,
                ["host.lineBytes"] = size.ToString(System.Globalization.CultureInfo.InvariantCulture)
            };
            if (oversized)
            {
                labels["host.lineTruncated"] = "true";
            }
            else if (previewRedactor is not null)
            {
                string preview = line.Length <= 256 ? line : line[..256];
                PrivacyTextResult redacted = previewRedactor.RedactText(preview);
                if (redacted.Succeeded && redacted.RedactedText is not null)
                {
                    labels["host.linePreview"] = redacted.RedactedText;
                }
            }

            EnrichLabels(labels);
            // Classify on the line only when it is within bounds.
            string classified = oversized ? string.Empty : line;

            events.Add(
                new SecurityEventEnvelope
                {
                    SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
                    EventId = $"ec2-{originalId}",
                    EventOriginalId = originalId,
                    TimeGenerated = observed,
                    TimeObserved = observed,
                    EventCategory = MapCategory(source.Kind, classified),
                    EventType = MapEventType(source.Kind),
                    EventAction = MapAction(source.Kind, classified),
                    EventResult = MapResult(classified),
                    EventSeverity = MapSeverity(classified),
                    Application = new ApplicationContext
                    {
                        Name = options.ApplicationName,
                        Environment = options.Environment,
                        Instance = metadata?.InstanceId,
                        TenantId = metadata?.AccountId
                    },
                    Source = new SourceContext
                    {
                        Hostname = metadata?.InstanceId
                    },
                    Target = new TargetContext
                    {
                        Type = "host-log",
                        Name = source.Path
                    },
                    Collector = new CollectorContext
                    {
                        Id = options.AgentId,
                        Version = "0.1.0",
                        SourceAdapter = "aws.ec2-agent",
                        ConfigurationHash = configurationHash,
                        ReceivedAt = observed
                    },
                    Labels = labels
                });
        }

        return events;
    }

    public static IReadOnlyList<HostLogSource> DefaultSourcesForPlatform(bool windows)
    {
        return windows
            ?
            [
                new HostLogSource("windows-security", HostLogKind.WindowsEvent, "Security"),
                new HostLogSource("sysmon", HostLogKind.Sysmon, "Microsoft-Windows-Sysmon/Operational"),
                new HostLogSource("powershell", HostLogKind.PowerShell, "Microsoft-Windows-PowerShell/Operational")
            ]
            :
            [
                new HostLogSource("syslog", HostLogKind.Syslog, "/var/log/syslog"),
                new HostLogSource("auth", HostLogKind.Auth, "/var/log/auth.log"),
                new HostLogSource("auditd", HostLogKind.Auditd, "/var/log/audit/audit.log"),
                new HostLogSource("docker", HostLogKind.Docker, "/var/lib/docker/containers")
            ];
    }

    private static string HashConfiguration(Ec2AgentOptions options)
    {
        StringBuilder material = new();
        material.Append(options.AgentId).Append('\u001f')
            .Append(options.Environment).Append('\u001f')
            .Append(options.ApplicationName).Append('\u001f')
            .Append(options.MaximumLineBytes).Append('\u001f')
            .Append(options.MaximumBatchLines).Append('\u001f')
            .Append(options.IncludeRedactedLinePreview);
        foreach (HostLogSource source in options.Sources.OrderBy(item => item.Id, StringComparer.Ordinal))
        {
            material.Append('\u001e')
                .Append(source.Id).Append('\u001f')
                .Append(source.Kind).Append('\u001f')
                .Append(source.Path).Append('\u001f')
                .Append(source.Enabled);
        }

        return "sha256:" + Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(material.ToString())));
    }

    private void EnrichLabels(Dictionary<string, string> labels)
    {
        if (metadata is null)
        {
            return;
        }

        labels["aws.instanceId"] = metadata.InstanceId;
        labels["aws.accountId"] = metadata.AccountId;
        labels["aws.region"] = metadata.Region;
        labels["aws.availabilityZone"] = metadata.AvailabilityZone;
        if (metadata.VpcId is not null) labels["aws.vpcId"] = metadata.VpcId;
        if (metadata.SubnetId is not null) labels["aws.subnetId"] = metadata.SubnetId;
        if (metadata.AmiId is not null) labels["aws.amiId"] = metadata.AmiId;
        if (metadata.SecurityGroups.Count > 0)
        {
            labels["aws.securityGroups"] = string.Join(',', metadata.SecurityGroups);
        }

        if (metadata.AutoScalingGroup is not null)
        {
            labels["aws.autoScalingGroup"] = metadata.AutoScalingGroup;
        }

        if (metadata.EcsCluster is not null) labels["aws.ecsCluster"] = metadata.EcsCluster;
        if (metadata.EksCluster is not null) labels["aws.eksCluster"] = metadata.EksCluster;
        foreach ((string key, string value) in metadata.Tags)
        {
            labels[$"aws.tag.{key}"] = value;
        }
    }

    private static string MapCategory(HostLogKind kind, string line)
    {
        if (line.Contains("Failed password", StringComparison.OrdinalIgnoreCase)
            || line.Contains("4625", StringComparison.Ordinal))
        {
            return SecurityEventCategories.Authentication;
        }

        return kind switch
        {
            HostLogKind.Auth => SecurityEventCategories.Authentication,
            HostLogKind.Auditd => SecurityEventCategories.AdministrativeActivity,
            HostLogKind.Docker => SecurityEventCategories.ApplicationSecurity,
            _ => SecurityEventCategories.ApplicationSecurity
        };
    }

    private static string MapEventType(HostLogKind kind)
    {
        return kind switch
        {
            HostLogKind.WindowsEvent => "host_windows_event",
            HostLogKind.Sysmon => "host_sysmon",
            HostLogKind.PowerShell => "host_powershell",
            HostLogKind.Syslog => "host_syslog",
            HostLogKind.Journald => "host_journald",
            HostLogKind.Auditd => "host_auditd",
            HostLogKind.Auth => "host_auth",
            HostLogKind.Docker => "host_docker",
            _ => "host_custom"
        };
    }

    private static string MapAction(HostLogKind kind, string line)
    {
        if (line.Contains("Failed password", StringComparison.OrdinalIgnoreCase))
        {
            return "authentication.failure";
        }

        return kind.ToString().ToLowerInvariant() + ".event";
    }

    private static EventResult MapResult(string line)
    {
        if (line.Contains("Failed", StringComparison.OrdinalIgnoreCase)
            || line.Contains("denied", StringComparison.OrdinalIgnoreCase)
            || line.Contains("4625", StringComparison.Ordinal))
        {
            return EventResult.Failure;
        }

        if (line.Contains("Accepted", StringComparison.OrdinalIgnoreCase)
            || line.Contains("4624", StringComparison.Ordinal))
        {
            return EventResult.Success;
        }

        return EventResult.Unknown;
    }

    private static EventSeverity MapSeverity(string line)
    {
        if (line.Contains("critical", StringComparison.OrdinalIgnoreCase))
        {
            return EventSeverity.Critical;
        }

        if (line.Contains("Failed", StringComparison.OrdinalIgnoreCase)
            || line.Contains("error", StringComparison.OrdinalIgnoreCase))
        {
            return EventSeverity.Medium;
        }

        return EventSeverity.Low;
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Contracts;

namespace Bower.Source.Ama;

public sealed record AmaDiscoveryResult(
    bool Installed,
    string? AgentVersion,
    string? Status,
    IReadOnlyList<string> DataCollectionRuleIds,
    IReadOnlyList<string> WorkspaceIds,
    IReadOnlyList<string> Findings);

public sealed record AmaCustomLogTarget(
    string Id,
    string Path,
    string Format,
    bool Enabled);

public sealed record AmaCompanionOptions
{
    public required string SourceId { get; init; }

    public string Environment { get; init; } = "production";

    public string ApplicationName { get; init; } = "ama-companion";

    public string? InstallMarkerPath { get; init; }

    public string? ConfigDirectory { get; init; }

    public IReadOnlyList<AmaCustomLogTarget> CustomLogs { get; init; } = [];

    public int MaximumLineBytes { get; init; } = 65_536;

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(SourceId);
        if (SourceId.Length > 128)
        {
            throw new ArgumentException("Source identifier cannot exceed 128 characters.");
        }

        if (MaximumLineBytes is < 256 or > 1_048_576)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumLineBytes));
        }

        foreach (AmaCustomLogTarget target in CustomLogs)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(target.Id);
            ArgumentException.ThrowIfNullOrWhiteSpace(target.Path);
            if (target.Path.Contains("..", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Custom log path for '{target.Id}' must not contain '..'.");
            }
        }
    }
}

public sealed class AmaCompanionService
{
    private readonly AmaCompanionOptions options;
    private readonly Func<string, bool> pathExists;
    private readonly Func<string, string> readAllText;

    public AmaCompanionService(
        AmaCompanionOptions options,
        Func<string, bool>? pathExists = null,
        Func<string, string>? readAllText = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        this.options = options;
        this.pathExists = pathExists ?? File.Exists;
        this.readAllText = readAllText ?? File.ReadAllText;
    }

    public AmaDiscoveryResult Discover()
    {
        List<string> findings = [];
        List<string> dcrs = [];
        List<string> workspaces = [];
        string? version = null;
        string status = "not-found";
        bool installed = false;

        string marker = options.InstallMarkerPath
            ?? (OperatingSystem.IsWindows()
                ? @"C:\Program Files\Azure Monitor Agent\Agent\agentversion"
                : "/opt/microsoft/azuremonitoragent/bin/azuremonitoragent");

        if (pathExists(marker))
        {
            installed = true;
            status = "installed";
            findings.Add($"AMA marker present at configured path.");
            try
            {
                string content = readAllText(marker).Trim();
                if (!string.IsNullOrWhiteSpace(content) && content.Length < 128)
                {
                    version = content;
                }
            }
            catch (IOException)
            {
                findings.Add("AMA marker exists but could not be read.");
            }
        }
        else
        {
            findings.Add("AMA installation marker not found; companion mode can still tail custom logs.");
        }

        string configDir = options.ConfigDirectory
            ?? (OperatingSystem.IsWindows()
                ? @"C:\Program Files\Azure Monitor Agent\Agent\config"
                : "/etc/opt/microsoft/azuremonitoragent/config");

        string inventoryPath = Path.Combine(configDir, "bower-ama-inventory.json");
        if (pathExists(inventoryPath))
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(readAllText(inventoryPath));
                if (document.RootElement.TryGetProperty("dcrs", out JsonElement dcrNode) &&
                    dcrNode.ValueKind == JsonValueKind.Array)
                {
                    dcrs.AddRange(dcrNode.EnumerateArray().Select(item => item.GetString() ?? string.Empty)
                        .Where(item => !string.IsNullOrWhiteSpace(item)));
                }

                if (document.RootElement.TryGetProperty("workspaces", out JsonElement wsNode) &&
                    wsNode.ValueKind == JsonValueKind.Array)
                {
                    workspaces.AddRange(wsNode.EnumerateArray().Select(item => item.GetString() ?? string.Empty)
                        .Where(item => !string.IsNullOrWhiteSpace(item)));
                }

                if (document.RootElement.TryGetProperty("status", out JsonElement statusNode))
                {
                    status = statusNode.GetString() ?? status;
                }
            }
            catch (JsonException)
            {
                findings.Add("AMA inventory file present but invalid JSON.");
            }
        }

        if (installed && dcrs.Count == 0)
        {
            findings.Add("No DCR identifiers discovered; verify AMA association.");
        }

        return new AmaDiscoveryResult(installed, version, status, dcrs, workspaces, findings);
    }

    public IReadOnlyList<SecurityEventEnvelope> MapCustomLogLines(
        string targetId,
        IEnumerable<string> lines,
        DateTimeOffset? observedAt = null)
    {
        AmaCustomLogTarget target = options.CustomLogs.FirstOrDefault(item =>
            string.Equals(item.Id, targetId, StringComparison.Ordinal))
            ?? throw new ArgumentException($"Unknown custom log target '{targetId}'.");

        if (!target.Enabled)
        {
            return [];
        }

        DateTimeOffset observed = observedAt ?? DateTimeOffset.UtcNow;
        List<SecurityEventEnvelope> events = [];
        int index = 0;
        foreach (string line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            int size = Encoding.UTF8.GetByteCount(line);
            if (size > options.MaximumLineBytes)
            {
                throw new InvalidOperationException(
                    $"Custom log line for '{targetId}' is {size} bytes; maximum is {options.MaximumLineBytes}.");
            }

            string originalId = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes($"{targetId}\u001f{index}\u001f{line}")))
                .ToLowerInvariant()[..24];
            index++;

            events.Add(
                new SecurityEventEnvelope
                {
                    SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
                    EventId = Guid.CreateVersion7().ToString(),
                    EventOriginalId = originalId,
                    TimeGenerated = observed,
                    TimeObserved = observed,
                    EventCategory = SecurityEventCategories.ApplicationSecurity,
                    EventType = "ama_custom_log",
                    EventAction = "log.append",
                    EventResult = EventResult.Unknown,
                    Application = new ApplicationContext
                    {
                        Name = options.ApplicationName,
                        Environment = options.Environment
                    },
                    Target = new TargetContext
                    {
                        Type = "file",
                        Name = target.Path
                    },
                    Collector = new CollectorContext
                    {
                        Id = options.SourceId,
                        Version = "0.1.0",
                        SourceAdapter = "ama.companion",
                        ConfigurationHash = originalId[..16],
                        ReceivedAt = observed
                    },
                    Labels = new Dictionary<string, string>
                    {
                        ["ama.targetId"] = target.Id,
                        ["ama.format"] = target.Format,
                        ["ama.linePreview"] = line.Length <= 256 ? line : line[..256]
                    }
                });
        }

        return events;
    }
}

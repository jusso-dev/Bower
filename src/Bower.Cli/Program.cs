using System.Net.Http.Json;
using System.Text.Json;
using Bower.Contracts;
using Bower.Persistence;
using Bower.PolicyEngine;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        return args switch
        {
            ["version"] => WriteVersion(),
            ["validate", .. string[] rest] => Validate(rest),
            ["queue", "inspect", .. string[] rest] => await InspectQueueAsync(rest),
            ["test", "emit", .. string[] rest] => await EmitCanaryAsync(rest),
            ["developer", "init", .. string[] rest] => DeveloperInit(rest),
            [] or ["--help"] or ["help"] => WriteHelp(),
            _ => Fail("Unknown command. Run 'bower --help'.")
        };
    }
    catch (Exception exception) when (exception is not OperationCanceledException)
    {
        return Fail(exception.Message);
    }
}

static int WriteVersion()
{
    Console.WriteLine("bower 0.1.0");
    return 0;
}

static int Validate(string[] args)
{
    string directory = GetOption(args, "--policy-directory")
        ?? Path.Combine(Directory.GetCurrentDirectory(), "policies", "default");
    IReadOnlyList<LoadedPolicy> policies = PolicyLoader.LoadDirectory(directory);
    Console.WriteLine(
        JsonSerializer.Serialize(
            new
            {
                valid = true,
                policyCount = policies.Count,
                policies = policies.Select(item => new
                {
                    item.Policy.Metadata.Id,
                    item.Policy.Metadata.Version,
                    item.Hash
                })
            },
            new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

static async Task<int> InspectQueueAsync(string[] args)
{
    string path = GetOption(args, "--database")
        ?? Path.Combine(Directory.GetCurrentDirectory(), "data", "bower.db");
    SqliteEventStore queue = new(path, 10L * 1024 * 1024 * 1024);
    await queue.InitializeAsync();
    Bower.Abstractions.QueueSnapshot snapshot = await queue.GetSnapshotAsync();
    Console.WriteLine(
        JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

static async Task<int> EmitCanaryAsync(string[] args)
{
    string endpoint = GetOption(args, "--endpoint") ?? "http://127.0.0.1:4319";
    string canaryId = $"bower-canary-{Guid.CreateVersion7()}";
    SecurityEventEnvelope canary = new()
    {
        SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
        EventId = Guid.CreateVersion7().ToString(),
        EventOriginalId = canaryId,
        TimeGenerated = DateTimeOffset.UtcNow,
        EventCategory = SecurityEventCategories.Authentication,
        EventType = SecurityEventTypes.AuthenticationFailure,
        EventAction = "authentication.attempt",
        EventResult = EventResult.Failure,
        EventOutcomeReason = "SyntheticInvalidPassword",
        Application = new ApplicationContext
        {
            Name = "BowerCanary",
            Environment = "test",
            Instance = Environment.MachineName
        },
        Actor = new ActorContext { Username = "synthetic-canary", Type = ActorType.System },
        Source = new SourceContext { IpAddress = "192.0.2.1" },
        Request = new RequestContext { CorrelationId = canaryId },
        Labels = new Dictionary<string, string> { ["evidenceType"] = "test" }
    };

    using HttpClient client = new() { BaseAddress = new Uri(EnsureSlash(endpoint)) };
    using HttpResponseMessage response = await client.PostAsJsonAsync(
        "v1/events",
        canary,
        BowerJson.Options);
    string result = await response.Content.ReadAsStringAsync();
    Console.WriteLine(result);
    return response.IsSuccessStatusCode ? 0 : 2;
}

static int DeveloperInit(string[] args)
{
    string root = Path.GetFullPath(GetOption(args, "--path") ?? Directory.GetCurrentDirectory());
    if (!Directory.Exists(root))
    {
        return Fail($"Target directory does not exist: {root}");
    }

    bool isDotNet = Directory.EnumerateFiles(root, "*.csproj", SearchOption.AllDirectories).Any();
    if (!isDotNet)
    {
        return Fail("No .NET project detected. This release supports .NET developer init.");
    }

    string docsDirectory = Path.Combine(root, "docs");
    Directory.CreateDirectory(docsDirectory);
    WriteNewFile(
        Path.Combine(docsDirectory, "security-telemetry.md"),
        DeveloperTemplates.SecurityTelemetry);
    WriteNewFile(Path.Combine(root, "bower.yaml"), DeveloperTemplates.Configuration);
    WriteNewFile(
        Path.Combine(root, "telemetry-catalogue.yaml"),
        DeveloperTemplates.Catalogue);
    UpdateAgents(Path.Combine(root, "AGENTS.md"));

    Console.WriteLine(
        JsonSerializer.Serialize(
            new
            {
                initialized = true,
                path = root,
                framework = "dotnet",
                note = "Package references are documented but not changed automatically in 0.1.0."
            },
            new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

static void UpdateAgents(string path)
{
    const string start = "<!-- bower:security-telemetry:start -->";
    const string end = "<!-- bower:security-telemetry:end -->";
    string section = $"{start}\n{DeveloperTemplates.AgentsSection}\n{end}\n";
    if (!File.Exists(path))
    {
        File.WriteAllText(path, section);
        return;
    }

    string current = File.ReadAllText(path);
    int startIndex = current.IndexOf(start, StringComparison.Ordinal);
    int endIndex = current.IndexOf(end, StringComparison.Ordinal);
    string updated = startIndex >= 0 && endIndex > startIndex
        ? current[..startIndex]
            + section
            + current[(endIndex + end.Length)..].TrimStart('\r', '\n')
        : $"{current.TrimEnd()}\n\n{section}";
    File.WriteAllText(path, updated);
}

static void WriteNewFile(string path, string content)
{
    if (!File.Exists(path))
    {
        File.WriteAllText(path, content);
    }
}

static string? GetOption(string[] args, string name)
{
    int index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static string EnsureSlash(string value)
{
    return value.EndsWith('/') ? value : $"{value}/";
}

static int WriteHelp()
{
    Console.WriteLine(
        """
        Bower security telemetry

        Commands:
          bower validate [--policy-directory PATH]
          bower queue inspect [--database PATH]
          bower test emit [--endpoint URL]
          bower developer init [--path PATH]
          bower version
        """);
    return 0;
}

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}

internal static class DeveloperTemplates
{
    public const string AgentsSection =
        """
        ## Bower security telemetry

        This repository uses Bower for structured security audit events.

        When changing authentication, authorisation, administration, identity,
        sensitive-data access, export, integration or security-control behaviour:

        1. Determine whether change creates or modifies a security-relevant event.
        2. Use strongly typed Bower SDK.
        3. Emit only after authoritative action succeeds.
        4. Include actor, action, target, outcome and correlation data.
        5. Never include passwords, tokens, cookies, secrets or unrestricted bodies.
        6. Add or update telemetry contract tests and event catalogue.
        7. Run `dotnet test`, `dotnet bower analyse`, and
           `dotnet bower catalogue validate`.

        Do not use ILogger as substitute for Bower security event. Do not create
        free-form event types where semantic event exists. Do not duplicate events
        across controller, service and persistence layers. Never weaken validation
        or bypass redaction.
        """;

    public const string SecurityTelemetry =
        """
        # Security telemetry

        Emit semantic Bower events at authoritative transaction boundaries. Keep
        actor, action, target, result and correlation context. Never include secrets,
        cookies, authorization headers, unrestricted bodies or file contents.

        Add `Bower.Sdk` and call `services.AddBower(...)`. Add contract tests for
        every catalogue entry.
        """;

    public const string Configuration =
        """
        apiVersion: bower.security/v1
        kind: ApplicationConfiguration
        application:
          name: replace-me
          environment: development
        transport:
          type: local-collector
          endpoint: http://127.0.0.1:4319
        """;

    public const string Catalogue =
        """
        apiVersion: bower.security/v1
        kind: ApplicationTelemetryCatalogue
        application:
          name: replace-me
          owner: replace-me
          environment: development
        events: []
        """;
}

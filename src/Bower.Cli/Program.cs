using System.Net.Http.Json;
using System.Text.Json;
using Bower.Cli.Commands;
using Bower.Contracts;
using Bower.Persistence;
using Bower.Pipeline;
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
            ["pipeline", "validate", .. string[] rest] => ValidatePipeline(rest),
            ["pipeline", "template", .. string[] rest] => PipelineTemplate(rest),
            ["queue", "inspect", .. string[] rest] => await InspectQueueAsync(rest),
            ["queue", "dead-letters", .. string[] rest] => await QueueCommands.DeadLettersAsync(rest),
            ["queue", "replay", .. string[] rest] => await QueueCommands.ReplayAsync(rest),
            ["queue", "verify", .. string[] rest] => await QueueCommands.VerifyAsync(rest),
            ["test", "emit", .. string[] rest] => await EmitCanaryAsync(rest),
            ["token", "generate", .. string[] rest] => TokenCommands.Generate(rest),
            ["doctor", .. string[] rest] => await DoctorCommand.RunAsync(rest),
            ["dcr", "generate", .. string[] rest] => DcrCommands.Generate(rest),
            ["dcr", "diff", .. string[] rest] => await DcrCommands.DiffAsync(rest),
            ["keys", "generate", .. string[] rest] => KeyCommands.Generate(rest),
            ["pack", "build", .. string[] rest] => PackCommands.Build(rest),
            ["pack", "verify", .. string[] rest] => PackCommands.Verify(rest),
            ["pack", "inspect", .. string[] rest] => PackCommands.Inspect(rest),
            ["pack", "test", .. string[] rest] => PackCommands.Test(rest),
            ["pack", "diff", .. string[] rest] => PackCommands.Diff(rest),
            ["evidence", "run", .. string[] rest] => await EvidenceCommands.RunAsync(rest),
            ["evidence", "verify", .. string[] rest] => EvidenceCommands.Verify(rest),
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

static int ValidatePipeline(string[] args)
{
    string? path = GetOption(args, "--file") ?? args.FirstOrDefault(item => !item.StartsWith('-'));
    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
    {
        return Fail("Provide an existing pipeline file with --file PATH.");
    }

    TelemetryPipeline pipeline = PipelineDocument.ParseYaml(File.ReadAllText(path));
    PipelineValidationResult validation = PipelineValidator.Validate(pipeline);
    PipelinePerformanceEstimate estimate = PipelineValidator.Estimate(pipeline);
    Console.WriteLine(
        JsonSerializer.Serialize(
            new
            {
                valid = validation.IsValid,
                pipeline.Id,
                pipeline.Name,
                pipeline.Version,
                order = validation.TopologicalOrder,
                estimate,
                issues = validation.Issues
            },
            new JsonSerializerOptions { WriteIndented = true }));
    return validation.IsValid ? 0 : 2;
}

static int PipelineTemplate(string[] args)
{
    string templateId = GetOption(args, "--id") ?? args.FirstOrDefault(item => !item.StartsWith('-')) ?? "sentinel-app";
    TelemetryPipeline pipeline = PipelineValidator.CreateTemplate(templateId);
    Console.WriteLine(PipelineDocument.ToYaml(pipeline));
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

    string? token = Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN");
    using HttpClient client = new() { BaseAddress = new Uri(EnsureSlash(endpoint)) };
    using HttpRequestMessage request = new(HttpMethod.Post, "v1/events")
    {
        Content = JsonContent.Create(canary, options: BowerJson.Options)
    };
    if (!string.IsNullOrWhiteSpace(token))
    {
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    }

    using HttpResponseMessage response = await client.SendAsync(request);
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
          bower pipeline validate --file PATH
          bower pipeline template [--id sentinel-app|aws-security]
          bower queue inspect [--database PATH]
          bower test emit [--endpoint URL]      (sends BOWER_INGEST_TOKEN when set)
          bower token generate [--id PRODUCER] (new ingest token; --id prints a tokens-file line)

          bower doctor [--policy-directory DIR] [--pack FILE --trusted-key PUB] [--privacy-profile FILE]
                       [--hmac-key-file FILE] [--collector-url URL] [--database FILE]
                       [--ingestion-endpoint URL] [--dcr-resource-id ID] [--workspace-resource-id ID]
                       [--credential azure-cli|managed-identity|workload-identity|environment] [--json]

          bower dcr generate [--out FILE] [--rule-name NAME] [--retention-days N] [--total-retention-days N]
          bower dcr diff (--rule FILE | --dcr-resource-id ID) [--table FILE | --workspace-resource-id ID]

          bower keys generate --out-dir DIR [--name NAME]
          bower pack build DIR --key PRIVATE.pem [--out DIR]
          bower pack verify|inspect|test FILE --trusted-key PUBLIC.pem
          bower pack diff OLD.bowerpack NEW.bowerpack --trusted-key PUBLIC.pem

          bower evidence run --collector-url URL [--workspace-id ID --workspace-resource-id ID]
                             [--table NAME] [--signing-key PRIVATE.pem] [--out FILE]
          bower evidence verify FILE --trusted-key PUBLIC.pem

          bower queue dead-letters --database FILE
          bower queue replay --database FILE (--code PREFIX | --event ID ...)
          bower queue verify --database FILE [--expect-head SEQUENCE:HASH]
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

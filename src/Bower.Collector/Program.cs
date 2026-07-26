using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Bower.Output.AmaSpool;
using Bower.Output.AzureLogsIngestion;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(
    Environment.GetEnvironmentVariable("BOWER_LISTEN_URL") ?? "http://127.0.0.1:4319");
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = JsonEventRedactor.MaximumPayloadBytes;
});
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ ";
    options.UseUtcTimestamp = true;
});

string databasePath = Environment.GetEnvironmentVariable("BOWER_QUEUE_PATH")
    ?? Path.Combine(AppContext.BaseDirectory, "data", "bower.db");
string policyDirectory = Environment.GetEnvironmentVariable("BOWER_POLICY_DIRECTORY")
    ?? Path.Combine(Directory.GetCurrentDirectory(), "policies", "default");
string collectorId = Environment.GetEnvironmentVariable("BOWER_COLLECTOR_ID")
    ?? Environment.MachineName;

builder.Services.AddSingleton<IClock, SystemClock>();
builder.Services.AddSingleton<IEventRedactor, JsonEventRedactor>();
builder.Services.AddSingleton<IDurableEventStore>(services =>
    new SqliteEventStore(
        databasePath,
        maximumBytes: 10L * 1024 * 1024 * 1024,
        services.GetRequiredService<IClock>()));
builder.Services.AddSingleton<ITelemetryPolicyEvaluator>(
    new DeterministicPolicyEvaluator(PolicyLoader.LoadDirectory(policyDirectory)));
builder.Services.AddSingleton<SecurityEventProcessor>();
builder.Services.AddSingleton(
    new CollectorIdentity(collectorId, "0.1.0", "local-http", "environment:v1"));

IOutputAdapter? output = CreateOutputFromEnvironment();
if (output is not null)
{
    builder.Services.AddSingleton(output);
    builder.Services.AddHostedService<QueueDeliveryWorker>();
}

string? managementEndpoint =
    Environment.GetEnvironmentVariable("BOWER_MANAGEMENT_ENDPOINT");
if (!string.IsNullOrWhiteSpace(managementEndpoint))
{
    string scope = RequiredEnvironment("BOWER_MANAGEMENT_SCOPE");
    builder.Services.AddSingleton(
        new ManagementReporterOptions(
            new Uri(managementEndpoint, UriKind.Absolute),
            scope,
            collectorId,
            "0.1.0",
            Environment.GetEnvironmentVariable("BOWER_ENVIRONMENT") ?? "unknown",
            "environment:v1",
            "policy-directory:v1",
            Environment.GetEnvironmentVariable("BOWER_OUTPUT") ?? "none",
            TimeSpan.FromSeconds(60)));
    builder.Services.AddSingleton<TokenCredential>(new DefaultAzureCredential());
    builder.Services.AddHostedService<ManagementReporter>();
}

WebApplication app = builder.Build();
IDurableEventStore queue = app.Services.GetRequiredService<IDurableEventStore>();
await queue.InitializeAsync(app.Lifetime.ApplicationStopping);

app.MapPost(
    "/v1/events",
    async (
        JsonElement candidate,
        SecurityEventProcessor processor,
        CollectorIdentity identity,
        CancellationToken cancellationToken) =>
    {
        ProcessingResult result = await processor.ProcessAsync(
            candidate.GetRawText(),
            identity,
            cancellationToken);
        object response = new
        {
            result.EventId,
            decision = result.Action.ToString().ToLowerInvariant(),
            result.Queued,
            result.Duplicate,
            result.Reasons,
            policy = result.PolicyDecision is null
                ? null
                : new
                {
                    result.PolicyDecision.PolicyId,
                    result.PolicyDecision.PolicyVersion,
                    result.PolicyDecision.PolicyHash,
                    result.PolicyDecision.Score
                }
        };

        return result.Action switch
        {
            DecisionAction.Accept or DecisionAction.RedactAndAccept =>
                Results.Json(response, statusCode: result.Duplicate ? 200 : 202),
            DecisionAction.Reject => Results.Json(response, statusCode: 422),
            _ => Results.Json(response, statusCode: 400)
        };
    });

app.MapGet(
    "/health",
    async (IDurableEventStore eventQueue, CancellationToken cancellationToken) =>
    {
        QueueSnapshot snapshot = await eventQueue.GetSnapshotAsync(cancellationToken);
        return Results.Json(new
        {
            status = snapshot.DeadLettered > 0 ? "degraded" : "healthy",
            queue = new
            {
                snapshot.Queued,
                snapshot.Retrying,
                snapshot.Uploading,
                snapshot.Delivered,
                snapshot.DeadLettered,
                snapshot.TotalBytes,
                snapshot.OldestUndelivered
            }
        });
    });

await app.RunAsync();

static IOutputAdapter? CreateOutputFromEnvironment()
{
    string outputType = Environment.GetEnvironmentVariable("BOWER_OUTPUT") ?? "none";
    if (string.Equals(outputType, "none", StringComparison.OrdinalIgnoreCase))
    {
        return null;
    }

    if (string.Equals(outputType, "ama-spool", StringComparison.OrdinalIgnoreCase))
    {
        string root = Environment.GetEnvironmentVariable("BOWER_AMA_SPOOL_PATH")
            ?? Path.Combine(AppContext.BaseDirectory, "spool");
        return new AmaSpoolOutput(new AmaSpoolOptions
        {
            Id = "ama-spool",
            CollectorId = Environment.GetEnvironmentVariable("BOWER_COLLECTOR_ID")
                ?? Environment.MachineName,
            StreamName = Environment.GetEnvironmentVariable("BOWER_STREAM_NAME")
                ?? "Custom-BowerSecurity",
            ActiveDirectory = Path.Combine(root, "active"),
            ReadyDirectory = Path.Combine(root, "ready")
        });
    }

    if (string.Equals(outputType, "azure-logs-ingestion", StringComparison.OrdinalIgnoreCase))
    {
        string endpoint = RequiredEnvironment("BOWER_DCE_ENDPOINT");
        AzureLogsIngestionOptions options = new()
        {
            Id = "azure-logs-ingestion",
            Endpoint = new Uri(endpoint),
            DcrImmutableId = RequiredEnvironment("BOWER_DCR_ID"),
            StreamName = RequiredEnvironment("BOWER_STREAM_NAME")
        };
        TokenCredential credential = new DefaultAzureCredential();
        return new AzureLogsIngestionOutput(options, credential);
    }

    throw new InvalidOperationException($"Unsupported BOWER_OUTPUT value: {outputType}");
}

static string RequiredEnvironment(string name)
{
    return Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"Required environment variable is missing: {name}");
}

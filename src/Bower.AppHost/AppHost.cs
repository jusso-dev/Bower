using System.Text;
using Aspire.Hosting.Dotnet;
using Bower.AppHost;

// Bower local development and integration-test harness. Not a deployment path: Compose,
// Bicep and the native packages stay the production paths. Everything here is synthetic
// and loopback-only. See docs/getting-started/aspire.md.
IDistributedApplicationBuilder builder = DistributedApplication.CreateBuilder(args);
string repo = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "..", ".."));
// Overridable so the integration test can run beside a developer session.
string state = builder.Configuration["BowerAspire:StateDirectory"] ?? Path.Combine(repo, "artifacts", "aspire");
string policies = Path.Combine(repo, "policies", "default");

// Generated per developer and stored in the AppHost user secrets; never committed.
IResourceBuilder<ParameterResource> ingestToken = builder.AddParameter(
    "ingest-token", new GenerateParameterDefault { MinLength = 48, Special = false }, secret: true, persist: true);
IResourceBuilder<ParameterResource> httpSinkToken = builder.AddParameter(
    "http-sink-token", new GenerateParameterDefault { MinLength = 32, Special = false }, secret: true, persist: true);

// S3-compatible emulator for BOWER_OUTPUT=s3 (unauthenticated, in-memory, loopback).
IResourceBuilder<ContainerResource> s3 = builder.AddContainer("s3", HarnessImages.S3Mock, HarnessImages.S3MockTag)
    .WithImageSHA256(HarnessImages.S3MockDigest)
    .WithEnvironment("COM_ADOBE_TESTING_S3MOCK_STORE_INITIAL_BUCKETS", Harness.S3Bucket)
    .WithEnvironment("COM_ADOBE_TESTING_S3MOCK_STORE_RETAIN_FILES_ON_EXIT", "false")
    .WithHttpEndpoint(targetPort: 9090, name: "http")
    // Healthy once the bucket exists and answers a ListObjects request.
    .WithHttpHealthCheck("/" + Harness.S3Bucket + "?list-type=2");
EndpointReference s3Endpoint = s3.GetEndpoint("http");
// 127.0.0.1, not localhost: the AWS SDK then uses path-style requests, which S3Mock serves.
ReferenceExpression s3Url = ReferenceExpression.Create($"http://127.0.0.1:{s3Endpoint.Property(EndpointProperty.Port)}");

// Stand-in destinations for BOWER_OUTPUT=http (NDJSON) and BOWER_OUTPUT=ama-syslog.
string syslogSocket = builder.Configuration["BowerAspire:SyslogSocket"] ?? Harness.SyslogSocketPath();
IResourceBuilder<DotnetProjectResource> sinks = builder.AddDotnetProject("devsinks", Path.Combine(repo, "tools", "Bower.DevSinks", "Bower.DevSinks.csproj"))
    .WithLocalHttpEndpoint()
    .WithEnvironment("DEVSINKS_HTTP_TOKEN", httpSinkToken)
    .WithEnvironment("DEVSINKS_S3_ENDPOINT", s3Url)
    .WithEnvironment("DEVSINKS_S3_BUCKET", Harness.S3Bucket)
    .WithEnvironment("DEVSINKS_SYSLOG_SOCKET", OperatingSystem.IsWindows() ? string.Empty : syslogSocket)
    .WithHttpHealthCheck("/health")
    .WithHttpCommand("/api/s3/refresh", "Read S3 bucket", commandName: "read-s3", commandOptions: new HttpCommandOptions
    {
        Description = "Read every NDJSON object in the S3 emulator bucket into the s3 sink.",
        IconName = "ArrowSync"
    })
    .WaitFor(s3);
EndpointReference sinksEndpoint = sinks.GetEndpoint("http");

// Fleet management API in its explicit local-only development mode.
builder.AddDotnetProject("management", Path.Combine(repo, "src", "Bower.Management.Api", "Bower.Management.Api.csproj"))
    .WithLocalHttpEndpoint("BOWER_MANAGEMENT_LISTEN_URL")
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("BOWER_AUTH_MODE", "development")
    .WithEnvironment("BOWER_MANAGEMENT_DB_PATH", Path.Combine(state, "management", "management.db"))
    .WithHttpHealthCheck("/health");

// One collector per output that can be exercised locally. Azure Logs Ingestion cannot be
// emulated (no Microsoft emulator; it needs a real DCE, DCR and Entra token).
builder.AddCollector("collector-s3", repo, state, policies, ingestToken)
    .WithEnvironment("BOWER_OUTPUT", "s3")
    .WithEnvironment("BOWER_S3_BUCKET", Harness.S3Bucket)
    .WithEnvironment("BOWER_S3_REGION", "ap-southeast-2")
    .WithEnvironment("BOWER_S3_PREFIX", "bower")
    // The emulator ignores signatures; these are placeholders, never real AWS credentials.
    // A session token mirrors the temporary credentials Bower expects from a role.
    .WithEnvironment("AWS_ENDPOINT_URL", s3Url)
    .WithEnvironment("AWS_ACCESS_KEY_ID", "aspire-local")
    .WithEnvironment("AWS_SECRET_ACCESS_KEY", "aspire-local")
    .WithEnvironment("AWS_SESSION_TOKEN", "aspire-local")
    .WithEnvironment("AWS_EC2_METADATA_DISABLED", "true")
    .WaitFor(s3);

builder.AddCollector("collector-http", repo, state, policies, ingestToken)
    .WithEnvironment("BOWER_OUTPUT", "http")
    .WithEnvironment("BOWER_HTTP_FORMAT", "ndjson")
    .WithEnvironment("BOWER_HTTP_URL", ReferenceExpression.Create($"http://127.0.0.1:{sinksEndpoint.Property(EndpointProperty.Port)}/ndjson"))
    .WithEnvironment("BOWER_HTTP_ALLOW_INSECURE_LOOPBACK", "true")
    .WithEnvironment("BOWER_HTTP_TOKEN", httpSinkToken)
    .WaitFor(sinks);

if (!OperatingSystem.IsWindows())
{
    // AmaSyslog writes Unix datagrams; the sink binds the socket in place of rsyslog/AMA.
    builder.AddCollector("collector-syslog", repo, state, policies, ingestToken)
        .WithEnvironment("BOWER_OUTPUT", "ama-syslog")
        .WithEnvironment("BOWER_AMA_SYSLOG_SOCKET", syslogSocket)
        .WaitFor(sinks);
}

// Serverless collector under Azure Functions Core Tools (`func`). HTTP triggers only, so no
// host storage (Azurite) is needed. Delivery targets an unreachable placeholder DCE: health
// and status work, ingest answers 503 because Logs Ingestion cannot be emulated.
builder.AddDotnetProject("functions", Path.Combine(repo, "src", "Bower.Functions.Collector", "Bower.Functions.Collector.csproj"))
    .WithHttpEndpoint(name: "http")
    .WithArgs(context => context.Args.Add("--port"))
    .WithArgs(context => context.Args.Add(context.Resource is IResourceWithEndpoints functions
        ? functions.GetEndpoint("http").Property(EndpointProperty.TargetPort)
        : throw new InvalidOperationException("The Functions resource has no endpoint.")))
    .WithEnvironment("AZURE_FUNCTIONS_ENVIRONMENT", "Development")
    .WithEnvironment("FUNCTIONS_WORKER_RUNTIME", "dotnet-isolated")
    .WithEnvironment("BOWER_DEVELOPMENT_AUTH", "true")
    .WithEnvironment("BOWER_AZURE_CREDENTIAL", "azure-cli")
    .WithEnvironment("BOWER_DCE_ENDPOINT", "https://logs-ingestion.invalid")
    .WithEnvironment("BOWER_DCR_ID", "dcr-00000000000000000000000000000000")
    .WithEnvironment("BOWER_COLLECTOR_ID", "aspire-functions")
    .WithEnvironment("BOWER_PRODUCER_SCOPES_JSON", CanaryEvent.ProducerScopesJson)
    .WithHttpHealthCheck("/health");

builder.Build().Run();

internal static class Harness
{
    public const string S3Bucket = "bower-aspire";

    /// <summary>
    /// A short per-user socket path (macOS caps Unix socket paths at 103 bytes), outside the
    /// repository so no socket file is ever committed.
    /// </summary>
    public static string SyslogSocketPath() =>
        Path.Combine(Path.GetTempPath(), $"bower-aspire-{Environment.UserName}", "log.sock");

    /// <summary>
    /// An http endpoint whose port reaches the process as an explicit <c>http://127.0.0.1:port</c>
    /// listen URL. Bower hosts set their own listen URL, so ASPNETCORE_URLS alone is not enough.
    /// </summary>
    public static IResourceBuilder<DotnetProjectResource> WithLocalHttpEndpoint(
        this IResourceBuilder<DotnetProjectResource> resource, string? listenUrlVariable = null)
    {
        resource.WithHttpEndpoint(name: "http");
        EndpointReference endpoint = resource.GetEndpoint("http");
        ReferenceExpression url = ReferenceExpression.Create($"http://127.0.0.1:{endpoint.Property(EndpointProperty.TargetPort)}");
        resource.WithEnvironment("ASPNETCORE_URLS", url);
        return listenUrlVariable is null ? resource : resource.WithEnvironment(listenUrlVariable, url);
    }

    public static IResourceBuilder<DotnetProjectResource> AddCollector(
        this IDistributedApplicationBuilder builder,
        string name,
        string repo,
        string state,
        string policies,
        IResourceBuilder<ParameterResource> ingestToken)
    {
        IResourceBuilder<DotnetProjectResource> collector = builder
            .AddDotnetProject(name, Path.Combine(repo, "src", "Bower.Collector", "Bower.Collector.csproj"))
            .WithLocalHttpEndpoint("BOWER_LISTEN_URL")
            .WithEnvironment("BOWER_COLLECTOR_ID", "aspire-" + name)
            .WithEnvironment("BOWER_ENVIRONMENT", "development")
            .WithEnvironment("BOWER_QUEUE_PATH", Path.Combine(state, name, "bower.db"))
            .WithEnvironment("BOWER_POLICY_DIRECTORY", policies)
            .WithEnvironment("BOWER_INGEST_TOKEN", ingestToken)
            .WithEnvironment("BOWER_PRODUCER_SCOPES_JSON", CanaryEvent.ProducerScopesJson)
            // Short leases so a stopped destination shows up quickly during local testing.
            .WithEnvironment("BOWER_DELIVERY_LEASE_SECONDS", "60")
            .WithEnvironment("BOWER_DELIVERY_TIMEOUT_SECONDS", "20")
            .WithHttpHealthCheck("/health/live");
        return collector.WithCanaryCommand(ingestToken);
    }

    /// <summary>Dashboard command that posts one synthetic canary to <c>/v1/events</c>.</summary>
    public static IResourceBuilder<DotnetProjectResource> WithCanaryCommand(
        this IResourceBuilder<DotnetProjectResource> resource, IResourceBuilder<ParameterResource> ingestToken) =>
        resource.WithHttpCommand("/v1/events", "Send canary", commandName: "send-canary", commandOptions: new HttpCommandOptions
        {
            Description = "POST one synthetic authentication failure (accepted by policies/default).",
            IconName = "Send",
            PrepareRequest = async context =>
            {
                string? token = await ingestToken.Resource.GetValueAsync(context.CancellationToken);
                context.Request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                context.Request.Content = new StringContent(CanaryEvent.Create().Json, Encoding.UTF8, "application/json");
            }
        });
}

internal static class HarnessImages
{
    // S3Mock 5.2.3 (Apache-2.0, Adobe). Pinned by digest; see docs/architecture/dependencies.md.
    public const string S3Mock = "adobe/s3mock";
    public const string S3MockTag = "5.2.3";
    public const string S3MockDigest = "ab01a6946750f451ca215a47e91030695b260e4003b8a5a6201d25029b8fca92";
}

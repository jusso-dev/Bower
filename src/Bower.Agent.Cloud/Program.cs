using Amazon;
using Amazon.S3;
using Amazon.SQS;
using Bower.Agent.Cloud;
using Bower.Agent.Cloud.Aws;
using Bower.Agent.Cloud.Gcp;
using Bower.Forwarding;
using Bower.Source.Aws;
using Bower.Source.Gcp;

if (args is ["--healthcheck"])
{
    return CloudHealth.Check(CloudAgentSettings.FromEnvironment());
}

try
{
    CloudAgentSettings settings = CloudAgentSettings.FromEnvironment();
    HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
    builder.Logging.ClearProviders();
    builder.Logging.AddSimpleConsole(options =>
    {
        options.SingleLine = true;
        options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ ";
        options.UseUtcTimestamp = true;
    });
    builder.Logging.AddFilter("System.Net.Http", LogLevel.Warning);

    builder.Services.AddSingleton(settings);
    builder.Services.AddSingleton(TimeProvider.System);
    builder.Services.AddHttpClient("bower-collector", client =>
    {
        client.BaseAddress = settings.CollectorUrl;
        client.Timeout = TimeSpan.FromSeconds(10);
    });
    builder.Services.AddSingleton(services => new CollectorClient(
        services.GetRequiredService<IHttpClientFactory>().CreateClient("bower-collector"),
        settings.IngestToken));

    if (settings.Aws is { } aws)
    {
        // Default credential chain only: instance profile, ECS task role or IRSA web identity.
        RegionEndpoint region = RegionEndpoint.GetBySystemName(aws.Region);
        builder.Services.AddSingleton<IAmazonSQS>(_ => new AmazonSQSClient(region));
        builder.Services.AddSingleton<IAmazonS3>(_ => new AmazonS3Client(region));
        builder.Services.AddSingleton<IHostedService>(services => new CloudForwarderWorker(
            new SqsMessageSource(services.GetRequiredService<IAmazonSQS>(), aws.QueueUrl),
            new AwsMessageTranslator(
                new AwsQueueMessageParser(new AwsQueueOptions
                {
                    SourceId = $"aws:{aws.AccountId}:{aws.Region}",
                    AccountId = aws.AccountId,
                    Region = aws.Region,
                    Environment = settings.Environment,
                    IncludeRawRecord = settings.IncludeRawRecords
                }),
                aws.AllowedBuckets.Count == 0 ? null : new S3ObjectReader(services.GetRequiredService<IAmazonS3>()),
                aws,
                TimeProvider.System,
                services.GetRequiredService<ILogger<AwsMessageTranslator>>()),
            services.GetRequiredService<CollectorClient>(),
            settings,
            TimeProvider.System,
            services.GetRequiredService<ILogger<CloudForwarderWorker>>()));
    }

    GoogleAccessTokenSource? googleTokens = null;
    if (settings.Gcp is { } gcp)
    {
        googleTokens = new GoogleAccessTokenSource(gcp.AllowServiceAccountKey);
        builder.Services.AddHttpClient("pubsub", client =>
        {
            client.BaseAddress = gcp.Endpoint;
            // Pull holds the request open while it waits for messages.
            client.Timeout = TimeSpan.FromSeconds(90);
        });
        builder.Services.AddSingleton<IHostedService>(services => new CloudForwarderWorker(
            new PubSubMessageSource(
                services.GetRequiredService<IHttpClientFactory>().CreateClient("pubsub"),
                googleTokens,
                gcp.Subscription),
            new PubSubMessageTranslator(
                new GcpSecurityEventMapper(new GcpSourceOptions
                {
                    SourceId = $"gcp:{gcp.Subscription.Split('/')[1]}",
                    Environment = settings.Environment,
                    IncludeRawRecord = settings.IncludeRawRecords
                }),
                TimeProvider.System),
            services.GetRequiredService<CollectorClient>(),
            settings,
            TimeProvider.System,
            services.GetRequiredService<ILogger<CloudForwarderWorker>>()));
    }

    using IHost host = builder.Build();
    ILogger logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Bower.Agent.Cloud");
    CloudResidency.Report(settings, logger);
    if (googleTokens is not null)
    {
        await googleTokens.InitializeAsync(CancellationToken.None);
    }

    await host.RunAsync();
    return 0;
}
catch (Exception exception) when (exception is not OperationCanceledException)
{
    // Exit with a status code; an unhandled abort can hang as PID 1 in a container.
    Console.Error.WriteLine($"Bower cloud agent failed: {exception.GetType().Name}: {exception.Message}");
    return 1;
}

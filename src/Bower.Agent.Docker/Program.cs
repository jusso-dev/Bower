using Bower.Abstractions;
using Bower.Agent.Docker;
using Bower.Persistence;

if (args is ["--healthcheck"])
{
    return SidecarHealth.Check(SidecarSettings.FromEnvironment());
}

try
{
    SidecarSettings settings = SidecarSettings.FromEnvironment();
    HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
    builder.Logging.ClearProviders();
    builder.Logging.AddSimpleConsole(options =>
    {
        options.SingleLine = true;
        options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ ";
        options.UseUtcTimestamp = true;
    });
    builder.Logging.AddFilter("System.Net.Http", LogLevel.Warning);

    EfSourceCursorStore cursors = new(settings.StatePath);
    builder.Services.AddSingleton(settings);
    builder.Services.AddSingleton(TimeProvider.System);
    builder.Services.AddSingleton<ISourceCursorStore>(cursors);
    builder.Services.AddHttpClient<CollectorClient>(client =>
    {
        client.BaseAddress = settings.CollectorUrl;
        client.Timeout = TimeSpan.FromSeconds(10);
    });
    builder.Services.AddHostedService<DockerSidecarWorker>();

    using IHost host = builder.Build();
    await cursors.InitializeAsync(CancellationToken.None);
    await host.RunAsync();
    return 0;
}
catch (Exception exception) when (exception is not OperationCanceledException)
{
    // Exit with a status code; an unhandled abort can hang as PID 1 in a container.
    Console.Error.WriteLine($"Bower Docker sidecar failed: {exception.GetType().Name}: {exception.Message}");
    return 1;
}

using Bower.Collector;

try
{
    CollectorSettings settings = CollectorSettings.FromEnvironment();
    WebApplication app = CollectorApplication.Build(settings);
    await CollectorApplication.InitializeAsync(app, app.Lifetime.ApplicationStopping);
    await app.RunAsync();
    return 0;
}
catch (Exception exception) when (exception is not OperationCanceledException)
{
    // Exit with a status code instead of an unhandled-exception abort: as PID 1 in a
    // container the abort path can hang, so the orchestrator would never restart it.
    // Messages are Bower-authored configuration or storage errors; no secrets.
    Console.Error.WriteLine($"Bower collector failed: {exception.GetType().Name}: {exception.Message}");
    return 1;
}

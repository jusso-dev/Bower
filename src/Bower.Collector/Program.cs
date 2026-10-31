using Bower.Collector;

try
{
    // Operator overrides that survive package upgrades (the MSI rewrites the service environment).
    CollectorSettingsFile.Apply();
    CollectorSettings settings = CollectorSettings.FromEnvironment();
    WebApplication app = CollectorApplication.Build(settings);
    await CollectorApplication.InitializeAsync(app, app.Lifetime.ApplicationStopping);
    await app.RunAsync();
    // Non-zero when the host asked the supervisor for a restart (managed privacy profile
    // staged or cleared), so Restart=on-failure and restart: on-failure also apply it.
    return Bower.Collector.Jobs.ManagedPrivacyProfileJob.RestartRequested
        ? Bower.Collector.Jobs.ManagedPrivacyProfileJob.RestartExitCode
        : 0;
}
catch (Exception exception) when (exception is not OperationCanceledException)
{
    // Exit with a status code instead of an unhandled-exception abort: as PID 1 in a
    // container the abort path can hang, so the orchestrator would never restart it.
    // Messages are Bower-authored configuration or storage errors; no secrets.
    Console.Error.WriteLine($"Bower collector failed: {exception.GetType().Name}: {exception.Message}");
    return 1;
}

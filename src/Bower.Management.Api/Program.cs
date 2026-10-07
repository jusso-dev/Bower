using Bower.Management.Api;

try
{
    WebApplication app = ManagementApplication.Build(args);
    await ManagementApplication.InitializeAsync(app, app.Lifetime.ApplicationStopping);
    await app.RunAsync();
    return 0;
}
catch (Exception exception) when (exception is not OperationCanceledException)
{
    // Exit with a status code instead of an unhandled-exception abort, which can hang
    // as PID 1 in a container and block orchestrator restarts.
    Console.Error.WriteLine($"Bower management API failed: {exception.GetType().Name}: {exception.Message}");
    return 1;
}

public partial class Program
{
}

using System.Text.Json;
using Bower.Contracts;
using Bower.Sdk;
using Microsoft.Extensions.DependencyInjection;

// Checks the consumer libraries on the runtime this build targets.
#if NET11_0_OR_GREATER
const int ExpectedMajor = 11;
#else
const int ExpectedMajor = 10;
#endif
Check(Environment.Version.Major == ExpectedMajor, $"runs on .NET {ExpectedMajor} (found {Environment.Version})");

// BowerJson.Envelope uses a different GetTypeInfo overload per target framework.
Check(ReferenceEquals(BowerJson.Envelope.Options, BowerJson.Options), "envelope metadata is bound to BowerJson.Options");
SecurityEventEnvelope envelope = new()
{
    SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
    EventId = "compat-1",
    TimeGenerated = new DateTimeOffset(2026, 11, 13, 0, 0, 0, TimeSpan.Zero),
    EventCategory = SecurityEventCategories.Authentication,
    EventType = SecurityEventTypes.AuthenticationFailure,
    EventAction = "authentication.attempt",
    EventResult = EventResult.Failure,
    Application = new ApplicationContext { Name = "Compat", Environment = "test" }
};
string json = JsonSerializer.Serialize(envelope, BowerJson.Envelope);
Check(json.Contains("\"eventResult\":\"failure\"", StringComparison.Ordinal), "enum wire format is camelCase");
Check(envelope == JsonSerializer.Deserialize(json, BowerJson.Envelope), "envelope round-trips");
bool refused = false;
try { JsonSerializer.Deserialize(json.Replace("\"failure\"", "7", StringComparison.Ordinal), BowerJson.Envelope); }
catch (JsonException) { refused = true; }
Check(refused, "undefined enum ordinal is refused");

ServiceCollection services = new();
services.AddBower(options =>
{
    options.Application.Name = "Compat";
    options.Application.Environment = "test";
    options.LocalCollector.Endpoint = "http://127.0.0.1:9";
});
await using (ServiceProvider provider = services.BuildServiceProvider())
{
    provider.GetRequiredService<IBowerTelemetry>();
    Check(provider.GetRequiredService<IBowerTelemetryDiagnostics>().DeliveryStatus.Accepted == 0, "AddBower registers the client");
}

Console.WriteLine($"Bower.Sdk compatibility: all checks passed on {Environment.Version}.");
return 0;

static void Check(bool condition, string what)
{
    if (!condition)
    {
        Console.Error.WriteLine($"FAILED: {what}");
        Environment.Exit(1);
    }
}

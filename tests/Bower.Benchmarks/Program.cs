using System.Diagnostics;
using Bower.Redaction.Privacy;

// Lightweight throughput smoke benchmark (no BenchmarkDotNet dependency).
// Run: dotnet run --project tests/Bower.Benchmarks -c Release

const int iterations = 5_000;
const string cleanEvent =
    """
    {
      "schemaVersion": "1.0.0",
      "eventId": "evt-1",
      "eventType": "authentication_success",
      "eventCategory": "authentication",
      "eventAction": "login",
      "eventResult": "success",
      "application": { "name": "demo", "environment": "dev" },
      "actor": { "userId": "u-1", "username": "demo.user" },
      "timeGenerated": "2026-01-01T00:00:00Z",
      "message": "user signed in from office network"
    }
    """;

const string dirtyEvent =
    """
    {
      "schemaVersion": "1.0.0",
      "eventId": "evt-2",
      "eventType": "authentication_failure",
      "eventCategory": "authentication",
      "eventAction": "login",
      "eventResult": "failure",
      "application": { "name": "demo", "environment": "dev" },
      "timeGenerated": "2026-01-01T00:00:00Z",
      "tfn": "100000001",
      "email": "alice@example.test",
      "pan": "4111111111111111",
      "awsKey": "AKIAIOSFODNN7EXAMPLE",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
      "note": "contact +61 412 345 678 and abn 51 824 753 556"
    }
    """;

PrivacyEngine engine = new();

// Warmup
for (int i = 0; i < 200; i++)
{
    _ = engine.RedactJson(cleanEvent);
    _ = engine.RedactJson(dirtyEvent);
}

static (double opsPerSec, double meanUs) Measure(PrivacyEngine engine, string payload, int iterations)
{
    Stopwatch sw = Stopwatch.StartNew();
    for (int i = 0; i < iterations; i++)
    {
        PrivacyScanResult result = engine.RedactJson(payload);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(result.FailureCode);
        }
    }

    sw.Stop();
    double ops = iterations / sw.Elapsed.TotalSeconds;
    double meanUs = sw.Elapsed.TotalMicroseconds / iterations;
    return (ops, meanUs);
}

(double cleanOps, double cleanUs) = Measure(engine, cleanEvent, iterations);
(double dirtyOps, double dirtyUs) = Measure(engine, dirtyEvent, iterations);

Console.WriteLine("Bower PrivacyEngine micro-benchmark");
Console.WriteLine($"  iterations: {iterations}");
Console.WriteLine($"  clean event: {cleanOps:F0} ops/s  mean {cleanUs:F1} µs");
Console.WriteLine($"  dirty event: {dirtyOps:F0} ops/s  mean {dirtyUs:F1} µs");
Console.WriteLine($"  detectors:   {engine.Detectors.Count}");

using System.Diagnostics;
using Bower.Abstractions;
using Bower.Output.AmaSpool;
using Bower.Persistence;
using Bower.Redaction.Privacy;
using Microsoft.Data.Sqlite;

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
      "note": "contact +61 412 345 678 and abn 51 824 753 556",
      "change": { "field": "password", "previousValue": "ordinary-before", "newValue": "ordinary-after" },
      "request": { "path": "https://user:ordinary-url@example.test/login?state=ordinary-query#ordinary-fragment" }
    }
    """;

PrivacyEngine engine = new();

const string permissionEvent =
    """
    {"eventType":"gcp_cloud_audit","change":{"field":"permission_direction","newValue":"mixed"},
     "attributes":{"cloud.permissionChanges":{"mode":"delta","target":"projects/example","entries":[
       {"member":"allUsers","permission":"roles/viewer","direction":"grant","conditionPresent":false},
       {"member":"user:alice@example.test","permission":"roles/owner","direction":"revoke","conditionPresent":true}]}}}
    """;

// Warmup
for (int i = 0; i < 200; i++)
{
    _ = engine.RedactJson(cleanEvent);
    _ = engine.RedactJson(dirtyEvent);
    _ = engine.RedactJson(permissionEvent);
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

// Wide event: many short fields, the common shape of cloud audit records.
System.Text.StringBuilder wide = new("{\"schemaVersion\":\"1.0.0\",\"eventId\":\"evt-3\"");
for (int i = 0; i < 200; i++)
{
    wide.Append(System.Globalization.CultureInfo.InvariantCulture, $",\"field_{i}\":\"value number {i} from resource arn:aws:iam::123456789012:role/r{i}\"");
}

string wideEvent = wide.Append('}').ToString();

// Dense value: one large field carrying thousands of findings (bounded by the 1 MiB limit).
System.Text.StringBuilder dense = new("{\"eventId\":\"evt-4\",\"note\":\"");
for (int i = 0; i < 20_000; i++)
{
    dense.Append(System.Globalization.CultureInfo.InvariantCulture, $"u{i}@ex.io ");
}

string denseEvent = dense.Append("\"}").ToString();

// Licence value: driver-licence context with thousands of state-bucketed tokens.
System.Text.StringBuilder licences = new("{\"eventId\":\"evt-5\",\"note\":\"driver licence");
for (int i = 0; i < 5_000; i++)
{
    licences.Append(System.Globalization.CultureInfo.InvariantCulture, $" AB{100_000 + i} {10_000_000 + i}");
}

string licenceEvent = licences.Append("\"}").ToString();

(double cleanOps, double cleanUs) = Measure(engine, cleanEvent, iterations);
(double dirtyOps, double dirtyUs) = Measure(engine, dirtyEvent, iterations);
(double permissionOps, double permissionUs) = Measure(engine, permissionEvent, iterations);
(double wideOps, double wideUs) = Measure(engine, wideEvent, 500);
(double denseOps, double denseUs) = Measure(engine, denseEvent, 3);
(double licenceOps, double licenceUs) = Measure(engine, licenceEvent, 20);
long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
for (int i = 0; i < 1_000; i++)
{
    _ = engine.RedactJson(cleanEvent);
}

long cleanAllocated = (GC.GetAllocatedBytesForCurrentThread() - allocatedBefore) / 1_000;

Console.WriteLine("Bower PrivacyEngine micro-benchmark");
Console.WriteLine($"  iterations: {iterations}");
Console.WriteLine($"  clean event: {cleanOps:F0} ops/s  mean {cleanUs:F1} µs  alloc {cleanAllocated} B/op");
Console.WriteLine($"  dirty event: {dirtyOps:F0} ops/s  mean {dirtyUs:F1} µs");
Console.WriteLine($"  cloud permission event: {permissionOps:F0} ops/s  mean {permissionUs:F1} µs");
Console.WriteLine($"  wide event (200 fields): {wideOps:F0} ops/s  mean {wideUs:F1} µs");
Console.WriteLine($"  dense value (20k emails, {denseEvent.Length / 1024} KiB): mean {denseUs / 1000:F1} ms");
Console.WriteLine($"  licence value (10k licence tokens, {licenceEvent.Length / 1024} KiB): mean {licenceUs / 1000:F1} ms");
Console.WriteLine($"  detectors:   {engine.Detectors.Count}");

// Queue settlement: one transaction per acknowledged event vs one per delivery batch.
const int settleBatch = 500;
string queueRoot = Path.Combine(Path.GetTempPath(), $"bower-bench-{Guid.NewGuid():N}");
Directory.CreateDirectory(queueRoot);
try
{
    SqliteEventStore store = new(Path.Combine(queueRoot, "queue.db"), 1L << 30);
    await store.InitializeAsync();
    string payload = "{\"eventId\":\"x\",\"note\":\"" + new string('p', 1_000) + "\"}";
    int nextId = 0;

    async Task<IReadOnlyList<string>> EnqueueAndLeaseAsync(int count)
    {
        for (int i = 0; i < count; i++)
        {
            string id = $"evt-{nextId++}";
            await store.EnqueueAsync(new QueuedEvent(id, $"sha256:{id}", payload, DateTimeOffset.UtcNow));
        }

        return [.. (await store.LeaseAsync(count, TimeSpan.FromMinutes(5))).Select(item => item.EventId)];
    }

    double perEventMs = 0;
    double batchMs = 0;
    const int rounds = 3;
    for (int round = 0; round < rounds; round++)
    {
        IReadOnlyList<string> ids = await EnqueueAndLeaseAsync(settleBatch);
        Stopwatch perEvent = Stopwatch.StartNew();
        foreach (string id in ids)
        {
            await store.MarkDeliveredAsync(id, "bench");
        }

        perEventMs += perEvent.Elapsed.TotalMilliseconds;

        ids = await EnqueueAndLeaseAsync(settleBatch);
        Stopwatch batch = Stopwatch.StartNew();
        await store.MarkDeliveredBatchAsync(ids, "bench");
        batchMs += batch.Elapsed.TotalMilliseconds;
    }

    // Enqueue cost with a deep backlog, with and without the capacity covering index.
    const int backlog = 20_000;
    for (int i = 0; i < backlog; i++)
    {
        string id = $"backlog-{i}";
        await store.EnqueueAsync(new QueuedEvent(id, $"sha256:{id}", payload, DateTimeOffset.UtcNow));
    }

    async Task<double> MeasureEnqueueMsAsync(string prefix)
    {
        Stopwatch watch = Stopwatch.StartNew();
        for (int i = 0; i < 200; i++)
        {
            string id = $"{prefix}-{i}";
            await store.EnqueueAsync(new QueuedEvent(id, $"sha256:{id}", payload, DateTimeOffset.UtcNow));
        }

        return watch.Elapsed.TotalMilliseconds / 200;
    }

    double indexedMs = await MeasureEnqueueMsAsync("indexed");
    await using (SqliteConnection raw = new($"Data Source={Path.Combine(queueRoot, "queue.db")};Pooling=False"))
    {
        await raw.OpenAsync();
        await using SqliteCommand drop = raw.CreateCommand();
        drop.CommandText = "DROP INDEX ix_queue_events_state_bytes;";
        await drop.ExecuteNonQueryAsync();
    }

    double unindexedMs = await MeasureEnqueueMsAsync("unindexed");
    SqliteConnection.ClearAllPools();

    Console.WriteLine("Bower queue micro-benchmark");
    Console.WriteLine($"  settle {settleBatch} acknowledged events, per-event: {perEventMs / rounds:F1} ms");
    Console.WriteLine($"  settle {settleBatch} acknowledged events, batched:   {batchMs / rounds:F1} ms");
    Console.WriteLine($"  enqueue with {backlog} backlog, capacity index:    {indexedMs * 1000:F0} µs/op");
    Console.WriteLine($"  enqueue with {backlog} backlog, no capacity index: {unindexedMs * 1000:F0} µs/op");
}
finally
{
    Directory.Delete(queueRoot, recursive: true);
}

// AMA spool: 5,000 x ~1 KiB records, current options vs the previous write-through file.
string spoolRoot = Path.Combine(Path.GetTempPath(), $"bower-spool-{Guid.NewGuid():N}");
try
{
    QueuedEvent[] spoolEvents =
    [
        .. Enumerable.Range(0, 5_000).Select(i => new QueuedEvent(
            $"spool-{i}",
            $"sha256:spool-{i}",
            "{\"eventId\":\"spool-" + i + "\",\"note\":\"" + new string('s', 1_000) + "\"}",
            DateTimeOffset.UtcNow))
    ];
    AmaSpoolOutput spool = new(new AmaSpoolOptions
    {
        Id = "bench",
        CollectorId = "bench",
        StreamName = "Custom-Bower",
        ActiveDirectory = Path.Combine(spoolRoot, "active"),
        ReadyDirectory = Path.Combine(spoolRoot, "ready")
    });
    Stopwatch current = Stopwatch.StartNew();
    await spool.DeliverAsync(spoolEvents);
    double currentMs = current.Elapsed.TotalMilliseconds;

    // Replica of the previous file options (WriteThrough, default buffer) for comparison.
    Stopwatch previous = Stopwatch.StartNew();
    FileStreamOptions writeThrough = new()
    {
        Access = FileAccess.Write,
        Mode = FileMode.CreateNew,
        Share = FileShare.None,
        Options = FileOptions.Asynchronous | FileOptions.WriteThrough
    };
    await using (FileStream stream = new(Path.Combine(spoolRoot, "previous.tmp"), writeThrough))
    await using (StreamWriter writer = new(stream, new System.Text.UTF8Encoding(false), leaveOpen: true))
    {
        writer.NewLine = "\n";
        foreach (QueuedEvent item in spoolEvents)
        {
            await writer.WriteLineAsync(item.Payload.AsMemory());
        }

        await writer.FlushAsync();
        stream.Flush(true);
    }

    double previousMs = previous.Elapsed.TotalMilliseconds;
    Console.WriteLine("Bower AMA spool micro-benchmark (5,000 x 1 KiB records)");
    Console.WriteLine($"  current (buffered, one fsync):  {currentMs:F1} ms");
    Console.WriteLine($"  previous (write-through):       {previousMs:F1} ms");
}
finally
{
    Directory.Delete(spoolRoot, recursive: true);
}

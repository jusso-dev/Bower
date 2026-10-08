using System.Text.Json;
using Bower.Abstractions;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Persistence;

namespace Bower.Cli.Commands;

internal static class EvidenceCommands
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>
    /// bower evidence run --collector-url URL [--workspace-id ID] [--workspace-resource-id RID]
    ///   [--table NAME] [--credential MODE] [--timeout-minutes N] [--signing-key FILE] [--out FILE]
    /// Reads the ingest token from BOWER_INGEST_TOKEN. Without --workspace-id the bundle is simulated.
    /// </summary>
    public static async Task<int> RunAsync(string[] args)
    {
        string? workspaceId = CliOptions.Get(args, "--workspace-id");
        HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };
        Azure.Core.TokenCredential? credential = workspaceId is null && CliOptions.Get(args, "--workspace-resource-id") is null
            ? null
            : VerifierCredential.Create(CliOptions.Get(args, "--credential"), CliOptions.Get(args, "--client-id"));
        EvidenceRunner runner = new(
            new HttpCanarySender(http),
            workspaceId is null || credential is null ? null : new LogAnalyticsQueryClient(http, credential),
            credential is null ? null : new ArmReader(http, credential));
        string collector = CliOptions.Required(args, "--collector-url");
        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions
            {
                CollectorUrl = new Uri(collector.EndsWith('/') ? collector : collector + "/"),
                IngestToken = Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN"),
                WorkspaceId = workspaceId,
                WorkspaceResourceId = CliOptions.Get(args, "--workspace-resource-id"),
                Table = CliOptions.Get(args, "--table") ?? "BowerSecurity_CL",
                Timeout = TimeSpan.FromMinutes(CliOptions.Int(args, "--timeout-minutes", 15))
            },
            CancellationToken.None);

        string? key = CliOptions.Get(args, "--signing-key") is { } keyPath ? File.ReadAllText(keyPath) : null;
        SignedEvidence signed = EvidenceRunner.Sign(bundle, key);
        string json = JsonSerializer.Serialize(signed, Indented);
        string output = CliOptions.Get(args, "--out") ?? $"bower-evidence-{bundle.GeneratedAt:yyyyMMddTHHmmssZ}.json";
        File.WriteAllText(output, json);

        Console.WriteLine($"Mode:     {bundle.Mode}");
        Console.WriteLine($"Canary:   {bundle.Canary.EventId} -> collector HTTP {bundle.Canary.CollectorStatus} ({bundle.Canary.CollectorDecision ?? "no decision"})");
        if (bundle.Arrival.Found)
        {
            Console.WriteLine($"Arrival:  found in {bundle.Arrival.Table} after {bundle.Arrival.LatencySeconds} s ({bundle.Arrival.Attempts} queries)");
        }
        else
        {
            Console.WriteLine($"Arrival:  not proven ({bundle.Arrival.QueryError ?? bundle.Mode})");
        }

        foreach (ControlRecord control in bundle.Controls)
        {
            Console.WriteLine($"  {control.Id,-16} {control.Status,-14} {control.Requirement}");
        }

        Console.WriteLine($"Signed:   {(signed.Signature is null ? "no (pass --signing-key)" : signed.Signature.KeyId)}");
        Console.WriteLine($"Bundle:   {output}");
        return bundle.Mode == EvidenceModes.Verified ? 0 : 2;
    }

    /// <summary>bower evidence verify FILE --trusted-key PUBLIC.pem</summary>
    public static int Verify(string[] args)
    {
        string file = CliOptions.Positional(args) ?? throw new ArgumentException("Provide an evidence bundle file.");
        SignedEvidence evidence = JsonSerializer.Deserialize<SignedEvidence>(File.ReadAllText(file))
            ?? throw new InvalidDataException("Evidence bundle is unreadable.");
        string[] keys = CliOptions.All(args, "--trusted-key").Select(File.ReadAllText).ToArray();
        bool valid = EvidenceRunner.Verify(evidence, keys);
        string mode = evidence.Bundle["mode"]?.GetValue<string>() ?? "unknown";
        Console.WriteLine(valid
            ? $"Signature valid (key {evidence.Signature!.KeyId}). Mode: {mode}."
            : "Signature INVALID or from an untrusted key.");
        return valid ? 0 : 1;
    }
}

internal static class QueueCommands
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static async Task<SqliteEventStore> OpenAsync(string[] args)
    {
        string path = CliOptions.Get(args, "--database") ?? Path.Combine(Directory.GetCurrentDirectory(), "data", "bower.db");
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Queue database not found: {path}");
        }

        SqliteEventStore store = new(path, 10L * 1024 * 1024 * 1024);
        await store.InitializeAsync();
        return store;
    }

    /// <summary>bower queue dead-letters --database FILE [--max N]: metadata only.</summary>
    public static async Task<int> DeadLettersAsync(string[] args)
    {
        SqliteEventStore store = await OpenAsync(args);
        IReadOnlyList<DeadLetterRecord> records = await store.ListDeadLetteredAsync(CliOptions.Int(args, "--max", 100));
        Console.WriteLine(JsonSerializer.Serialize(records, Indented));
        return 0;
    }

    /// <summary>bower queue replay --database FILE (--code PREFIX | --event ID ...) [--max N]</summary>
    public static async Task<int> ReplayAsync(string[] args)
    {
        string? code = CliOptions.Get(args, "--code");
        IReadOnlyList<string> events = CliOptions.All(args, "--event");
        if (code is null && events.Count == 0)
        {
            throw new ArgumentException("Choose what to replay with --code PREFIX or --event ID.");
        }

        SqliteEventStore store = await OpenAsync(args);
        int replayed = await store.ReplayDeadLetteredAsync(code, events, CliOptions.Int(args, "--max", 1000));
        Console.WriteLine($"Returned {replayed} dead-lettered event(s) to the queue.");
        return 0;
    }

    /// <summary>bower queue verify --database FILE [--expect-head SEQUENCE:HASH]</summary>
    public static async Task<int> VerifyAsync(string[] args)
    {
        SqliteEventStore store = await OpenAsync(args);
        LedgerVerification result = await store.VerifyLedgerAsync();
        Console.WriteLine($"Ledger entries: {result.Entries}; head {result.HeadSequence}:{result.HeadHash}");
        foreach (LedgerIssue issue in result.Issues.Take(50))
        {
            Console.WriteLine($"  {issue.Code,-18} seq {issue.Sequence,-8} {issue.EventId} {issue.Detail}");
        }

        bool headOk = true;
        if (CliOptions.Get(args, "--expect-head") is { } expected)
        {
            string[] parts = expected.Split(':', 2);
            long sequence = long.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture);
            headOk = result.HeadSequence > sequence
                || (result.HeadSequence == sequence && parts.Length == 2 && parts[1] == result.HeadHash);
            if (!headOk)
            {
                Console.WriteLine("  head-regression    The ledger is behind or differs from the witnessed head.");
            }
        }

        Console.WriteLine(result.Intact && headOk ? "Ledger intact." : "Ledger verification FAILED.");
        return result.Intact && headOk ? 0 : 1;
    }
}

internal static class TokenCommands
{
    /// <summary>bower token generate [--id PRODUCER]</summary>
    public static int Generate(string[] args)
    {
        byte[] bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        string token = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (CliOptions.Get(args, "--id") is { } producer)
        {
            string digest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
            Console.Error.WriteLine($"Give this token to producer '{producer}' (shown once):");
            Console.WriteLine(token);
            Console.Error.WriteLine("Add this line to the collector's BOWER_INGEST_TOKENS_FILE (remove it to revoke):");
            Console.Error.WriteLine($"{producer} sha256:{digest}");
        }
        else
        {
            Console.WriteLine(token);
        }

        return 0;
    }
}

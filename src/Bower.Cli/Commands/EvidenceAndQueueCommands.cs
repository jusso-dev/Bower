using System.Text.Json;
using Bower.Abstractions;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Persistence;

namespace Bower.Cli.Commands;

internal static class EvidenceCommands
{
    /// <summary>
    /// bower evidence run --collector-url URL [--workspace-id ID] [--workspace-resource-id RID]
    ///   [--table NAME] [--credential MODE] [--timeout-minutes N] [--signing-key FILE] [--out FILE]
    ///   [--probe-profile generic|parser:PACK:INDEX]
    /// Reads the ingest token from BOWER_INGEST_TOKEN. Without --workspace-id the bundle is simulated.
    /// The default generic probe posts a canary to /v1/events; a parser profile posts a trusted
    /// synthetic fixture through that signed pack parser's intake instead.
    /// </summary>
    public static async Task<int> RunAsync(string[] args)
    {
        TimeSpan timeout = TimeSpan.FromMinutes(TimeoutMinutes(args));
        string probeProfile = CliOptions.Get(args, "--probe-profile") ?? ProbeProfiles.Generic;
        if (probeProfile != ProbeProfiles.Generic)
        {
            ProbeProfiles.ResolveParser(probeProfile);
        }

        string? workspaceId = CliOptions.Get(args, "--workspace-id");
        HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };
        Azure.Core.TokenCredential? credential = workspaceId is null && CliOptions.Get(args, "--workspace-resource-id") is null
            ? null
            : VerifierCredential.Create(CliOptions.Get(args, "--credential"), CliOptions.Get(args, "--client-id"));
        HttpCanarySender sender = new(http);
        EvidenceRunner runner = new(
            sender,
            workspaceId is null || credential is null ? null : new LogAnalyticsQueryClient(http, credential),
            credential is null ? null : new ArmReader(http, credential),
            parserSender: sender);
        string collector = CliOptions.Required(args, "--collector-url");
        EvidenceBundle bundle = await runner.RunAsync(
            new EvidenceOptions
            {
                CollectorUrl = new Uri(collector.EndsWith('/') ? collector : collector + "/"),
                IngestToken = Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN"),
                WorkspaceId = workspaceId,
                WorkspaceResourceId = CliOptions.Get(args, "--workspace-resource-id"),
                Table = CliOptions.Get(args, "--table") ?? "BowerSecurity_CL",
                Timeout = timeout,
                ProbeProfile = probeProfile
            },
            CancellationToken.None);

        string? key = CliOptions.Get(args, "--signing-key") is { } keyPath ? File.ReadAllText(keyPath) : null;
        SignedEvidence signed = EvidenceRunner.Sign(bundle, key);
        string json = JsonSerializer.Serialize(signed, CliJsonContext.Default.SignedEvidence);
        string output = CliOptions.Get(args, "--out") ?? $"bower-evidence-{bundle.GeneratedAt:yyyyMMddTHHmmssZ}.json";
        File.WriteAllText(output, json);

        Console.WriteLine($"Mode:     {bundle.Mode}");
        Console.WriteLine($"Canary:   {bundle.Canary.EventId} -> collector HTTP {bundle.Canary.CollectorStatus} ({bundle.Canary.CollectorDecision ?? "no decision"})");
        if (bundle.Probe is { } probe)
        {
            Console.WriteLine($"Probe:    {probe.Profile} pack {probe.PackVersion ?? "unknown"} ({probe.ParserStatus ?? "unknown"}) -> {probe.Outcome}");
        }

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

    /// <summary>Longest arrival wait <c>evidence run</c> accepts: one day.</summary>
    public const int MaximumTimeoutMinutes = 1_440;

    /// <summary><c>--timeout-minutes N</c> (default 15); must be 1 to <see cref="MaximumTimeoutMinutes"/>.</summary>
    public static int TimeoutMinutes(string[] args)
    {
        int minutes = CliOptions.Int(args, "--timeout-minutes", 15);
        return minutes is >= 1 and <= MaximumTimeoutMinutes
            ? minutes
            : throw new ArgumentException($"--timeout-minutes must be between 1 and {MaximumTimeoutMinutes}.");
    }

    /// <summary>bower evidence verify FILE --trusted-key PUBLIC.pem</summary>
    public static int Verify(string[] args)
    {
        string file = CliOptions.Positional(args) ?? throw new ArgumentException("Provide an evidence bundle file.");
        SignedEvidence evidence = EvidenceRunner.Parse(File.ReadAllText(file));
        string[] keys = CliOptions.All(args, "--trusted-key").Select(File.ReadAllText).ToArray();
        bool valid = EvidenceRunner.Verify(evidence, keys);
        string mode = EvidenceRunner.ModeOf(evidence);
        Console.WriteLine(valid
            ? $"Signature valid (key {evidence.Signature!.KeyId}). Mode: {mode}."
            : "Signature INVALID or from an untrusted key.");
        return valid ? 0 : 1;
    }
}

internal static class QueueCommands
{
    internal static Task<SqliteEventStore> OpenStoreAsync(string[] args) => OpenAsync(args);

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
        Console.WriteLine(JsonSerializer.Serialize(records, CliJsonContext.Default.IReadOnlyListDeadLetterRecord));
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

    /// <summary>
    /// bower queue backup --database FILE --output BACKUP [--collector-id ID]: consistent online
    /// copy plus BACKUP.manifest.json (metadata only). Never initializes or migrates the source.
    /// A damaged queue is still copied; the command then warns and exits 3.
    /// </summary>
    public static async Task<int> BackupAsync(string[] args)
    {
        QueueBackupManifest manifest = await QueueBackup.CreateAsync(
            CliOptions.Required(args, "--database"),
            CliOptions.Required(args, "--output"),
            CliOptions.Get(args, "--collector-id"));
        Console.WriteLine(QueueBackup.ToJson(manifest));
        if (manifest.Damaged)
        {
            Console.Error.WriteLine(
                "WARNING: the queue FAILED its integrity or ledger check. The backup was written and marked " +
                "damaged; keep it and the original files. Restoring it requires --allow-damaged.");
            return 3;
        }
        return 0;
    }

    /// <summary>
    /// bower queue restore --backup BACKUP --database FILE [--allow-damaged]: verifies the
    /// manifest, refuses to overwrite an existing queue or WAL, and checks the restored copy
    /// before renaming it.
    /// </summary>
    public static async Task<int> RestoreAsync(string[] args)
    {
        QueueRestoreResult result = await QueueBackup.RestoreAsync(
            CliOptions.Required(args, "--backup"),
            CliOptions.Required(args, "--database"),
            allowDamaged: CliOptions.Has(args, "--allow-damaged"));
        Console.WriteLine(QueueBackup.ToJson(result));
        Console.Error.WriteLine(result.RestoredDamagedBackup
            ? "Restored a DAMAGED backup as requested. Verify the queue before delivery resumes."
            : "Restored. Unsettled rows will be delivered again (at least once); source cursors resume from the backup point.");
        return 0;
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

using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Evidence;
using Bower.Persistence;

namespace Bower.Cli.Commands;

internal static class BundleCommands
{
    /// <summary>
    /// bower export bundle --database FILE --out FILE --signing-key PRIVATE.pem
    ///   [--collector-id ID] [--environment ENV] [--policy-hash HASH] [--privacy-profile-hash HASH]
    ///   [--encrypt-key-file FILE] [--max-events N]
    /// </summary>
    public static async Task<int> ExportAsync(string[] args)
    {
        SqliteEventStore store = await QueueCommands.OpenStoreAsync(args);
        string outPath = CliOptions.Required(args, "--out");
        string signingKeyPath = CliOptions.Required(args, "--signing-key");
        string signingKeyPem = await File.ReadAllTextAsync(signingKeyPath);
        byte[]? encryptionKey = CliOptions.Get(args, "--encrypt-key-file") is { } encFile
            ? AirGappedBundle.ReadEncryptionKeyFile(encFile)
            : null;
        int maxEvents = CliOptions.Int(args, "--max-events", 50_000);
        if (maxEvents is < 1 or > 100_000)
        {
            throw new ArgumentException("--max-events must be between 1 and 100000.");
        }

        ExportBundleCursor? last = await store.GetLastExportBundleAsync();
        long afterSequence = last?.ToLedgerSequence ?? 0;
        long nextBundleSequence = (last?.BundleSequence ?? 0) + 1;
        string previousBundleHash = last?.BundleHash ?? AirGappedBundleManifest.GenesisBundleHash;

        IReadOnlyList<LedgerEvent> events = await store.ReadLedgerEventsAsync(afterSequence, maxEvents);
        QueueSnapshot snapshot = await store.GetSnapshotAsync();
        LedgerHead head = await store.GetLedgerHeadAsync();
        long fromSequence = events.Count > 0 ? events[0].Sequence : afterSequence;
        long toSequence = events.Count > 0 ? events[^1].Sequence : afterSequence;
        string headHash = events.Count > 0 ? events[^1].ChainHash : head.Hash;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string bundleId = $"bundle-{Guid.CreateVersion7():N}";

        AirGappedBundleManifest manifest = new(
            AirGappedBundleManifest.CurrentKind,
            bundleId,
            CliOptions.Get(args, "--collector-id") ?? Environment.MachineName,
            Environment.MachineName,
            CliOptions.Get(args, "--environment") ?? "air-gapped",
            BowerVersion.Current,
            CliOptions.Get(args, "--policy-hash") ?? "local",
            CliOptions.Get(args, "--privacy-profile-hash") ?? "default",
            nextBundleSequence,
            previousBundleHash,
            fromSequence,
            toSequence,
            headHash,
            events.Count,
            snapshot.Queued + snapshot.Retrying + snapshot.Uploading,
            snapshot.DeadLettered,
            string.Empty,
            encryptionKey is not null,
            now.ToString("O", CultureInfo.InvariantCulture));

        AirGappedExportResult result = AirGappedBundle.Create(
            outPath,
            manifest,
            events.Select(item => item.Payload),
            signingKeyPem,
            encryptionKey);

        await store.RecordExportBundleAsync(new ExportBundleCursor(
            result.BundleSequence,
            result.BundleId,
            result.FromLedgerSequence,
            result.ToLedgerSequence,
            result.BundleHash,
            now));

        Console.WriteLine(JsonSerializer.Serialize(
            new BundleExportOutput(
                result.BundleId,
                result.BundleSequence,
                result.BundleHash,
                result.FromLedgerSequence,
                result.ToLedgerSequence,
                result.EventCount,
                result.Encrypted),
            CliJsonContext.Default.BundleExportOutput));
        return 0;
    }

    /// <summary>
    /// bower verify bundle --bundle FILE --trusted-key PUBLIC.pem
    ///   [--expect-sequence N] [--expect-previous-hash HASH] [--decrypt-key-file FILE]
    /// </summary>
    public static int Verify(string[] args)
    {
        string bundlePath = CliOptions.Required(args, "--bundle");
        IReadOnlyList<string> trustedKeyPaths = CliOptions.All(args, "--trusted-key");
        if (trustedKeyPaths.Count == 0)
        {
            throw new ArgumentException("At least one --trusted-key PUBLIC.pem is required.");
        }

        string[] keys = trustedKeyPaths.Select(File.ReadAllText).ToArray();
        long? expectedSeq = CliOptions.Has(args, "--expect-sequence")
            ? CliOptions.Int(args, "--expect-sequence", 0)
            : null;
        string? expectedPrev = CliOptions.Get(args, "--expect-previous-hash");
        byte[]? decryptionKey = CliOptions.Get(args, "--decrypt-key-file") is { } decFile
            ? AirGappedBundle.ReadEncryptionKeyFile(decFile)
            : null;

        AirGappedBundleVerification verification = AirGappedBundle.Verify(
            bundlePath, keys, expectedSeq, expectedPrev, decryptionKey);
        Console.WriteLine(JsonSerializer.Serialize(
            new BundleVerifyOutput(
                verification.Valid,
                verification.Error,
                verification.Manifest?.BundleId,
                verification.Manifest?.CollectorId,
                verification.Manifest?.BundleSequence,
                verification.BundleHash,
                verification.Manifest?.EventCount,
                verification.Manifest?.Encrypted),
            CliJsonContext.Default.BundleVerifyOutput));
        return verification.Valid ? 0 : 3;
    }

    /// <summary>
    /// bower import bundle --bundle FILE --trusted-key PUBLIC.pem
    ///   [--collector-url URL] [--management-url URL] [--decrypt-key-file FILE] [--dry-run]
    /// Verifies the bundle first. Submits already-redacted events only to --collector-url, and
    /// submits only the signed metadata-only status report to --management-url.
    /// </summary>
    public static Task<int> ImportAsync(string[] args) => ImportAsync(args, null, Console.Out, Console.Error);

    internal static async Task<int> ImportAsync(
        string[] args,
        HttpMessageHandler? handler,
        TextWriter output,
        TextWriter error)
    {
        string bundlePath = CliOptions.Required(args, "--bundle");
        IReadOnlyList<string> trustedKeyPaths = CliOptions.All(args, "--trusted-key");
        if (trustedKeyPaths.Count == 0)
        {
            throw new ArgumentException("At least one --trusted-key PUBLIC.pem is required.");
        }

        string[] keys = trustedKeyPaths.Select(File.ReadAllText).ToArray();
        byte[]? decryptionKey = CliOptions.Get(args, "--decrypt-key-file") is { } decFile
            ? AirGappedBundle.ReadEncryptionKeyFile(decFile)
            : null;
        bool dryRun = CliOptions.Has(args, "--dry-run");
        string? collectorUrl = CliOptions.Get(args, "--collector-url");
        string? managementUrl = CliOptions.Get(args, "--management-url");

        AirGappedBundleVerification verification = AirGappedBundle.Verify(bundlePath, keys, decryptionKey: decryptionKey);
        if (!verification.Valid || verification.Manifest is null || verification.OfflineReport is null)
        {
            output.WriteLine(JsonSerializer.Serialize(
                new BundleVerifyOutput(false, verification.Error, null, null, null, null, null, null),
                CliJsonContext.Default.BundleVerifyOutput));
            error.WriteLine($"Bundle failed verification: {verification.Error}");
            return 3;
        }

        IReadOnlyList<string> events = AirGappedBundle.ReadVerifiedEvents(bundlePath, keys, decryptionKey);
        SortedDictionary<string, long> collectorResponses = new(StringComparer.Ordinal);
        string? managementStatus = null;

        if (!dryRun && !string.IsNullOrWhiteSpace(collectorUrl))
        {
            using HttpClient client = new(handler ?? new HttpClientHandler(), disposeHandler: handler is null)
            {
                BaseAddress = new Uri(collectorUrl.EndsWith('/') ? collectorUrl : collectorUrl + "/"),
                Timeout = TimeSpan.FromSeconds(30)
            };
            if (Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN") is { Length: > 0 } token)
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            foreach (string payload in events)
            {
                using StringContent content = new(payload, Encoding.UTF8, "application/json");
                using HttpResponseMessage response = await client.PostAsync("v1/events", content);
                string code = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
                collectorResponses[code] = collectorResponses.GetValueOrDefault(code) + 1;
            }
        }

        if (!dryRun && !string.IsNullOrWhiteSpace(managementUrl))
        {
            using HttpClient mgmt = new(handler ?? new HttpClientHandler(), disposeHandler: handler is null)
            {
                BaseAddress = new Uri(managementUrl.EndsWith('/') ? managementUrl : managementUrl + "/"),
                Timeout = TimeSpan.FromSeconds(30)
            };
            if (Environment.GetEnvironmentVariable("BOWER_MANAGEMENT_TOKEN") is { Length: > 0 } mgmtToken)
            {
                mgmt.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", mgmtToken);
            }

            string reportJson = JsonSerializer.Serialize(
                verification.OfflineReport, AirGappedBundleJsonContext.Default.SignedOfflineSiteReport);
            using StringContent content = new(reportJson, Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await mgmt.PostAsync("api/fleet/offline-import", content);
            managementStatus = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
        }

        output.WriteLine(JsonSerializer.Serialize(
            new BundleImportOutput(
                verification.Manifest.BundleId,
                verification.Manifest.BundleSequence,
                events.Count,
                dryRun,
                collectorResponses,
                managementStatus),
            CliJsonContext.Default.BundleImportOutput));
        return 0;
    }
}

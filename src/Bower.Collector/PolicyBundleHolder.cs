using System.Text.Json.Serialization;
using Bower.Abstractions;
using Bower.Packs;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;

namespace Bower.Collector;

/// <summary>
/// Metadata-only outcome of the most recent in-process configuration hot reload. Never
/// contains file paths, YAML content, secrets or credentials.
/// </summary>
public sealed record ConfigReloadStatus(
    string Outcome,
    string Trigger,
    DateTimeOffset At,
    string PolicyHash,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? PreviousPolicyHash = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? ErrorType = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    long? LedgerSequence = null);

/// <summary>
/// Atomic holder for the collector's active <see cref="PolicyBundle"/>, redactor and policy
/// evaluator. Readers observe an immutable snapshot lock-free; reloads validate every file
/// (policies, signed packs, trusted keys, privacy profile, source routes and health-record
/// policy) and record a hash-chained ledger entry before swapping the active reference.
/// Invalid reloads leave the running snapshot untouched.
/// </summary>
public sealed partial class PolicyBundleHolder : IPolicyRuntimeProvider, IDisposable
{
    private sealed record Snapshot(PolicyBundle Bundle, ActivePolicyRuntime Runtime);

    private readonly CollectorSettings settings;
    private readonly IDurableEventStore? eventStore;
    private readonly TimeProvider clock;
    private readonly ILogger<PolicyBundleHolder> logger;
    private readonly SemaphoreSlim reloadGate = new(1, 1);

    private Snapshot current;
    private ConfigReloadStatus? lastReload;

    public PolicyBundleHolder(
        PolicyBundle initialBundle,
        CollectorSettings settings,
        IDurableEventStore? eventStore = null,
        TimeProvider? clock = null,
        ILogger<PolicyBundleHolder>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(initialBundle);
        ArgumentNullException.ThrowIfNull(settings);
        this.settings = settings;
        this.eventStore = eventStore;
        this.clock = clock ?? TimeProvider.System;
        this.logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<PolicyBundleHolder>.Instance;
        current = CreateSnapshot(initialBundle);
    }

    public PolicyBundle CurrentBundle => Volatile.Read(ref current).Bundle;

    public ActivePolicyRuntime Current => Volatile.Read(ref current).Runtime;

    public ConfigReloadStatus? LastReload => Volatile.Read(ref lastReload);

    /// <summary>
    /// Reloads policies, signed packs and privacy profile from disk without stopping the
    /// collector or interrupting queued delivery. Serialized so concurrent SIGHUP, watcher
    /// and HTTP triggers cannot interleave.
    /// </summary>
    public async Task<ConfigReloadStatus> ReloadAsync(string trigger, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trigger);
        await reloadGate.WaitAsync(cancellationToken);
        try
        {
            Snapshot active = Volatile.Read(ref current);
            DateTimeOffset now = clock.GetUtcNow();
            PolicyBundle candidate;
            try
            {
                candidate = PolicyBundle.Load(settings.PolicySources());
                _ = CollectorStartupSources.Load(settings, candidate);
                if (settings.HealthRecordInterval is not null)
                {
                    CollectorApplication.RequireHealthRecordPolicy(settings, candidate);
                }
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
            {
                string errorType = exception.GetType().Name;
                LogReloadRejected(logger, trigger, errorType);
                ConfigReloadStatus rejected = new(
                    "rejected",
                    trigger,
                    now,
                    active.Bundle.Hash,
                    ErrorType: errorType);
                Volatile.Write(ref lastReload, rejected);
                return rejected;
            }

            if (string.Equals(candidate.Hash, active.Bundle.Hash, StringComparison.Ordinal)
                && string.Equals(candidate.PrivacyProfileHash, active.Bundle.PrivacyProfileHash, StringComparison.Ordinal))
            {
                ConfigReloadStatus unchanged = new(
                    "unchanged",
                    trigger,
                    now,
                    active.Bundle.Hash);
                Volatile.Write(ref lastReload, unchanged);
                LogReloadUnchanged(logger, trigger, active.Bundle.Hash);
                return unchanged;
            }

            Snapshot next = CreateSnapshot(candidate);
            long? ledgerSequence = null;
            if (eventStore is SqliteEventStore sqlite)
            {
                ConfigReloadLedgerEntry entry = await sqlite.RecordConfigReloadAsync(
                    trigger,
                    active.Bundle.Hash,
                    candidate.Hash,
                    active.Bundle.PrivacyProfileHash ?? "default",
                    candidate.PrivacyProfileHash ?? "default",
                    cancellationToken);
                ledgerSequence = entry.Sequence;
            }

            Interlocked.Exchange(ref current, next);
            ConfigReloadStatus reloaded = new(
                "reloaded",
                trigger,
                now,
                candidate.Hash,
                PreviousPolicyHash: active.Bundle.Hash,
                LedgerSequence: ledgerSequence);
            Volatile.Write(ref lastReload, reloaded);
            LogReloadSucceeded(logger, trigger, active.Bundle.Hash, candidate.Hash, ledgerSequence ?? 0);
            return reloaded;
        }
        finally
        {
            reloadGate.Release();
        }
    }

    public void Dispose() => reloadGate.Dispose();

    private static Snapshot CreateSnapshot(PolicyBundle bundle)
    {
        DeterministicPolicyEvaluator evaluator = new(bundle.Policies);
        PackDetectionRedactor redactor = new(
            new JsonEventRedactor(bundle.Privacy),
            evaluator,
            bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray());
        return new Snapshot(bundle, new ActivePolicyRuntime(redactor, evaluator));
    }

    [LoggerMessage(
        EventId = 1701,
        Level = LogLevel.Information,
        Message = "Hot reload ({Trigger}) applied: policy bundle changed from {PreviousHash} to {NewHash} (reload ledger sequence {LedgerSequence}).")]
    private static partial void LogReloadSucceeded(
        ILogger logger,
        string trigger,
        string previousHash,
        string newHash,
        long ledgerSequence);

    [LoggerMessage(
        EventId = 1702,
        Level = LogLevel.Error,
        Message = "Hot reload ({Trigger}) rejected ({ErrorType}); the previous policy bundle stays active.")]
    private static partial void LogReloadRejected(ILogger logger, string trigger, string errorType);

    [LoggerMessage(
        EventId = 1703,
        Level = LogLevel.Information,
        Message = "Hot reload ({Trigger}) verified with no policy bundle change ({PolicyHash}).")]
    private static partial void LogReloadUnchanged(ILogger logger, string trigger, string policyHash);
}

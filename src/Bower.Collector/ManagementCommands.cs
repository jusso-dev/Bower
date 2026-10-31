using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Bower.Integrity;

namespace Bower.Collector;

/// <summary>
/// The closed set of management commands. Each maps to one fixed action: management can
/// never send code, paths or arguments. Anything else is refused as <c>unknown-command</c>.
/// </summary>
public static class ManagementCommandTypes
{
    public const string FetchBundle = "fetch-bundle";
    public const string RunCanary = "run-canary";
    public const string Reload = "reload";

    /// <summary>Rotates the key-bound credential of a token-enrolled collector (#109).</summary>
    public const string RotateCredential = "rotate-credential";

    public static readonly IReadOnlyList<string> All = [FetchBundle, RunCanary, Reload, RotateCredential];

    /// <summary>
    /// Commands this collector executes, in wire order. <c>fetch-bundle</c> needs managed
    /// privacy profiles (the only bundle management serves); <c>rotate-credential</c> needs a
    /// key-bound credential (token enrolment; an Entra identity has nothing to rotate). Empty
    /// without trusted command keys.
    /// </summary>
    public static IReadOnlyList<string> Supported(CollectorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.ManagementCommandTrustedKeyFiles.Count == 0)
        {
            return [];
        }

        List<string> supported = settings.UsesManagedPrivacyProfile ? [FetchBundle, RunCanary, Reload] : [RunCanary, Reload];
        if (settings.UsesEnrolment)
        {
            supported.Add(RotateCredential);
        }

        return supported;
    }
}

/// <summary>Result statuses and codes reported on the next heartbeat. Metadata only.</summary>
public static class ManagementCommandResults
{
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string Rejected = "rejected";

    public const string MalformedCommand = "malformed-command";
    public const string UntrustedSignature = "untrusted-signature";
    public const string WrongCollector = "wrong-collector";
    public const string UnknownCommand = "unknown-command";
    public const string NotYetValid = "not-yet-valid";
    public const string Expired = "expired";
    public const string InvalidLifetime = "invalid-lifetime";
    public const string Replayed = "replayed";
    public const string UnsupportedCommand = "unsupported-command";
    public const string CommandsNotConfigured = "commands-not-configured";
    public const string LedgerUnavailable = "ledger-unavailable";
    public const string LedgerFull = "ledger-full";
    public const string ExecutorBusy = "executor-busy";
    public const string Interrupted = "interrupted";

    public const string FetchTriggered = "fetch-triggered";
    public const string FetchUnavailable = "fetch-unavailable";
    public const string CanaryQueued = "canary-queued";
    public const string RestartRequested = "restart-requested";
    public const string ReloadRateLimited = "reload-rate-limited";
    public const string ReloadValidationFailed = "reload-validation-failed";
}

/// <summary>Wire shape of a signed command. Unknown members are rejected: every field is signed.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ManagementCommandDocument(
    string? Kind,
    string? CommandId,
    string? CollectorId,
    string? Command,
    string? Nonce,
    string? IssuedAt,
    string? ExpiresAt,
    DetachedSignature? Signature);

/// <summary>A command whose signature, collector binding and validity window verified.</summary>
public sealed record VerifiedManagementCommand(
    string CommandId,
    string Command,
    string Nonce,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);

/// <summary>Either a verified command or a rejection code (with the command id when it could be read).</summary>
public sealed record ManagementCommandVerification(
    VerifiedManagementCommand? Command,
    string? RejectionCode,
    string? CommandId)
{
    public static ManagementCommandVerification Reject(string code, string? commandId) => new(null, code, commandId);
}

/// <summary>
/// Verifies signed management commands. Order (first failure wins): shape, signature,
/// collector binding, closed command set, validity window. Must match the management API's
/// <c>ManagementCommandSigner</c> and the Rust collector byte for byte.
/// </summary>
public static class ManagementCommandVerifier
{
    public const string Kind = "bower.collector-command/v1";

    /// <summary>Clock skew tolerated on <c>issuedAt</c>.</summary>
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>Longest validity window management may sign.</summary>
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromHours(1);

    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    public static ManagementCommandVerification Verify(
        JsonElement element,
        string collectorId,
        IReadOnlyList<string> trustedPublicKeyPems,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        ManagementCommandDocument? document;
        try
        {
            document = element.ValueKind == JsonValueKind.Object
                ? element.Deserialize(CollectorJsonContext.Default.ManagementCommandDocument)
                : null;
        }
        catch (JsonException)
        {
            document = null;
        }

        if (document is not
            {
                Kind: Kind,
                CommandId: { } commandId,
                CollectorId: { } documentCollector,
                Command: { } command,
                Nonce: { } nonce,
                IssuedAt: { } issuedText,
                ExpiresAt: { } expiresText,
                Signature: { Algorithm: not null, KeyId: not null, Value: not null } signature
            }
            || !IsIdentifier(commandId)
            || !IsIdentifier(nonce)
            || command.Length is 0 or > 64
            || !TryParseTimestamp(issuedText, out DateTimeOffset issuedAt)
            || !TryParseTimestamp(expiresText, out DateTimeOffset expiresAt))
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.MalformedCommand, null);
        }

        // Unverified documents never name a command: a tampered copy injected on the path
        // must not be able to mark the real command rejected.
        byte[] payload = SignedBytes(commandId, documentCollector, command, nonce, issuedText, expiresText);
        if (!DetachedSigner.Verify(payload, signature, trustedPublicKeyPems))
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.UntrustedSignature, null);
        }

        if (!string.Equals(documentCollector, collectorId, StringComparison.Ordinal))
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.WrongCollector, commandId);
        }

        if (!ManagementCommandTypes.All.Contains(command, StringComparer.Ordinal))
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.UnknownCommand, commandId);
        }

        if (issuedAt > now + MaximumClockSkew)
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.NotYetValid, commandId);
        }

        if (expiresAt <= now)
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.Expired, commandId);
        }

        if (expiresAt <= issuedAt || expiresAt - issuedAt > MaximumLifetime)
        {
            return ManagementCommandVerification.Reject(ManagementCommandResults.InvalidLifetime, commandId);
        }

        return new ManagementCommandVerification(
            new VerifiedManagementCommand(commandId, command, nonce, issuedAt, expiresAt), null, commandId);
    }

    /// <summary>
    /// Canonical JSON of exactly the signed fields: kind, commandId, collectorId, command,
    /// nonce, issuedAt and expiresAt.
    /// </summary>
    public static byte[] SignedBytes(
        string commandId,
        string collectorId,
        string command,
        string nonce,
        string issuedAt,
        string expiresAt) =>
        CanonicalJson.Bytes(new JsonObject
        {
            ["kind"] = Kind,
            ["commandId"] = commandId,
            ["collectorId"] = collectorId,
            ["command"] = command,
            ["nonce"] = nonce,
            ["issuedAt"] = issuedAt,
            ["expiresAt"] = expiresAt
        });

    /// <summary>32 lowercase hex characters (a GUID "N" or 16 random bytes).</summary>
    public static bool IsIdentifier(string? value) =>
        value is { Length: 32 } && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');

    public static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);

    public static bool TryParseTimestamp(string text, out DateTimeOffset value) =>
        DateTimeOffset.TryParseExact(
            text,
            TimestampFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out value);
}

/// <summary>One command result as reported on the heartbeat.</summary>
public sealed record CommandResultReport(string? CommandId, string Status, string Code, DateTimeOffset CompletedAt);

/// <summary>The last canary a <c>run-canary</c> command ran. <c>queued</c> is local admission, never Sentinel proof.</summary>
public sealed record CanaryReport(string CommandId, string? EventId, DateTimeOffset RanAt, string Outcome);

/// <summary>A durable ledger entry: the command was admitted, and then finished.</summary>
internal sealed record CommandLedgerEntry(
    string CommandId,
    string Nonce,
    string Command,
    DateTimeOffset ExpiresAt,
    string Status,
    string? Code,
    DateTimeOffset? CompletedAt,
    bool Acknowledged);

internal sealed record CommandLedgerDocument(
    int SchemaVersion,
    IReadOnlyList<CommandLedgerEntry> Entries,
    CanaryReport? LastCanary,
    DateTimeOffset? LastReloadAt);

/// <summary>How the ledger admitted a verified command.</summary>
public enum CommandAdmission
{
    /// <summary>New: recorded as started; execute it once.</summary>
    Accepted,

    /// <summary>Same command id and nonce seen before: never execute again.</summary>
    Duplicate,

    /// <summary>Not executed; a rejection result is pending.</summary>
    Rejected
}

/// <summary>
/// Durable record of every admitted command, so execution is at most once across restarts
/// and results survive until management acknowledges them. Rejections of commands that never
/// ran stay in memory (bounded). A ledger that cannot be read refuses every command
/// (<c>ledger-unavailable</c>) rather than risk running one twice. Metadata only.
/// </summary>
public sealed class ManagementCommandLedger
{
    public const string FileName = "ledger.json";
    public const int MaximumEntries = 128;
    public const int MaximumPendingRejections = 32;
    public const int MaximumReportedResults = 32;

    /// <summary>Minimum time between two executed reloads.</summary>
    public static readonly TimeSpan ReloadInterval = TimeSpan.FromMinutes(10);

    /// <summary>Unacknowledged results are given up this long after their command expired.</summary>
    public static readonly TimeSpan UnacknowledgedRetention = TimeSpan.FromDays(7);

    private const string Started = "started";

    private readonly Lock gate = new();
    private readonly string path;
    private readonly TimeProvider clock;
    private readonly List<CommandLedgerEntry> entries = [];
    private readonly List<CommandResultReport> rejections = [];
    private CanaryReport? lastCanary;
    private DateTimeOffset? lastReloadAt;

    public ManagementCommandLedger(string directory, TimeProvider clock)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        path = Path.Combine(directory, FileName);
        this.clock = clock ?? TimeProvider.System;
        if (!File.Exists(path))
        {
            Available = true;
            return;
        }

        try
        {
            CommandLedgerDocument? document = JsonSerializer.Deserialize(
                File.ReadAllBytes(path), CollectorJsonContext.Default.CommandLedgerDocument);
            if (document is not { SchemaVersion: 1, Entries: not null })
            {
                return;
            }

            // A command still marked started belongs to a previous process that stopped
            // before finishing it: report it, never run it again.
            DateTimeOffset now = this.clock.GetUtcNow();
            entries.AddRange(document.Entries.Select(entry => entry.Status == Started
                ? entry with
                {
                    Status = ManagementCommandResults.Failed,
                    Code = ManagementCommandResults.Interrupted,
                    CompletedAt = now
                }
                : entry));
            lastCanary = document.LastCanary;
            lastReloadAt = document.LastReloadAt;
            Available = true;
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            Available = false;
        }
    }

    public bool Available { get; }

    public CanaryReport? LastCanary
    {
        get
        {
            lock (gate)
            {
                return lastCanary;
            }
        }
    }

    /// <summary>Records a verified command before it runs. Persisted before returning Accepted.</summary>
    public CommandAdmission Admit(VerifiedManagementCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        lock (gate)
        {
            if (!Available)
            {
                AddRejection(command.CommandId, ManagementCommandResults.LedgerUnavailable);
                return CommandAdmission.Rejected;
            }

            CommandLedgerEntry? known = entries.Find(entry => entry.CommandId == command.CommandId);
            if (known is not null && known.Nonce == command.Nonce)
            {
                return CommandAdmission.Duplicate;
            }

            if (known is not null || entries.Exists(entry => entry.Nonce == command.Nonce))
            {
                AddRejection(command.CommandId, ManagementCommandResults.Replayed);
                return CommandAdmission.Rejected;
            }

            Prune();
            if (entries.Count >= MaximumEntries)
            {
                AddRejection(command.CommandId, ManagementCommandResults.LedgerFull);
                return CommandAdmission.Rejected;
            }

            entries.Add(new CommandLedgerEntry(
                command.CommandId, command.Nonce, command.Command, command.ExpiresAt, Started, null, null, false));
            try
            {
                Save();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Not durably recorded, so it must not run: a restart could run it again.
                entries.RemoveAt(entries.Count - 1);
                AddRejection(command.CommandId, ManagementCommandResults.LedgerUnavailable);
                return CommandAdmission.Rejected;
            }

            return CommandAdmission.Accepted;
        }
    }

    /// <summary>A command that was refused before admission (never executed).</summary>
    public void Reject(string? commandId, string code)
    {
        lock (gate)
        {
            AddRejection(commandId, code);
        }
    }

    public void Complete(string commandId, string status, string code)
    {
        lock (gate)
        {
            int index = entries.FindIndex(entry => entry.CommandId == commandId);
            if (index < 0)
            {
                return;
            }

            entries[index] = entries[index] with { Status = status, Code = code, CompletedAt = clock.GetUtcNow() };
            Save();
        }
    }

    public void RecordCanary(CanaryReport report)
    {
        lock (gate)
        {
            lastCanary = report;
            Save();
        }
    }

    /// <summary>True (and recorded) when no reload ran within <see cref="ReloadInterval"/>.</summary>
    public bool TryBeginReload()
    {
        lock (gate)
        {
            DateTimeOffset now = clock.GetUtcNow();
            if (lastReloadAt is { } last && now - last < ReloadInterval && now >= last)
            {
                return false;
            }

            lastReloadAt = now;
            Save();
            return true;
        }
    }

    /// <summary>Finished, unacknowledged results (oldest first), then pending rejections.</summary>
    public IReadOnlyList<CommandResultReport> PendingResults()
    {
        lock (gate)
        {
            return
            [
                .. entries
                    .Where(entry => !entry.Acknowledged && entry.Status != Started)
                    .Select(entry => new CommandResultReport(
                        entry.CommandId, entry.Status, entry.Code ?? entry.Status, entry.CompletedAt ?? clock.GetUtcNow()))
                    .Concat(rejections)
                    .Take(MaximumReportedResults)
            ];
        }
    }

    /// <summary>
    /// Management acknowledged these results. Rejections without a readable command id
    /// can never be acknowledged, so they are dropped once <paramref name="reported"/>.
    /// </summary>
    public void Acknowledge(IReadOnlyCollection<string> commandIds, IReadOnlyCollection<CommandResultReport> reported)
    {
        lock (gate)
        {
            HashSet<string> acknowledged = new(commandIds, StringComparer.Ordinal);
            rejections.RemoveAll(result => result.CommandId is null
                ? reported.Contains(result)
                : acknowledged.Contains(result.CommandId));
            bool changed = false;
            for (int index = 0; index < entries.Count; index++)
            {
                CommandLedgerEntry entry = entries[index];
                if (!entry.Acknowledged && entry.Status != Started && acknowledged.Contains(entry.CommandId))
                {
                    entries[index] = entry with { Acknowledged = true };
                    changed = true;
                }
            }

            if (changed)
            {
                Prune();
                Save();
            }
        }
    }

    private void AddRejection(string? commandId, string code)
    {
        if (commandId is not null && rejections.Exists(result => result.CommandId == commandId))
        {
            return;
        }

        if (rejections.Count >= MaximumPendingRejections)
        {
            rejections.RemoveAt(0);
        }

        rejections.Add(new CommandResultReport(commandId, ManagementCommandResults.Rejected, code, clock.GetUtcNow()));
    }

    /// <summary>
    /// Drops acknowledged entries whose command expired (a later replay fails the expiry
    /// check) and unacknowledged results long past expiry.
    /// </summary>
    private void Prune()
    {
        DateTimeOffset now = clock.GetUtcNow();
        entries.RemoveAll(entry => entry.Status != Started
            && ((entry.Acknowledged && entry.ExpiresAt <= now)
                || entry.ExpiresAt + UnacknowledgedRetention <= now));
    }

    private void Save()
    {
        ManagedPrivacyProfileCache.WriteAtomically(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                new CommandLedgerDocument(1, [.. entries], lastCanary, lastReloadAt),
                CollectorJsonContext.Default.CommandLedgerDocument));
    }
}

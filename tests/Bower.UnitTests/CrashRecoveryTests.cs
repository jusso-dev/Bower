using Bower.Abstractions;
using Bower.Collector;
using Bower.Persistence;

namespace Bower.UnitTests;

/// <summary>#138: run marker, unclean-shutdown ledger check and temporary-file sweep.</summary>
public sealed class CrashRecoveryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 9, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Marker_ReportsAnUncleanPreviousRunOnlyWhenItWasLeftBehind()
    {
        using TemporaryDirectory directory = new();
        string marker = CrashRecovery.MarkerPath(Path.Combine(directory.Path, "queue.db"));

        Assert.Null(CrashRecovery.BeginRun(marker, Now));
        CrashRecovery.EndRun(marker);
        Assert.False(File.Exists(marker));
        Assert.Null(CrashRecovery.BeginRun(marker, Now.AddMinutes(1)));

        // No EndRun: the process was killed.
        Assert.Equal(Now.AddMinutes(1), CrashRecovery.BeginRun(marker, Now.AddMinutes(2)));
        File.WriteAllText(marker, "garbage");
        Assert.Equal(DateTimeOffset.MinValue, CrashRecovery.BeginRun(marker, Now.AddMinutes(3)));
    }

    [Fact]
    public void Sweep_RemovesOnlyOldAtomicWriteTemporariesInTheGivenDirectories()
    {
        using TemporaryDirectory directory = new();
        string state = directory.Path;
        string nested = Directory.CreateDirectory(Path.Combine(state, "nested")).FullName;
        string guid = Guid.NewGuid().ToString("N");
        string old = Write(state, $".collector-id.{guid}.tmp", Now.AddHours(-2));
        string fresh = Write(state, $".credential.json.{Guid.NewGuid():N}.tmp", Now.AddMinutes(-5));
        string queueWal = Write(state, "queue.db-wal", Now.AddDays(-3));
        string spool = Write(state, "bower-000001.tmp", Now.AddDays(-3));
        string userFile = Write(state, ".notes.tmp", Now.AddDays(-3));
        string deeper = Write(nested, $".x.{Guid.NewGuid():N}.tmp", Now.AddDays(-3));

        int removed = CrashRecovery.SweepTemporaryFiles([state, state, Path.Combine(state, "missing")], Now);

        Assert.Equal(1, removed);
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(fresh));
        Assert.True(File.Exists(queueWal));
        Assert.True(File.Exists(spool));
        Assert.True(File.Exists(userFile));
        Assert.True(File.Exists(deeper));
    }

    [Fact]
    public async Task Recover_VerifiesTheLedgerOnlyAfterAnUncleanShutdown()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, TimeProvider.System);
        await store.InitializeAsync(ct);

        CrashRecoveryStatus clean = await CrashRecovery.RecoverAsync(store, null, 2, Now, ct);
        CrashRecoveryStatus unclean = await CrashRecovery.RecoverAsync(store, Now.AddHours(-1), 0, Now, ct);
        CrashRecoveryStatus unknownStart = await CrashRecovery.RecoverAsync(store, DateTimeOffset.MinValue, 0, Now, ct);

        Assert.False(clean.UncleanShutdown);
        Assert.Null(clean.LedgerIntact);
        Assert.Equal(2, clean.TemporaryFilesRemoved);
        Assert.True(unclean.UncleanShutdown);
        Assert.True(unclean.LedgerIntact);
        Assert.Equal(0, unclean.LedgerIssues);
        Assert.Equal(Now.AddHours(-1), unclean.PreviousStartedAt);
        Assert.Null(unknownStart.PreviousStartedAt);
    }

    [Fact]
    public async Task Recover_ReportsABrokenLedger()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        CrashRecoveryStatus status = await CrashRecovery.RecoverAsync(
            _ => Task.FromResult(new LedgerVerification(false, 3, 3, "hash", [new LedgerIssue(2, "event-2", "hash-mismatch", "detail")])),
            Now.AddHours(-1), 0, Now, ct);

        Assert.False(status.LedgerIntact);
        Assert.Equal(1, status.LedgerIssues);
    }

    private static string Write(string directory, string name, DateTimeOffset modified)
    {
        string path = Path.Combine(directory, name);
        File.WriteAllText(path, "x");
        File.SetLastWriteTimeUtc(path, modified.UtcDateTime);
        return path;
    }
}

using Bower.Management.Api;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class PrivacyProfileStoreTests
{
    [Fact]
    public async Task Migration_UpgradesAnOldSchemaDatabaseAndSurvivesRestart()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "management.db");
        // The original collectors/approvals/audit schema, before any additive migration.
        await using (SqliteConnection legacy = new($"Data Source={path};Pooling=False"))
        {
            await legacy.OpenAsync(ct);
            await using SqliteCommand create = legacy.CreateCommand();
            create.CommandText =
                """
                CREATE TABLE collectors (
                    id TEXT PRIMARY KEY, machine_name TEXT NOT NULL, environment TEXT NOT NULL,
                    version TEXT NOT NULL, status TEXT NOT NULL, principal_object_id TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
                    configuration_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
                    queue_depth INTEGER NOT NULL DEFAULT 0, delivery_status TEXT NOT NULL DEFAULT 'unknown');
                CREATE TABLE management_audit (
                    id TEXT PRIMARY KEY, action TEXT NOT NULL, target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL, actor_object_id TEXT NOT NULL, actor_name TEXT NOT NULL,
                    occurred_at TEXT NOT NULL);
                INSERT INTO collectors VALUES (
                    'legacy-01', 'legacy-01', 'prod', '0.0.9', 'Active', 'principal',
                    '2026-01-01T00:00:00.0000000+00:00', '2026-01-01T00:00:00.0000000+00:00',
                    'sha256:c', 'sha256:p', 4, 'healthy');
                """;
            await create.ExecuteNonQueryAsync(ct);
        }

        ManagementStore store = new(path);
        await store.InitializeAsync(ct);
        CollectorRecord? upgraded = await store.GetAsync("legacy-01", ct);
        PrivacyProfileVersionDetail version = await ApprovedVersionAsync(store, ct);
        await store.AssignPrivacyProfileAsync("legacy-01", version.Id, "Roll out", "admin", "Admin", TestEvents.Now, ct);

        // Restart: initialisation is idempotent and keeps the migrated state.
        ManagementStore restarted = new(path);
        await restarted.InitializeAsync(ct);
        CollectorRecord? afterRestart = await restarted.GetAsync("legacy-01", ct);
        CollectorRecord? reported = await restarted.HeartbeatAsync(
            "legacy-01",
            PrivacyProfileApiTests.Heartbeat(version.ContentHash),
            "principal",
            TestEvents.Now.AddMinutes(1),
            ct);

        Assert.NotNull(upgraded);
        Assert.Null(upgraded.DesiredPrivacyProfile);
        Assert.Null(upgraded.ReportedPrivacyProfileHash);
        Assert.Null(upgraded.PrivacyProfileInSync);
        Assert.Equal(4, upgraded.QueueDepth);
        Assert.Equal(version.Id, afterRestart!.DesiredPrivacyProfile!.VersionId);
        Assert.False(afterRestart.PrivacyProfileInSync);
        Assert.True(reported!.PrivacyProfileInSync);
        Assert.Single(await restarted.ListPrivacyProfileVersionsAsync(ct));
        Assert.Single(await restarted.ListPrivacyProfileAssignmentsAsync(ct));
    }

    [Fact]
    public async Task Migration_FailsLoudlyOnACorruptDatabase()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "management.db");
        await File.WriteAllBytesAsync(path, [.. Enumerable.Repeat((byte)0x5a, 8192)], ct);
        ManagementStore store = new(path);

        await Assert.ThrowsAsync<SqliteException>(() => store.InitializeAsync(ct));
        Assert.Equal(8192, new FileInfo(path).Length);
    }

    [Theory]
    [InlineData("privacy-profile.submitted")]
    [InlineData("privacy-profile.approved")]
    [InlineData("privacy-profile.rejected")]
    [InlineData("collector.privacy-profile-assigned")]
    [InlineData("collector.privacy-profile-cleared")]
    public async Task StateChange_RollsBackWhenItsAuditRowCannotBeWritten(string action)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        string path = Path.Combine(root.Path, "management.db");
        ManagementStore store = new(path);
        await store.InitializeAsync(ct);
        await store.RegisterAsync(
            new CollectorRegistration("edge-01", "edge-01", "test", "0.1.0", "c", "p", [], []),
            "principal", TestEvents.Now, ct);
        PrivacyProfileVersionDetail approved = await ApprovedVersionAsync(store, ct);
        if (action == "collector.privacy-profile-cleared")
        {
            await store.AssignPrivacyProfileAsync("edge-01", approved.Id, "Roll out", "admin", "Admin", TestEvents.Now, ct);
        }

        PrivacyProfileVersionDetail pending = await store.SubmitPrivacyProfileVersionAsync(
            PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("2.0.0")).Candidate,
            "Pending change", "alice", "Alice", TestEvents.Now, ct);
        CollectorRecord? before = await store.GetAsync("edge-01", ct);
        int assignmentsBefore = (await store.ListPrivacyProfileAssignmentsAsync(ct)).Count;
        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(ct);
            await using SqliteCommand trigger = connection.CreateCommand();
            trigger.CommandText =
                $"""
                CREATE TRIGGER fail_audit BEFORE INSERT ON management_audit
                WHEN NEW.action = '{action}'
                BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;
                """;
            await trigger.ExecuteNonQueryAsync(ct);
        }

        Task change = action switch
        {
            "privacy-profile.submitted" => store.SubmitPrivacyProfileVersionAsync(
                PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("3.0.0")).Candidate,
                "New", "failing-actor", "Failing", TestEvents.Now, ct),
            "privacy-profile.approved" => store.ReviewPrivacyProfileVersionAsync(
                pending.Id, true, "ok", "failing-actor", "Failing", TestEvents.Now, ct),
            "privacy-profile.rejected" => store.ReviewPrivacyProfileVersionAsync(
                pending.Id, false, "no", "failing-actor", "Failing", TestEvents.Now, ct),
            "collector.privacy-profile-assigned" => store.AssignPrivacyProfileAsync(
                "edge-01", approved.Id, "Roll out", "failing-actor", "Failing", TestEvents.Now, ct),
            _ => store.AssignPrivacyProfileAsync("edge-01", null, "Clear", "failing-actor", "Failing", TestEvents.Now, ct)
        };

        await Assert.ThrowsAsync<SqliteException>(() => change);
        Assert.Equal(2, (await store.ListPrivacyProfileVersionsAsync(ct)).Count);
        Assert.Equal(
            PrivacyProfileVersionStatus.PendingReview,
            (await store.GetPrivacyProfileVersionAsync(pending.Id, ct))!.Status);
        Assert.Equal(before!.DesiredPrivacyProfile, (await store.GetAsync("edge-01", ct))!.DesiredPrivacyProfile);
        Assert.Equal(assignmentsBefore, (await store.ListPrivacyProfileAssignmentsAsync(ct)).Count);
        Assert.DoesNotContain(await store.ListAuditAsync(ct), item => item.Action == action && item.ActorObjectId == "failing-actor");
    }

    [Fact]
    public async Task RejectedOperations_WriteNoStateOrAudit()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory root = new();
        ManagementStore store = new(Path.Combine(root.Path, "management.db"));
        await store.InitializeAsync(ct);
        PrivacyProfileVersionDetail pending = await store.SubmitPrivacyProfileVersionAsync(
            PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("1.0.0")).Candidate,
            "Initial", "alice", "Alice", TestEvents.Now, ct);
        int auditBefore = (await store.ListAuditAsync(ct)).Count;

        await Assert.ThrowsAsync<PrivacyProfileConflictException>(() => store.ReviewPrivacyProfileVersionAsync(
            pending.Id, true, "self", "alice", "Alice", TestEvents.Now, ct));
        await Assert.ThrowsAsync<PrivacyProfileValidationException>(() => store.SubmitPrivacyProfileVersionAsync(
            PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("0.9.9")).Candidate,
            "Older", "alice", "Alice", TestEvents.Now, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => store.SubmitPrivacyProfileVersionAsync(
            PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("1.0.1")).Candidate,
            "", "alice", "Alice", TestEvents.Now, ct));

        Assert.Equal(PrivacyProfileVersionStatus.PendingReview, (await store.GetPrivacyProfileVersionAsync(pending.Id, ct))!.Status);
        Assert.Single(await store.ListPrivacyProfileVersionsAsync(ct));
        Assert.Equal(auditBefore, (await store.ListAuditAsync(ct)).Count);
    }

    [Theory]
    [InlineData("1.0.0", "0.9.9", true)]
    [InlineData("1.10.0", "1.9.0", true)]
    [InlineData("2.0.0", "1.99.99", true)]
    [InlineData("1.0.10", "1.0.9", true)]
    [InlineData("1.0.0", "1.0.0", false)]
    [InlineData("1.0.0", "1.0.1", false)]
    [InlineData("10000000000000000000000.0.0", "9999999999999999999999.0.0", true)]
    public void SemanticVersions_CompareNumerically(string next, string latest, bool greater)
    {
        Assert.Equal(greater, PrivacyProfileInspector.RequireGreater(next, latest) is null);
    }

    [Theory]
    [InlineData("1.0")]
    [InlineData("1.0.0.0")]
    [InlineData("01.0.0")]
    [InlineData("1.0.0-beta")]
    [InlineData("v1.0.0")]
    [InlineData("1..0")]
    [InlineData("-1.0.0")]
    [InlineData("1.0.0 ")]
    public void SemanticVersions_RejectNonCanonicalForms(string version)
    {
        Assert.False(ProfileSemanticVersion.TryParse(version, out _));
    }

    private static async Task<PrivacyProfileVersionDetail> ApprovedVersionAsync(ManagementStore store, CancellationToken ct)
    {
        PrivacyProfileVersionDetail submitted = await store.SubmitPrivacyProfileVersionAsync(
            PrivacyProfileInspector.Load(PrivacyProfileApiTests.Profile("1.0.0")).Candidate,
            "Initial", "alice", "Alice", TestEvents.Now, ct);
        return (await store.ReviewPrivacyProfileVersionAsync(
            submitted.Id, true, "Reviewed", "bob", "Bob", TestEvents.Now, ct))!;
    }
}

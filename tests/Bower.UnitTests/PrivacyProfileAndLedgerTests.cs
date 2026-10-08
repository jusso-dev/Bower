using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Persistence;
using Bower.Redaction.Privacy;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class PrivacyProfileAndLedgerTests
{
    private const string PseudonymProfile =
        """
        apiVersion: bower.security/v1
        kind: PrivacyProfile
        metadata:
          id: test
          version: 1.0.0
        fields:
          - path: actor.username
            action: hmac
          - path: request.userAgent
            action: truncate
            maxLength: 10
        maximumFieldLength: 1024
        """;

    [Fact]
    public void Hmac_PseudonymisesDeterministicallyWithKeyId()
    {
        PrivacyEngine engine = new(PrivacyProfileLoader.Load(PseudonymProfile, Key(1), "k2026").Policy);
        string json = """{"actor":{"username":"alice"},"request":{"userAgent":"Mozilla/5.0 something long"}}""";

        string first = engine.RedactJson(json).RedactedJson!;
        string second = engine.RedactJson(json).RedactedJson!;
        JsonNode node = JsonNode.Parse(first)!;

        Assert.Equal(first, second);
        Assert.StartsWith("hmac-sha256:k2026:", node["actor"]!["username"]!.GetValue<string>(), StringComparison.Ordinal);
        Assert.DoesNotContain("alice", first, StringComparison.Ordinal);
        Assert.Equal("Mozilla/5.", node["request"]!["userAgent"]!.GetValue<string>());
    }

    [Fact]
    public void Hmac_DiffersAcrossKeysSoPseudonymsAreTenantScoped()
    {
        string json = """{"actor":{"username":"alice"}}""";

        string a = new PrivacyEngine(PrivacyProfileLoader.Load(PseudonymProfile, Key(1)).Policy).RedactJson(json).RedactedJson!;
        string b = new PrivacyEngine(PrivacyProfileLoader.Load(PseudonymProfile, Key(2)).Policy).RedactJson(json).RedactedJson!;

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Profile_FailsClosedWithoutHmacKey()
    {
        Assert.Throws<InvalidOperationException>(() => PrivacyProfileLoader.Load(PseudonymProfile));
    }

    [Theory]
    [InlineData("detectors:\n  not.a.detector: mask")]
    [InlineData("fields:\n  - path: actor.username\n    action: obliterate")]
    [InlineData("unexpectedKey: true")]
    [InlineData("maximumFieldLength: 10")]
    public void Profile_RejectsUnknownOrUnsafeSettings(string extra)
    {
        string yaml = "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1.0.0\n" + extra + "\n";

        Assert.Throws<InvalidDataException>(() => PrivacyProfileLoader.Load(yaml));
    }

    [Fact]
    public void MaximumFieldLength_TruncatesEveryLongString()
    {
        PrivacyEngine engine = new(new PrivacyPolicy { MaximumFieldLength = 300 });

        PrivacyScanResult result = engine.RedactJson($$"""{"a":"{{new string('y', 1_000)}}","list":["{{new string('z', 500)}}"]}""");
        JsonNode node = JsonNode.Parse(result.RedactedJson!)!;

        Assert.Equal(300, node["a"]!.GetValue<string>().Length);
        Assert.Equal(300, node["list"]![0]!.GetValue<string>().Length);
        Assert.Contains(result.Findings, finding => finding.DetectorId == DetectorIds.FieldLength);
    }

    [Fact]
    public async Task Ledger_IsIntactThroughNormalLifecycleIncludingPurge()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        for (int index = 0; index < 5; index++)
        {
            await store.EnqueueAsync(new QueuedEvent($"e{index}", $"f{index}", $$"""{"n":{{index}}}""", clock.UtcNow), cancellationToken);
        }

        await store.LeaseAsync(3, TimeSpan.FromMinutes(1), cancellationToken);
        foreach (string id in new[] { "e0", "e1", "e2" })
        {
            await store.MarkDeliveredAsync(id, "ack", cancellationToken);
        }

        clock.Advance(TimeSpan.FromDays(10));
        int purged = await store.PurgeDeliveredAsync(clock.UtcNow.AddDays(-7), 100, cancellationToken);
        LedgerVerification verification = await store.VerifyLedgerAsync(cancellationToken);
        LedgerHead head = await store.GetLedgerHeadAsync(cancellationToken);

        Assert.Equal(3, purged);
        Assert.True(verification.Intact, string.Join("; ", verification.Issues.Select(issue => issue.Code)));
        Assert.Equal(5, head.Sequence);
        Assert.Equal(2, verification.Entries);
    }

    [Fact]
    public async Task Ledger_DetectsModifiedPayloadDeletedRowAndInjectedEvent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * 1024 * 1024, new FakeClock(TestEvents.Now));
        await store.InitializeAsync(cancellationToken);
        foreach (string id in new[] { "a", "b", "c" })
        {
            await store.EnqueueAsync(new QueuedEvent(id, id, $$"""{"id":"{{id}}"}""", TestEvents.Now), cancellationToken);
        }

        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand tamper = connection.CreateCommand();
            tamper.CommandText =
                """
                UPDATE queue_events SET payload = '{"id":"a","attacker":true}' WHERE event_id = 'a';
                DELETE FROM queue_events WHERE event_id = 'b';
                INSERT INTO queue_events (event_id, fingerprint, payload, payload_bytes, received_at, state)
                VALUES ('forged', 'forged', '{}', 2, '2026-01-01T00:00:00Z', 0);
                """;
            await tamper.ExecuteNonQueryAsync(cancellationToken);
        }

        LedgerVerification verification = await store.VerifyLedgerAsync(cancellationToken);
        string[] codes = verification.Issues.Select(issue => issue.Code).ToArray();

        Assert.False(verification.Intact);
        Assert.Contains("payload-modified", codes);
        Assert.Contains("event-missing", codes);
        Assert.Contains("unledgered-event", codes);
    }

    [Fact]
    public async Task Ledger_DetectsRewrittenChain()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "queue.db");
        SqliteEventStore store = new(path, 10 * 1024 * 1024, new FakeClock(TestEvents.Now));
        await store.InitializeAsync(cancellationToken);
        await store.EnqueueAsync(new QueuedEvent("a", "a", "{}", TestEvents.Now), cancellationToken);
        await store.EnqueueAsync(new QueuedEvent("b", "b", "{}", TestEvents.Now), cancellationToken);

        await using (SqliteConnection connection = new($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand tamper = connection.CreateCommand();
            tamper.CommandText = "UPDATE queue_ledger SET received_at = '2020-01-01T00:00:00Z' WHERE sequence = 1;";
            await tamper.ExecuteNonQueryAsync(cancellationToken);
        }

        Assert.Contains((await store.VerifyLedgerAsync(cancellationToken)).Issues, issue => issue.Code == "chain-broken");
    }

    [Fact]
    public async Task DeadLetters_AreListedWithoutPayloadsAndReplayedByCode()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        foreach (string id in new[] { "x", "y" })
        {
            await store.EnqueueAsync(new QueuedEvent(id, id, """{"secret-free":true}""", clock.UtcNow), cancellationToken);
        }

        await store.LeaseAsync(2, TimeSpan.FromMinutes(1), cancellationToken);
        await store.MarkDeadLetteredAsync("x", "azure-http-400", cancellationToken);
        await store.MarkDeadLetteredAsync("y", "preflight-field-too-large", cancellationToken);

        IReadOnlyList<DeadLetterRecord> listed = await store.ListDeadLetteredAsync(10, cancellationToken);
        int none = await store.ReplayDeadLetteredAsync(null, null, 10, cancellationToken);
        int replayed = await store.ReplayDeadLetteredAsync("azure-http-", null, 10, cancellationToken);
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);
        IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken);

        Assert.Equal(2, listed.Count);
        Assert.Equal(0, none);
        Assert.Equal(1, replayed);
        Assert.Equal(1, snapshot.DeadLettered);
        QueuedEvent again = Assert.Single(leased);
        Assert.Equal("x", again.EventId);
        Assert.Equal(1, again.DeliveryAttempts);
    }

    private static byte[] Key(byte seed) => Enumerable.Repeat(seed, 32).ToArray();
}

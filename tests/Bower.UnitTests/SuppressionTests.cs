using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;

namespace Bower.UnitTests;

public sealed class SuppressionTests
{
    private static readonly CollectorIdentity Identity =
        new("collector-1", "0.1.0", "test", "sha256:configuration");

    internal const string SuppressingPolicy =
        """
        apiVersion: bower.security/v1
        kind: TelemetryPolicy
        metadata:
          id: BWR-POL-AUTH-SUPPRESSED
          name: Authentication failures, suppressed
          version: 1.0.0
          owner: Security Operations
        match:
          eventCategories:
            - authentication
          eventTypes:
            - authentication_failure
        requirements:
          requiredFields:
            - timeGenerated
            - eventType
          atLeastOne:
            - actor.username
        decision:
          action: accept
          minimumValueScore: 50
          neverSample: false
        suppression:
          keyFields:
            - actor.username
            - source.ipAddress
          windowSeconds: 60
          allowPerWindow: 2
        """;

    internal const string SummaryPolicy =
        """
        apiVersion: bower.security/v1
        kind: TelemetryPolicy
        metadata:
          id: BWR-POL-SUPPRESSION-SUMMARY
          name: Suppression summaries
          version: 1.0.0
          owner: Security Operations
        match:
          eventTypes:
            - telemetry_aggregation_summary
        requirements:
          requiredFields:
            - timeGenerated
            - eventType
            - application.name
            - target.id
        decision:
          action: accept
          minimumValueScore: 50
          neverSample: true
        """;

    [Fact]
    public async Task Process_AdmitsAllowanceThenCountsDurablyAndSummarisesOnce()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        IReadOnlyList<LoadedPolicy> policies = LoadPolicies(directory, SuppressingPolicy, SummaryPolicy);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        PipelineTelemetry telemetry = new(clock);
        SecurityEventProcessor processor = CreateProcessor(store, clock, policies, telemetry);

        List<ProcessingResult> results = [];
        for (int index = 1; index <= 3; index++)
        {
            results.Add(await processor.ProcessAsync(Candidate(clock, index), Identity, cancellationToken));
        }

        // Restart mid-window: counts continue from the queue file.
        SqliteEventStore restarted = await CreateStoreAsync(directory, clock, cancellationToken);
        processor = CreateProcessor(restarted, clock, policies, telemetry);
        for (int index = 4; index <= 5; index++)
        {
            results.Add(await processor.ProcessAsync(Candidate(clock, index), Identity, cancellationToken));
        }

        results.Add(await processor.ProcessAsync(Candidate(clock, 1), Identity, cancellationToken));

        Assert.Equal([true, true, false, false, false, false], results.Select(item => item.Queued));
        Assert.Equal([false, false, true, true, true, false], results.Select(item => item.Suppressed));
        Assert.True(results[^1].Duplicate);
        Assert.Contains(results[2].Reasons, reason => reason.StartsWith("Suppressed:", StringComparison.Ordinal));
        Assert.Equal(3, telemetry.Snapshot().Suppressed);

        Assert.Equal(0, await processor.CloseSuppressionWindowsAsync(Identity, cancellationToken));
        clock.Advance(TimeSpan.FromMinutes(2));
        int summaries = await processor.CloseSuppressionWindowsAsync(Identity, cancellationToken);
        int repeated = await processor.CloseSuppressionWindowsAsync(Identity, cancellationToken);
        IReadOnlyList<QueuedEvent> queued = await restarted.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken);
        LedgerVerification ledger = await restarted.VerifyLedgerAsync(cancellationToken);

        Assert.Equal(1, summaries);
        Assert.Equal(0, repeated);
        Assert.Equal(3, queued.Count);
        Assert.True(ledger.Intact);
        using JsonDocument summary = JsonDocument.Parse(queued.Single(item => item.EventId.StartsWith("suppression-", StringComparison.Ordinal)).Payload);
        JsonElement root = summary.RootElement;
        Assert.Equal(SecurityEventTypes.TelemetryAggregationSummary, root.GetProperty("eventType").GetString());
        Assert.Equal(Suppression.SummaryAction, root.GetProperty("eventAction").GetString());
        Assert.Equal("aggregate", root.GetProperty("security").GetProperty("decision").GetString());
        Assert.Equal("BWR-POL-SUPPRESSION-SUMMARY", root.GetProperty("security").GetProperty("policyId").GetString());
        Assert.Equal("2026-07-26T02:15:00+00:00", root.GetProperty("timeGenerated").GetString());
        JsonElement attributes = root.GetProperty("attributes");
        Assert.Equal(3, attributes.GetProperty("suppressedCount").GetInt64());
        Assert.Equal(2, attributes.GetProperty("admittedCount").GetInt64());
        Assert.Equal("2026-07-26T02:14:00Z", attributes.GetProperty("windowStart").GetString());
        Assert.Equal("test-user", attributes.GetProperty("suppressionKey").GetProperty("actor.username").GetString());
        Assert.Equal("192.0.2.10", attributes.GetProperty("suppressionKey").GetProperty("source.ipAddress").GetString());
    }

    [Fact]
    public async Task Process_KeepsSeparateAllowancePerKeyAndDropsQuietWindows()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        IReadOnlyList<LoadedPolicy> policies = LoadPolicies(directory, SuppressingPolicy, SummaryPolicy);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        SecurityEventProcessor processor = CreateProcessor(store, clock, policies, null);

        for (int index = 1; index <= 3; index++)
        {
            await processor.ProcessAsync(Candidate(clock, index), Identity, cancellationToken);
        }

        ProcessingResult other = await processor.ProcessAsync(
            Candidate(clock, 10, username: "other-user"), Identity, cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(2));
        int summaries = await processor.CloseSuppressionWindowsAsync(Identity, cancellationToken);
        ProcessingResult nextWindow = await processor.ProcessAsync(Candidate(clock, 11), Identity, cancellationToken);

        Assert.True(other.Queued);
        Assert.Equal(1, summaries);
        Assert.True(nextWindow.Queued);
    }

    [Fact]
    public async Task Close_KeepsWindowsWhenSummaryIsNotAccepted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        IReadOnlyList<LoadedPolicy> policies = LoadPolicies(directory, SuppressingPolicy);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        SecurityEventProcessor processor = CreateProcessor(store, clock, policies, null);
        for (int index = 1; index <= 3; index++)
        {
            await processor.ProcessAsync(Candidate(clock, index), Identity, cancellationToken);
        }

        clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.ThrowsAsync<SuppressionSummaryRejectedException>(
            () => processor.CloseSuppressionWindowsAsync(Identity, cancellationToken));

        // The same windows close once a summary policy is present.
        SecurityEventProcessor fixedProcessor = CreateProcessor(
            store, clock, LoadPolicies(directory, SuppressingPolicy, SummaryPolicy), null);
        Assert.Equal(1, await fixedProcessor.CloseSuppressionWindowsAsync(Identity, cancellationToken));
    }

    [Fact]
    public async Task Close_SummarisesAWindowRecreatedAfterTheClockStepsBack()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        IReadOnlyList<LoadedPolicy> policies = LoadPolicies(directory, SuppressingPolicy, SummaryPolicy);
        SqliteEventStore store = await CreateStoreAsync(directory, clock, cancellationToken);
        SecurityEventProcessor processor = CreateProcessor(store, clock, policies, null);
        for (int index = 1; index <= 3; index++)
        {
            await processor.ProcessAsync(Candidate(clock, index), Identity, cancellationToken);
        }

        clock.Advance(TimeSpan.FromMinutes(2));
        int first = await processor.CloseSuppressionWindowsAsync(Identity, cancellationToken);
        // NTP steps the clock back into the closed window; new events recreate it.
        clock.Advance(TimeSpan.FromMinutes(-2) + TimeSpan.FromSeconds(5));
        for (int index = 4; index <= 7; index++)
        {
            await processor.ProcessAsync(Candidate(clock, index), Identity, cancellationToken);
        }

        clock.Advance(TimeSpan.FromMinutes(2));
        int second = await processor.CloseSuppressionWindowsAsync(Identity, cancellationToken);

        Assert.Equal((1, 1), (first, second));
    }

    [Fact]
    public void Bundle_RequiresSummaryPolicyWhenAnyPolicySuppresses()
    {
        using TemporaryDirectory directory = new();
        string policies = Path.Combine(directory.Path, "policies");
        Directory.CreateDirectory(policies);
        File.WriteAllText(Path.Combine(policies, "suppressed.yaml"), SuppressingPolicy);

        InvalidDataException failure = Assert.Throws<InvalidDataException>(
            () => PolicyBundle.Load(new PolicyBundleSources { PolicyDirectory = policies }));
        File.WriteAllText(Path.Combine(policies, "summary.yaml"), SummaryPolicy);
        PolicyBundle bundle = PolicyBundle.Load(new PolicyBundleSources { PolicyDirectory = policies });

        Assert.Equal(
            "Policies define suppression but none accepts 'telemetry_aggregation_summary'.",
            failure.Message);
        Assert.Equal(2, bundle.Policies.Count);
    }

    [Theory]
    [InlineData("neverSample: false", "neverSample: true", "A neverSample policy cannot define suppression.")]
    [InlineData("action: accept", "action: reject", "Suppression applies only to accept or redact-and-accept policies.")]
    [InlineData("    - source.ipAddress\n  windowSeconds", "    - attributes.password\n  windowSeconds", "Policy suppression keyFields must list 1–5 distinct string field paths.")]
    [InlineData("    - source.ipAddress\n  windowSeconds", "    - actor.username\n  windowSeconds", "Policy suppression keyFields must list 1–5 distinct string field paths.")]
    [InlineData("windowSeconds: 60", "windowSeconds: 0", "Policy suppression windowSeconds must be between 1 and 86400.")]
    [InlineData("allowPerWindow: 2", "allowPerWindow: 100001", "Policy suppression allowPerWindow must be between 1 and 100000.")]
    public void Loader_RejectsInvalidSuppression(string original, string replacement, string message)
    {
        string yaml = SuppressingPolicy.Replace(original, replacement, StringComparison.Ordinal);
        Assert.NotEqual(SuppressingPolicy, yaml);

        InvalidDataException failure = Assert.Throws<InvalidDataException>(
            () => PolicyLoader.LoadYaml(yaml, "suppressed.yaml"));

        Assert.Equal(message, failure.Message);
    }

    [Fact]
    public void Loader_HashIncludesSuppressionOnlyWhenPresent()
    {
        LoadedPolicy suppressed = PolicyLoader.LoadYaml(SuppressingPolicy, "suppressed.yaml");
        string withoutSuppression = SuppressingPolicy[..SuppressingPolicy.IndexOf("suppression:", StringComparison.Ordinal)];
        LoadedPolicy plain = PolicyLoader.LoadYaml(withoutSuppression, "plain.yaml");
        LoadedPolicy otherWindow = PolicyLoader.LoadYaml(
            SuppressingPolicy.Replace("windowSeconds: 60", "windowSeconds: 61", StringComparison.Ordinal),
            "other.yaml");

        Assert.Null(plain.Policy.Suppression);
        Assert.NotEqual(plain.Hash, suppressed.Hash);
        Assert.NotEqual(suppressed.Hash, otherWindow.Hash);
        Assert.Equal(["actor.username", "source.ipAddress"], suppressed.Policy.Suppression!.KeyFields);
    }

    [Fact]
    public void Summary_IdAndFingerprintAreStableForAWindow()
    {
        DateTimeOffset start = new(2026, 7, 26, 2, 14, 0, TimeSpan.Zero);
        SuppressionRequest rule = new(
            "BWR-POL-X", "1.0.0", "sha256:p", "abc", ["source.ipAddress"], ["192.0.2.1"], 60, 2,
            "authentication", "authentication_failure", "App", "prod", null);
        SuppressionWindow window = new(rule, start, start.AddSeconds(60), 2, 5, start.AddSeconds(3), start.AddSeconds(9));

        SecurityEventEnvelope first = Suppression.CreateSummary(window, Identity, start.AddMinutes(2));
        SecurityEventEnvelope retry = Suppression.CreateSummary(window, Identity, start.AddMinutes(9));

        Assert.Equal(first.EventId, retry.EventId);
        Assert.StartsWith("suppression-", first.EventId, StringComparison.Ordinal);
        Assert.Equal(first.EventId.Length, "suppression-".Length + 32);
        Assert.Equal(EventFingerprint.Create(first), EventFingerprint.Create(retry));
    }

    private static string Candidate(FakeClock clock, int index, string username = "test-user") =>
        JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(clock.UtcNow, $"event-{index}", $"source-{index}") with
            {
                Actor = new ActorContext { Username = username }
            },
            BowerJson.Options);

    internal static IReadOnlyList<LoadedPolicy> LoadPolicies(TemporaryDirectory directory, params string[] yaml)
    {
        string path = Path.Combine(directory.Path, $"policies-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        for (int index = 0; index < yaml.Length; index++)
        {
            File.WriteAllText(Path.Combine(path, $"policy-{index}.yaml"), yaml[index]);
        }

        return PolicyLoader.LoadDirectory(path);
    }

    private static SecurityEventProcessor CreateProcessor(
        SqliteEventStore store,
        FakeClock clock,
        IReadOnlyList<LoadedPolicy> policies,
        PipelineTelemetry? telemetry) =>
        new(new JsonEventRedactor(), new DeterministicPolicyEvaluator(policies), store, clock, telemetry);

    private static async Task<SqliteEventStore> CreateStoreAsync(
        TemporaryDirectory directory,
        FakeClock clock,
        CancellationToken cancellationToken)
    {
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        return store;
    }
}

public sealed class PolicyDiffTests
{
    [Fact]
    public async Task Diff_ListsOnlyEventsWhoseDecisionOrPolicyChanges()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string baselineDirectory = Path.Combine(directory.Path, "baseline");
        string candidateDirectory = Path.Combine(directory.Path, "candidate");
        Directory.CreateDirectory(baselineDirectory);
        Directory.CreateDirectory(candidateDirectory);
        string policy = SuppressionTests.SuppressingPolicy[..SuppressionTests.SuppressingPolicy.IndexOf("suppression:", StringComparison.Ordinal)];
        File.WriteAllText(Path.Combine(baselineDirectory, "auth.yaml"), policy);
        File.WriteAllText(
            Path.Combine(candidateDirectory, "auth.yaml"),
            policy.Replace("version: 1.0.0", "version: 1.1.0", StringComparison.Ordinal)
                .Replace("    - timeGenerated\n", "    - timeGenerated\n    - request.traceId\n", StringComparison.Ordinal));
        PolicyBundle baseline = PolicyBundle.Load(new PolicyBundleSources { PolicyDirectory = baselineDirectory });
        PolicyBundle candidate = PolicyBundle.Load(new PolicyBundleSources { PolicyDirectory = candidateDirectory });
        string plain = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(clock.UtcNow), BowerJson.Options);
        string traced = JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(clock.UtcNow, "event-2", "source-2") with
            {
                Request = new RequestContext { CorrelationId = "c", TraceId = "t" }
            },
            BowerJson.Options);
        string unknown = JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(clock.UtcNow, "event-3", "source-3") with { EventType = "page_view" },
            BowerJson.Options);

        Cli.Commands.PolicyDiffOutput same = await Cli.Commands.PolicyCommands.ComputeDiffAsync(
            baseline, baseline, [("plain.json", plain)], clock);
        Cli.Commands.PolicyDiffOutput diff = await Cli.Commands.PolicyCommands.ComputeDiffAsync(
            baseline, candidate, [("plain.json", plain), ("traced.json", traced), ("unknown.json", unknown)], clock);

        Assert.Equal(0, same.Changed);
        Assert.Equal(3, diff.Events);
        Cli.Commands.PolicyDiffChange change = Assert.Single(diff.Changes);
        Assert.Equal("plain.json", change.File);
        Assert.Equal(("accept", "BWR-POL-AUTH-SUPPRESSED"), (change.Baseline.Decision, change.Baseline.PolicyId));
        Assert.Equal(("quarantine", "BWR-POL-AUTH-SUPPRESSED"), (change.Candidate.Decision, change.Candidate.PolicyId));
        Assert.NotEqual(diff.BaselineBundleHash, diff.CandidateBundleHash);
    }

    [Fact]
    public void DiffFiles_FailOnChangeNeverSwallowsAFile()
    {
        Assert.Equal(
            ["a.json", "b.json"],
            Cli.Commands.PolicyCommands.DiffFiles(
                ["--fail-on-change", "a.json", "--baseline", "x", "b.json", "--candidate", "y"]));
    }
}

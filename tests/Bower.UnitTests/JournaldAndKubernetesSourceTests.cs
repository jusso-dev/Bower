using System.Net;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;
using Bower.Source.Journald;
using Bower.Source.Kubernetes;

namespace Bower.UnitTests;

public sealed class JournaldAndKubernetesSourceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void JournaldOptions_DefaultDenyAndRejectWildcards()
    {
        Assert.Throws<ArgumentException>(() => new JournaldSourceOptions
        {
            SubscriptionName = "ssh"
        }.Validate());

        Assert.Throws<ArgumentException>(() => new JournaldSourceOptions
        {
            SubscriptionName = "ssh",
            Units = ["ssh*.service"]
        }.Validate());

        Assert.Throws<ArgumentException>(() => new JournaldSourceOptions
        {
            SubscriptionName = "ssh",
            Identifiers = ["*"]
        }.Validate());
    }

    [Fact]
    public async Task JournaldSource_EnforcesAllowList_ResumesDurableCursor_AndParsesWithSignedSshPack()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory temp = new();
        EfSourceCursorStore store = new(Path.Combine(temp.Path, "cursors.db"));
        await store.InitializeAsync(ct);

        long usec = Now.ToUnixTimeMilliseconds() * 1000L;
        JournaldEntry[] stream =
        [
            new("c-1", usec, "cron.service", "CRON", "ignored cron noise"),
            new("c-2", usec + 1000, "sshd.service", "sshd", "Failed password for invalid user alice from 192.0.2.44 port 51234 ssh2"),
            new("c-3", usec + 2000, "sshd.service", "sshd", new string('x', 40_000)), // oversized
            new("c-4", usec + 3000, "sshd.service", "sshd", "Failed publickey for bob from 192.0.2.45 port 51235 ssh2")
        ];

        FakeJournalReader reader = new(stream);
        JournaldSourceOptions options = new()
        {
            SubscriptionName = "ssh-auth",
            Units = ["sshd.service"],
            MaxBatchSize = 10
        };
        JournaldSource source = new(options, reader, store);

        // Simulate backpressure/crash on c-4: accept c-2, reject c-4 so cursor must stop at c-3 (before c-4).
        List<JournaldRecord> received = [];
        JournaldPollResult first = await source.PollOnceAsync((record, _) =>
        {
            if (record.Cursor == "c-4")
            {
                return Task.FromResult(false);
            }

            received.Add(record);
            return Task.FromResult(true);
        }, ct);

        Assert.Equal(4, first.Read);
        Assert.Equal(1, first.Delivered);
        Assert.Equal(1, first.FilteredOut);
        Assert.Equal(1, first.RejectedOversized);
        Assert.True(first.StoppedOnBackpressure);
        Assert.Equal("c-3", first.CommittedCursor);
        Assert.Single(received);
        Assert.Equal("c-2", received[0].Cursor);

        // Parse c-2 through signed packs/linux-journald-ssh -> privacy -> policy!
        LoadedPack sshPack = BuildPack("linux-journald-ssh");
        SecurityEventEnvelope? parsed = PackRuntime.Parse(sshPack.Parsers[0], received[0].RecordJson, Now);
        Assert.NotNull(parsed);
        Assert.Equal("authentication_failure", parsed.EventType);
        Assert.Equal("alice", parsed.Actor!.Username);
        Assert.Equal("192.0.2.44", parsed.Source!.IpAddress);

        // Simulate restart with a fresh JournaldSource reading the same durable SQLite store.
        JournaldSource restarted = new(options, reader, store);
        JournaldPollResult second = await restarted.PollOnceAsync((record, _) =>
        {
            received.Add(record);
            return Task.FromResult(true);
        }, ct);

        Assert.Equal(1, second.Read);
        Assert.Equal(1, second.Delivered);
        Assert.False(second.StoppedOnBackpressure);
        Assert.Equal("c-4", second.CommittedCursor);
        Assert.Equal(2, received.Count);
        Assert.Equal("c-4", received[1].Cursor);

        // Third poll has nothing left -> zero duplicates.
        JournaldPollResult third = await restarted.PollOnceAsync((_, _) => Task.FromResult(true), ct);
        Assert.Equal(0, third.Read);
        Assert.Equal(0, third.Delivered);
    }

    [Fact]
    public void KubernetesOptions_RefuseClusterWideOrWildcardNamespaces()
    {
        Assert.Throws<ArgumentException>(() => new KubernetesLogSourceOptions
        {
            PodLogRoot = "/var/log/pods",
            Namespaces = [],
            LabelSelectors = [new("bower.io/collect", "true")]
        }.Validate());

        Assert.Throws<ArgumentException>(() => new KubernetesLogSourceOptions
        {
            PodLogRoot = "/var/log/pods",
            Namespaces = ["*"],
            LabelSelectors = [new("bower.io/collect", "true")]
        }.Validate());

        Assert.Throws<ArgumentException>(() => new KubernetesLogSourceOptions
        {
            PodLogRoot = "/var/log/pods",
            Namespaces = ["payments"],
            LabelSelectors = []
        }.Validate());
    }

    [Fact]
    public async Task KubernetesSource_EnforcesAllowLists_JoinsCriPartials_SurvivesRotationAndRestart()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory temp = new();
        EfSourceCursorStore store = new(Path.Combine(temp.Path, "cursors.db"));
        await store.InitializeAsync(ct);

        string podLogRoot = Path.Combine(temp.Path, "pods");
        KubernetesPodInfo allowedPod = new(
            "payments",
            "checkout-api-0",
            "uid-allowed-1",
            ["app"],
            new Dictionary<string, string>
            {
                ["bower.io/collect"] = "true",
                ["app.kubernetes.io/name"] = "checkout-api",
                ["secret-label"] = "must-not-attach"
            });
        KubernetesPodInfo forbiddenNsPod = new(
            "kube-system",
            "coredns-0",
            "uid-forbidden-ns",
            ["coredns"],
            new Dictionary<string, string> { ["bower.io/collect"] = "true" });
        KubernetesPodInfo forbiddenLabelPod = new(
            "payments",
            "debug-pod-0",
            "uid-forbidden-label",
            ["debug"],
            new Dictionary<string, string> { ["app"] = "debug" });

        string allowedDir = Path.Combine(podLogRoot, "payments_checkout-api-0_uid-allowed-1", "app");
        string forbiddenDir = Path.Combine(podLogRoot, "kube-system_coredns-0_uid-forbidden-ns", "coredns");
        Directory.CreateDirectory(allowedDir);
        Directory.CreateDirectory(forbiddenDir);

        string env1 = BuildEnvelopeJson("evt-k8s-1", "alice@example.com");
        string env2 = BuildEnvelopeJson("evt-k8s-2", "bob@example.com");
        string env1PartA = env1[..45];
        string env1PartB = env1[45..];

        string allowedLog = Path.Combine(allowedDir, "0.log");
        await File.WriteAllTextAsync(
            allowedLog,
            $"2026-11-22T00:00:01.000000000Z stdout F plain stdout debug noise\n"
            + $"not-a-cri-line\n"
            + $"2026-11-22T00:00:02.000000000Z stdout P {env1PartA}\n"
            + $"2026-11-22T00:00:02.000000001Z stdout F {env1PartB}\n",
            ct);
        await File.WriteAllTextAsync(
            Path.Combine(forbiddenDir, "0.log"),
            $"2026-11-22T00:00:01.000000000Z stdout F {BuildEnvelopeJson("evt-forbidden", "eve@example.com")}\n",
            ct);

        FakePodCatalog catalog = new([allowedPod, forbiddenNsPod, forbiddenLabelPod]);
        KubernetesLogSourceOptions options = new()
        {
            PodLogRoot = podLogRoot,
            Namespaces = ["payments"],
            LabelSelectors = [new("bower.io/collect", "true")],
            AllowedMetadataLabels = ["app.kubernetes.io/name"],
            StartAtEnd = false
        };

        KubernetesLogSource source = new(options, catalog, store);
        List<SecurityEventEnvelope> delivered = [];
        KubernetesPollResult first = await source.PollOnceAsync((env, _) =>
        {
            delivered.Add(env);
            return Task.FromResult(true);
        }, ct);

        Assert.Equal(1, first.PodsScanned);
        Assert.Equal(1, first.FilesTailed);
        Assert.Equal(1, first.EventsDelivered);
        Assert.Equal(1, first.DroppedNonSecurity);
        Assert.Equal(1, first.MalformedLines);
        Assert.Single(delivered);
        Assert.Equal("evt-k8s-1", delivered[0].EventId);
        Assert.Equal("payments", delivered[0].Labels!["k8s.namespace"]);
        Assert.Equal("checkout-api-0", delivered[0].Labels!["k8s.pod"]);
        Assert.Equal("app", delivered[0].Labels!["k8s.container"]);
        Assert.Equal("checkout-api", delivered[0].Labels!["k8s.label.app.kubernetes.io/name"]);
        Assert.False(delivered[0].Labels!.ContainsKey("k8s.label.secret-label"));

        // Rotate log file (rename 0.log -> 0.log.1, write new 0.log) and restart source from SQLite cursor.
        string rotatedLog = Path.Combine(allowedDir, "0.log.1");
        File.Move(allowedLog, rotatedLog);
        await File.WriteAllTextAsync(
            allowedLog,
            $"2026-11-22T00:01:00.000000000Z stderr F {env2}\n",
            ct);

        KubernetesLogSource restarted = new(options, catalog, store);
        // Poll enough times for rename grace polls (5) + transition to read the new file.
        for (int i = 0; i < 10 && delivered.Count < 2; i++)
        {
            await restarted.PollOnceAsync((env, _) =>
            {
                delivered.Add(env);
                return Task.FromResult(true);
            }, ct);
        }

        Assert.Equal(2, delivered.Count);
        Assert.Equal("evt-k8s-2", delivered[1].EventId);
        Assert.Equal("stderr", delivered[1].Labels!["k8s.stream"]);
    }

    [Fact]
    public async Task KubernetesApiPodCatalog_UsesNamespacedEndpointAndBearerTokenFile()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory temp = new();
        string tokenFile = Path.Combine(temp.Path, "token");
        await File.WriteAllTextAsync(tokenFile, "k8s-sa-token-xyz\n", ct);

        Uri? capturedUri = null;
        string? capturedAuth = null;
        using HttpClient client = new(new StubHttpHandler(req =>
        {
            capturedUri = req.RequestUri;
            capturedAuth = req.Headers.Authorization?.ToString();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"items":[{"metadata":{"namespace":"payments","name":"api-1","uid":"u-1","labels":{"bower.io/collect":"true"}},"spec":{"containers":[{"name":"app"}]}}]}""",
                    Encoding.UTF8,
                    "application/json")
            };
        }));

        KubernetesApiPodCatalog catalog = new(client, new Uri("https://kubernetes.default.svc"), tokenFile, "node-a");
        IReadOnlyList<KubernetesPodInfo> pods = await catalog.ListPodsAsync("payments", new("bower.io/collect", "true"), ct);

        Assert.Single(pods);
        Assert.Equal("api-1", pods[0].Name);
        Assert.Equal("Bearer k8s-sa-token-xyz", capturedAuth);
        Assert.Contains("/api/v1/namespaces/payments/pods", capturedUri!.AbsolutePath, StringComparison.Ordinal);
        Assert.Contains("labelSelector=bower.io%2Fcollect%3Dtrue", capturedUri.Query, StringComparison.Ordinal);
        Assert.Contains("fieldSelector=spec.nodeName%3Dnode-a", capturedUri.Query, StringComparison.Ordinal);
    }

    private static string BuildEnvelopeJson(string eventId, string username) =>
        JsonSerializer.Serialize(new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = eventId,
            TimeGenerated = Now,
            EventCategory = SecurityEventCategories.Authentication,
            EventType = SecurityEventTypes.AuthenticationFailure,
            EventAction = "authentication.attempt",
            EventResult = EventResult.Failure,
            EventOutcomeReason = "InvalidCredentials",
            Application = new ApplicationContext { Name = "checkout-api", Environment = "production" },
            Actor = new ActorContext { Username = username },
            Source = new SourceContext { IpAddress = "192.0.2.90" },
            Request = new RequestContext { CorrelationId = $"corr-{eventId}" }
        }, BowerJson.Envelope);

    private static LoadedPack BuildPack(string packId)
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", packId), privatePem, output.Path);
        return PackArchive.Load(archive, [publicPem]);
    }

    private sealed class FakeJournalReader(IReadOnlyList<JournaldEntry> entries) : IJournalReader
    {
        public ValueTask<IReadOnlyList<JournaldEntry>> ReadBatchAsync(
            string? afterCursor,
            int maxRecords,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int start = 0;
            if (!string.IsNullOrWhiteSpace(afterCursor))
            {
                for (int i = 0; i < entries.Count; i++)
                {
                    if (string.Equals(entries[i].Cursor, afterCursor, StringComparison.Ordinal))
                    {
                        start = i + 1;
                        break;
                    }
                }
            }

            return ValueTask.FromResult<IReadOnlyList<JournaldEntry>>(entries.Skip(start).Take(maxRecords).ToArray());
        }

        public void Dispose()
        {
        }
    }

    private sealed class FakePodCatalog(IReadOnlyList<KubernetesPodInfo> pods) : IKubernetesPodCatalog
    {
        public Task<IReadOnlyList<KubernetesPodInfo>> ListPodsAsync(
            string namespaceName,
            LabelSelectorEntry selector,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(pods);
    }

    private sealed class StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}

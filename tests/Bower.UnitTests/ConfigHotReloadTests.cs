using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// Config hot reload without dropping or duplicating queued events (#96): atomic policy
/// swap, pre-validation fail-safe, hash-chained reload ledger, concurrent ingest soak,
/// operator authorization on POST /v1/reload, and optional debounced file watcher.
/// </summary>
public sealed class ConfigHotReloadTests
{
    private const string SharedToken = "hot-reload-test-token-0123456789abcdef";

    [Fact]
    public async Task HotReload_ValidAndInvalidPolicyChanges_UpdatesStatusLedgerAndKeepsPreviousOnError()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string policyDir = Path.Combine(directory.Path, "policies");
        Directory.CreateDirectory(policyDir);
        string policyFile = Path.Combine(policyDir, "auth.yaml");
        await File.WriteAllTextAsync(policyFile, PolicyYaml("1.0.0", "accept"), cancellation);

        CollectorSettings settings = CreateSettings(directory.Path, policyDir);
        await using WebApplication app = BuildCollector(settings);
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);

        try
        {
            using HttpClient client = app.GetTestClient();
            string initialHash = await GetPolicyHashAsync(client, cancellation);

            // Event accepted under policy v1.0.0.
            using HttpResponseMessage first = await PostEventAsync(client, "evt-reload-1", cancellation);
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);

            // Update policy to v2.0.0 rejecting authentication_failure, then POST /v1/reload.
            await File.WriteAllTextAsync(policyFile, PolicyYaml("2.0.0", "reject"), cancellation);
            using HttpResponseMessage reloadResponse = await PostReloadAsync(client, SharedToken, cancellation);
            Assert.Equal(HttpStatusCode.OK, reloadResponse.StatusCode);
            using JsonDocument reloadJson = JsonDocument.Parse(await reloadResponse.Content.ReadAsStringAsync(cancellation));
            Assert.Equal("reloaded", reloadJson.RootElement.GetProperty("outcome").GetString());
            Assert.Equal("http", reloadJson.RootElement.GetProperty("trigger").GetString());
            string updatedHash = reloadJson.RootElement.GetProperty("policyHash").GetString()!;
            Assert.NotEqual(initialHash, updatedHash);
            Assert.Equal(initialHash, reloadJson.RootElement.GetProperty("previousPolicyHash").GetString());
            Assert.Equal(1, reloadJson.RootElement.GetProperty("ledgerSequence").GetInt64());

            // /v1/status reflects the new policy hash and reload metadata.
            Assert.Equal(updatedHash, await GetPolicyHashAsync(client, cancellation));

            // New event now rejected under v2.0.0.
            using HttpResponseMessage second = await PostEventAsync(client, "evt-reload-2", cancellation);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, second.StatusCode);

            // Corrupt the YAML on disk; reload must fail with 422 and keep v2.0.0 active.
            await File.WriteAllTextAsync(policyFile, "not: [valid: yaml: :::", cancellation);
            using HttpResponseMessage badReload = await PostReloadAsync(client, SharedToken, cancellation);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, badReload.StatusCode);
            using JsonDocument badJson = JsonDocument.Parse(await badReload.Content.ReadAsStringAsync(cancellation));
            Assert.Equal("rejected", badJson.RootElement.GetProperty("outcome").GetString());
            Assert.Equal(updatedHash, badJson.RootElement.GetProperty("policyHash").GetString());
            Assert.False(string.IsNullOrWhiteSpace(badJson.RootElement.GetProperty("errorType").GetString()));
            // Metadata only: error never leaks file path or raw YAML.
            string badBody = badJson.RootElement.GetRawText();
            Assert.DoesNotContain(policyFile, badBody, StringComparison.Ordinal);

            // Previous v2.0.0 policy still active (still rejects).
            using HttpResponseMessage third = await PostEventAsync(client, "evt-reload-3", cancellation);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, third.StatusCode);

            // Reload ledger and queue ledger both remain intact.
            SqliteEventStore store = (SqliteEventStore)app.Services.GetRequiredService<IDurableEventStore>();
            IReadOnlyList<ConfigReloadLedgerEntry> reloads = await store.ListConfigReloadsAsync(cancellationToken: cancellation);
            ConfigReloadLedgerEntry entry = Assert.Single(reloads);
            Assert.Equal(initialHash, entry.PreviousPolicyHash);
            Assert.Equal(updatedHash, entry.NewPolicyHash);
            Assert.True(await store.VerifyConfigReloadLedgerAsync(cancellation));
            Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
        }
        finally
        {
            await app.StopAsync(cancellation);
        }
    }

    [Fact]
    public async Task HotReload_ConcurrentIngestAndMultipleReloads_NeverDropsOrDuplicatesEvents()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string policyDir = Path.Combine(directory.Path, "policies");
        Directory.CreateDirectory(policyDir);
        string policyFile = Path.Combine(policyDir, "auth.yaml");
        await File.WriteAllTextAsync(policyFile, PolicyYaml("1.0.0", "accept"), cancellation);

        RecordingOutputAdapter output = new();
        CollectorSettings settings = CreateSettings(directory.Path, policyDir);
        await using WebApplication app = BuildCollector(settings, output);
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);

        try
        {
            using HttpClient client = app.GetTestClient();
            PolicyBundleHolder holder = app.Services.GetRequiredService<PolicyBundleHolder>();

            const int totalEvents = 60;
            ConcurrentBag<string> acceptedIds = [];
            Task producers = Task.WhenAll(Enumerable.Range(0, totalEvents).Select(async i =>
            {
                string id = $"soak-evt-{i:D4}";
                using HttpResponseMessage response = await PostEventAsync(client, id, cancellation);
                Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
                acceptedIds.Add(id);
            }));

            Task reloader = Task.Run(async () =>
            {
                for (int version = 2; version <= 6; version++)
                {
                    await File.WriteAllTextAsync(policyFile, PolicyYaml($"{version}.0.0", "accept"), cancellation);
                    ConfigReloadStatus status = await holder.ReloadAsync("sighup", cancellation);
                    Assert.Equal("reloaded", status.Outcome);
                    await Task.Delay(5, cancellation);
                }
            }, cancellation);

            await Task.WhenAll(producers, reloader);
            Assert.Equal(totalEvents, acceptedIds.Count);

            // Wait for delivery worker to acknowledge every queued event (no drops, no duplicates).
            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);
            while (output.DeliveredIds.Count < totalEvents && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(25, cancellation);
            }

            Assert.Equal(totalEvents, output.DeliveredIds.Count);
            Assert.Equal(totalEvents, output.DeliveredIds.Distinct(StringComparer.Ordinal).Count());

            SqliteEventStore store = (SqliteEventStore)app.Services.GetRequiredService<IDurableEventStore>();
            Assert.True(await store.VerifyConfigReloadLedgerAsync(cancellation));
            Assert.True((await store.VerifyLedgerAsync(cancellation)).Intact);
            Assert.Equal(5, (await store.ListConfigReloadsAsync(cancellationToken: cancellation)).Count);
        }
        finally
        {
            await app.StopAsync(cancellation);
        }
    }

    [Fact]
    public async Task HotReload_PolicyWatchEnabled_AutomaticallyReloadsOnFileEdit()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string policyDir = Path.Combine(directory.Path, "policies");
        Directory.CreateDirectory(policyDir);
        string policyFile = Path.Combine(policyDir, "auth.yaml");
        await File.WriteAllTextAsync(policyFile, PolicyYaml("1.0.0", "accept"), cancellation);

        CollectorSettings settings = CreateSettings(directory.Path, policyDir) with
        {
            PolicyWatchEnabled = true,
            PolicyWatchDebounce = TimeSpan.FromMilliseconds(100)
        };
        await using WebApplication app = BuildCollector(settings);
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);

        try
        {
            PolicyBundleHolder holder = app.Services.GetRequiredService<PolicyBundleHolder>();
            string initialHash = holder.CurrentBundle.Hash;

            await File.WriteAllTextAsync(policyFile, PolicyYaml("1.1.0", "accept"), cancellation);

            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (string.Equals(holder.CurrentBundle.Hash, initialHash, StringComparison.Ordinal)
                && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(50, cancellation);
            }

            Assert.NotEqual(initialHash, holder.CurrentBundle.Hash);
            Assert.Equal("watch", holder.LastReload?.Trigger);
            Assert.Equal("reloaded", holder.LastReload?.Outcome);
        }
        finally
        {
            await app.StopAsync(cancellation);
        }
    }

    [Fact]
    public async Task HotReload_HttpEndpoint_RejectsNonOperatorProducerToken()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        string policyDir = Path.Combine(directory.Path, "policies");
        Directory.CreateDirectory(policyDir);
        await File.WriteAllTextAsync(Path.Combine(policyDir, "auth.yaml"), PolicyYaml("1.0.0", "accept"), cancellation);

        const string producerSecret = "ordinary-producer-token-0123456789abcdef";
        string hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(producerSecret)));
        string tokensFile = Path.Combine(directory.Path, "tokens.txt");
        await File.WriteAllTextAsync(tokensFile, $"app-01 sha256:{hash}\n", cancellation);

        CollectorSettings settings = CreateSettings(directory.Path, policyDir) with
        {
            IngestToken = null,
            IngestTokensFile = tokensFile
        };
        await using WebApplication app = BuildCollector(settings);
        await CollectorApplication.InitializeAsync(app, cancellation);
        await app.StartAsync(cancellation);

        try
        {
            using HttpClient client = app.GetTestClient();
            using HttpResponseMessage forbidden = await PostReloadAsync(client, producerSecret, cancellation);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        }
        finally
        {
            await app.StopAsync(cancellation);
        }
    }

    private static CollectorSettings CreateSettings(string directory, string policyDir) => new()
    {
        CollectorId = "hot-reload-01",
        Environment = "test",
        ListenUrl = "http://127.0.0.1:4319",
        PolicyDirectory = policyDir,
        QueuePath = Path.Combine(directory, "queue.db"),
        OutputType = "none",
        IngestToken = SharedToken,
        SingleTrustDomain = true
    };

    private static WebApplication BuildCollector(CollectorSettings settings, IOutputAdapter? output = null) =>
        CollectorApplication.Build(
            settings,
            output: output,
            configure: builder => builder.WebHost.UseTestServer());

    private static async Task<string> GetPolicyHashAsync(HttpClient client, CancellationToken cancellation)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", SharedToken);
        using HttpResponseMessage response = await client.SendAsync(request, cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellation));
        return doc.RootElement.GetProperty("policy").GetProperty("hash").GetString()!;
    }

    private static async Task<HttpResponseMessage> PostReloadAsync(HttpClient client, string token, CancellationToken cancellation)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "/v1/reload");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, cancellation);
    }

    private static async Task<HttpResponseMessage> PostEventAsync(HttpClient client, string eventId, CancellationToken cancellation)
    {
        string body = $$"""
            {
              "schemaVersion": "1.0.0",
              "eventId": "{{eventId}}",
              "timeGenerated": "{{DateTimeOffset.UtcNow:O}}",
              "eventCategory": "authentication",
              "eventType": "authentication_failure",
              "eventAction": "login.failed",
              "eventResult": "failure",
              "eventSeverity": "medium",
              "eventOutcomeReason": "invalid_credentials",
              "application": { "name": "portal", "environment": "test" },
              "actor": { "username": "alice", "type": "human" },
              "source": { "ipAddress": "198.51.100.10" },
              "request": { "correlationId": "corr-{{eventId}}" }
            }
            """;
        using HttpRequestMessage request = new(HttpMethod.Post, "/v1/events")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", SharedToken);
        return await client.SendAsync(request, cancellation);
    }

    private static string PolicyYaml(string version, string action) => $$"""
        apiVersion: bower.security/v1
        kind: TelemetryPolicy

        metadata:
          id: BWR-POL-AUTH-FAILURE
          name: Authentication failures
          version: {{version}}
          owner: Security Operations
          reviewDate: 2027-01-01

        match:
          eventCategories:
            - authentication
          eventTypes:
            - authentication_failure

        requirements:
          requiredFields:
            - timeGenerated
            - eventType
            - eventResult
            - application.name
          atLeastOne:
            - actor.userId
            - actor.username

        decision:
          action: {{action}}
          minimumValueScore: 70
          neverSample: true

        routing:
          profile: authentication
          destination: security-events
        """;

    private sealed class RecordingOutputAdapter : IOutputAdapter
    {
        public string Id => "recording";
        public ConcurrentBag<string> DeliveredIds { get; } = [];

        public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> batch, CancellationToken cancellationToken)
        {
            List<string> acked = [];
            foreach (QueuedEvent item in batch)
            {
                DeliveredIds.Add(item.EventId);
                acked.Add(item.EventId);
            }

            return Task.FromResult(new DeliveryResult(
                acked,
                [],
                $"ack-{Guid.NewGuid():N}"));
        }
    }
}

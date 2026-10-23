using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Output.AmaSpool;
using Bower.Output.AzureLogsIngestion;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Redaction.Privacy;
using Microsoft.Data.Sqlite;

namespace Bower.UnitTests;

public sealed class SemanticPrivacyTests
{
    [Fact]
    public void SemanticGuardBytesMatchRustFixture()
    {
        const string input = """{"change":{"field":"password","newValue":"after-canary"},"request":{"path":"/login?opaque=query-canary"}}""";
        const string expected = """{"change":{"field":"password"},"request":{"path":"/login"},"privacy":{"detected":["field-name-secret"],"actions":{"field-name-secret":"Removed"}}}""";
        Assert.Equal(expected, new PrivacyEngine().RedactJson(input).RedactedJson);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("apiKey")]
    [InlineData("access_token")]
    [InlineData("unknown")]
    [InlineData("role")]
    public void UnapprovedChangeValuesAreRemovedRegardlessOfShape(string field)
    {
        string json = $$$"""{"change":{"field":"{{{field}}}","previousValue":{"nested":"before-canary"},"newValue":["after-canary"]}}""";
        PrivacyScanResult result = new PrivacyEngine().RedactJson(json);
        Assert.True(result.Succeeded);
        Assert.DoesNotContain("canary", result.RedactedJson, StringComparison.Ordinal);
        Assert.Equal(["$.change.previousValue", "$.change.newValue"], result.RemovedPaths);
    }

    [Fact]
    public void ReviewedRoleChangeKeepsValuesAndStillRunsDetectors()
    {
        PrivacyScanResult result = new PrivacyEngine().RedactJson(
            """{"eventType":"role_membership_changed","change":{"field":"role","previousValue":"reader","newValue":"admin"}}""");
        Assert.True(result.Succeeded);
        Assert.Contains("\"previousValue\":\"reader\"", result.RedactedJson, StringComparison.Ordinal);
        Assert.Contains("\"newValue\":\"admin\"", result.RedactedJson, StringComparison.Ordinal);
        result = new PrivacyEngine().RedactJson(
            """{"eventType":"role_membership_changed","change":{"field":"role","newValue":"4111111111111111"}}""");
        Assert.DoesNotContain("4111111111111111", result.RedactedJson, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/login?opaque=query-canary#fragment-canary", "/login")]
    [InlineData("https://user:userinfo-canary@example.test/login?code=query-canary", "https://example.test/login")]
    [InlineData("//user:userinfo-canary@example.test/login#fragment-canary", "//example.test/login")]
    [InlineData("https://user:password-canary?opaque=x@host/login", "[redacted]")]
    [InlineData("/login%3Ftoken=query-canary", "/login")]
    [InlineData("https://user%40userinfo-canary@example.test/login", "[redacted]")]
    [InlineData("https:\\userinfo-canary", "[redacted]")]
    public void RequestUrlsDiscardCredentialsAndOpaqueQueryValues(string path, string expected)
    {
        string json = JsonSerializer.Serialize(new { request = new { path } });
        PrivacyScanResult result = new PrivacyEngine().RedactJson(json);
        Assert.True(result.Succeeded);
        using JsonDocument document = JsonDocument.Parse(result.RedactedJson!);
        Assert.Equal(expected, document.RootElement.GetProperty("request").GetProperty("path").GetString());
        Assert.DoesNotContain("canary", result.RedactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AcceptedCanariesNeverReachSqliteWalSpoolOrCapturedAzureRequest()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string database = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(database, 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        // Keep a reader open so WAL frames remain available for the byte-level assertion.
        await using SqliteConnection reader = new($"Data Source={database};Pooling=False");
        await reader.OpenAsync(cancellationToken);
        await using SqliteCommand command = reader.CreateCommand();
        command.CommandText = "BEGIN; SELECT count(*) FROM queue_events;";
        await command.ExecuteScalarAsync(cancellationToken);
        SecurityEventProcessor processor = new(new JsonEventRedactor(),
            new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy(), TestEvents.PrivacyDetectionPolicy()]), store, clock);
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(clock.UtcNow) with
        {
            Change = new ChangeContext { Field = "password", PreviousValue = "before-canary", NewValue = "after-canary" },
            Request = new RequestContext { Path = "https://u:userinfo-canary@example.test/login?opaque=query-canary#fragment-canary" }
        };
        ProcessingResult result = await processor.ProcessAsync(JsonSerializer.Serialize(candidate, BowerJson.Envelope),
            new CollectorIdentity("collector", "test", "test", "sha256:test"), cancellationToken);
        Assert.True(result.Queued);
        IReadOnlyList<QueuedEvent> batch = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken);
        Assert.Contains(batch, item => item.EventId == candidate.EventId);
        Assert.All(batch, item => Assert.DoesNotContain("canary", item.Payload, StringComparison.Ordinal));
        Assert.True(new FileInfo(database + "-wal").Length > 0);
        foreach (string path in new[] { database, database + "-wal" })
        {
            Assert.DoesNotContain("canary", Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path, cancellationToken)), StringComparison.Ordinal);
        }

        AmaSpoolOutput spool = new(new AmaSpoolOptions
        {
            Id = "test",
            CollectorId = "test",
            StreamName = "Custom-BowerSecurity",
            ActiveDirectory = Path.Combine(directory.Path, "active"),
            ReadyDirectory = Path.Combine(directory.Path, "ready")
        });
        DeliveryResult spooled = await spool.DeliverAsync(batch, cancellationToken);
        Assert.Equal(batch.Count, spooled.AcknowledgedEventIds.Count);
        string[] files = Directory.GetFiles(Path.Combine(directory.Path, "ready"), "*", SearchOption.AllDirectories);
        Assert.NotEmpty(files);
        foreach (string path in files)
        {
            Assert.DoesNotContain("canary", await File.ReadAllTextAsync(path, cancellationToken), StringComparison.Ordinal);
        }

        CaptureHandler capture = new();
        AzureLogsIngestionOutput output = new(new AzureLogsIngestionOptions
        {
            Id = "test",
            Endpoint = new Uri("https://simulated.ingest.monitor.azure.com"),
            DcrImmutableId = "dcr-test",
            StreamName = "Custom-BowerSecurity"
        }, new FakeCredential(), new LogsIngestionClientOptions
        {
            Transport = new HttpClientTransport(new HttpClient(capture)),
            Retry = { MaxRetries = 0 }
        });
        DeliveryResult delivered = await output.DeliverAsync(batch, cancellationToken);
        Assert.Equal(batch.Count, delivered.AcknowledgedEventIds.Count);
        Assert.NotEmpty(capture.Bodies);
        Assert.All(capture.Bodies, body => Assert.DoesNotContain("canary", body, StringComparison.Ordinal));
        command.CommandText = "ROLLBACK;";
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            if (request.Content.Headers.ContentEncoding.Contains("gzip"))
            {
                using GZipStream gzip = new(new MemoryStream(bytes), CompressionMode.Decompress);
                using MemoryStream plain = new();
                await gzip.CopyToAsync(plain, cancellationToken);
                bytes = plain.ToArray();
            }

            Bodies.Add(Encoding.UTF8.GetString(bytes));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    private sealed class FakeCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("synthetic-test-token", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}

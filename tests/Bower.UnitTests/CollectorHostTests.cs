using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Packs;
using Bower.PolicyEngine;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Hangfire keeps process-wide configuration, so hosts are tested one at a time.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SerialHostTests
{
    public const string Name = "hosts";
}

[Collection(SerialHostTests.Name)]
public sealed class CollectorHostTests
{
    private const string Token = "test-ingest-token-0123456789abcdef0123456789";

    [Theory]
    [InlineData("throw")]
    [InlineData("failure")]
    [InlineData("missing")]
    [InlineData("damaged")]
    public async Task Ingest_OperationalRedactionFailureIsRetryableAndDoesNotLeak(string mode)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        IEventRedactor redactor = new PackDetectionRedactor(new UnavailableTestRedactor(mode), new DeterministicPolicyEvaluator([]), []);
        await using WebApplication app = await StartAsync(directory, Token, cancellation, redactor: redactor);
        using HttpClient client = app.GetTestClient();
        using HttpRequestMessage request = Post(AuthenticationFailure() with { EventId = "synthetic-id" }, Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellation);
        string body = await response.Content.ReadAsStringAsync(cancellation);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(60), response.Headers.RetryAfter?.Delta);
        Assert.Contains("redaction-unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain(UnavailableTestRedactor.SecretMarker, body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-id", body, StringComparison.Ordinal);
        Assert.Empty(await app.Services.GetRequiredService<IDurableEventStore>().LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Fact]
    public async Task Ingest_ValidJsonWithInvalidSchemaRemainsPermanentFailure()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellation);
        using HttpClient client = app.GetTestClient();
        string body = JsonSerializer.Serialize(AuthenticationFailure() with { EventId = "safe-id" }, BowerJson.Envelope);
        System.Text.Json.Nodes.JsonObject json = System.Text.Json.Nodes.JsonNode.Parse(body)!.AsObject();
        json["timeGenerated"] = "invalid-date";
        using HttpRequestMessage request = new(HttpMethod.Post, "/v1/events") { Content = new StringContent(json.ToJsonString(), System.Text.Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellation);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.RetryAfter);
        Assert.Empty(await app.Services.GetRequiredService<IDurableEventStore>().LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Fact]
    public async Task Ingest_IdentityChangedByPrivacyIsRetryableAndNeverQueued()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellation);
        using HttpClient client = app.GetTestClient();
        SecurityEventEnvelope first = AuthenticationFailure() with { EventId = "10040680-c19c-4eec-8ca0-056e33f7f420" };
        SecurityEventEnvelope second = first with { EventId = "10170680-c19c-4eec-8ca0-056e33f7f420" };
        foreach (SecurityEventEnvelope candidate in new[] { first, second, first })
        {
            using HttpRequestMessage request = Post(candidate, Token);
            using HttpResponseMessage response = await client.SendAsync(request, cancellation);
            string body = await response.Content.ReadAsStringAsync(cancellation);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(TimeSpan.FromSeconds(60), response.Headers.RetryAfter?.Delta);
            Assert.Contains("event-id-redacted", body, StringComparison.Ordinal);
            Assert.DoesNotContain(candidate.EventId, body, StringComparison.Ordinal);
            using JsonDocument json = JsonDocument.Parse(body);
            Assert.False(json.RootElement.GetProperty("queued").GetBoolean());
            Assert.False(json.RootElement.GetProperty("duplicate").GetBoolean());
        }
        Bower.Abstractions.IDurableEventStore store = app.Services.GetRequiredService<Bower.Abstractions.IDurableEventStore>();
        Assert.Empty(await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellation));
    }

    [Fact]
    public async Task Ingest_RejectsMissingAndWrongTokens()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellationToken);
        HttpClient client = app.GetTestClient();

        using HttpResponseMessage missing = await client.PostAsJsonAsync(
            "/v1/events", AuthenticationFailure(), BowerJson.Options, cancellationToken);
        using HttpRequestMessage wrongRequest = Post(AuthenticationFailure(), "wrong-token");
        using HttpResponseMessage wrong = await client.SendAsync(wrongRequest, cancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
    }

    [Fact]
    public async Task Ingest_AcceptsValidTokenAndRedactsBeforeQueueing()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellationToken);
        HttpClient client = app.GetTestClient();
        SecurityEventEnvelope candidate = AuthenticationFailure() with
        {
            Attributes = new Dictionary<string, JsonElement>
            {
                ["dbPassword"] = JsonSerializer.SerializeToElement("never-persist")
            }
        };

        using HttpRequestMessage request = Post(candidate, Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Null(response.Headers.RetryAfter);
        Assert.Contains("redactandaccept", body, StringComparison.Ordinal);
        Assert.DoesNotContain("never-persist", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Ingest_CrossProducerIdentityConflictIsActionableAndCountedWithoutPayload()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        const string otherToken = "other-token-0123456789abcdef0123456789";
        string tokensFile = Path.Combine(directory.Path, "tokens");
        File.WriteAllLines(tokensFile, [IngestAuthentication.TokensFileLine("other-producer", otherToken)]);
        await using WebApplication app = await StartAsync(directory, Token, cancellation,
            settings => settings with { IngestTokensFile = tokensFile });
        using HttpClient client = app.GetTestClient();
        SecurityEventEnvelope candidate = AuthenticationFailure() with
        {
            EventId = "private-event-id",
            Attributes = new Dictionary<string, JsonElement>
            {
                ["producer"] = JsonSerializer.SerializeToElement("forged-producer"),
                ["dbPassword"] = JsonSerializer.SerializeToElement("payload-secret-canary")
            }
        };
        using HttpRequestMessage first = Post(candidate, Token);
        using HttpResponseMessage accepted = await client.SendAsync(first, cancellation);
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        using HttpRequestMessage replay = Post(candidate, Token);
        using HttpResponseMessage duplicate = await client.SendAsync(replay, cancellation);
        Assert.Equal(HttpStatusCode.OK, duplicate.StatusCode);
        for (int index = 0; index < 2; index++)
        {
            using HttpRequestMessage request = Post(candidate, otherToken);
            using HttpResponseMessage response = await client.SendAsync(request, cancellation);
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            string body = await response.Content.ReadAsStringAsync(cancellation);
            using JsonDocument json = JsonDocument.Parse(body);
            Assert.Equal("event-identity-conflict", json.RootElement.GetProperty("reasons")[0].GetString());
            Assert.False(json.RootElement.GetProperty("queued").GetBoolean());
            Assert.False(json.RootElement.GetProperty("duplicate").GetBoolean());
            Assert.Contains("Preserve the upstream event", json.RootElement.GetProperty("remediation").GetString(), StringComparison.Ordinal);
            Assert.DoesNotContain("payload-secret-canary", body, StringComparison.Ordinal);
        }
        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", otherToken);
        using HttpResponseMessage status = await client.SendAsync(statusRequest, cancellation);
        string diagnostics = await status.Content.ReadAsStringAsync(cancellation);
        using JsonDocument document = JsonDocument.Parse(diagnostics);
        JsonElement conflicts = document.RootElement.GetProperty("eventIdentityConflicts");
        JsonElement producer = Assert.Single(conflicts.GetProperty("producers").EnumerateArray());
        Assert.Equal("other-producer", producer.GetProperty("producer").GetString());
        Assert.Equal(2, producer.GetProperty("count").GetInt64());
        Assert.Equal(0, conflicts.GetProperty("unattributed").GetInt64());
        Assert.Equal(0, conflicts.GetProperty("overflow").GetInt64());
        Assert.DoesNotContain("private-event-id", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("forged-producer", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("payload-secret-canary", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain(otherToken, diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Health_IsAnonymousButStatusRequiresToken()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellationToken);
        HttpClient client = app.GetTestClient();

        string health = await client.GetStringAsync("/health", cancellationToken);
        using HttpResponseMessage anonymousStatus = await client.GetAsync("/v1/status", cancellationToken);
        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(statusRequest, cancellationToken);
        string statusBody = await status.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal("""{"status":"healthy"}""", health);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousStatus.StatusCode);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        // The installed build, right after the status (as the Rust collector).
        Assert.StartsWith($$"""{"status":"healthy","version":"{{BowerVersion.Current}}",""", statusBody, StringComparison.Ordinal);
        Assert.DoesNotContain("version", health, StringComparison.Ordinal);
        Assert.Contains("queue-retention", statusBody, StringComparison.Ordinal);
        Assert.Contains("queue-maintenance", statusBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status_ReportsAdaptiveDeliveryConcurrencyAsMetadataOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        ConcurrencyReportingOutput output = new();
        await using WebApplication app = CollectorApplication.Build(
            BaseSettings(directory.Path) with { IngestToken = Token },
            builder => builder.WebHost.UseTestServer(),
            output);
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        HttpClient client = app.GetTestClient();

        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(statusRequest, cancellationToken);
        string body = await status.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        // Same text as the Rust collector (collector_host.rs).
        Assert.Contains(
            """
            "delivery":{"outputId":"azure-logs-ingestion","limit":2,"minimumLimit":1,"maximumLimit":4,"inFlight":1,"latencyEwmaMilliseconds":163,"requests":9,"throttles":3,"serverErrors":1,"timeouts":0,"latencySpikes":1,"decreases":2,"increases":1,"pauses":1,"processLocalPausedUntil":"2026-07-26T02:16:19+00:00"}
            """.Trim(),
            body,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status_OmitsDeliveryWhenTheOutputDoesNotAdaptConcurrency()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellationToken);
        HttpClient client = app.GetTestClient();

        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage status = await client.SendAsync(statusRequest, cancellationToken);

        Assert.DoesNotContain("\"delivery\"", await status.Content.ReadAsStringAsync(cancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status_ReportsTheConfiguredOutputAndOmitsItWithoutOne()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory sentinel = new();
        using TemporaryDirectory s3 = new();
        await using WebApplication none = await StartAsync(sentinel, Token, cancellationToken);
        await using WebApplication bucket = await StartAsync(s3, Token, cancellationToken, settings => settings with
        {
            OutputType = "s3",
            S3Output = new Bower.Output.S3.S3OutputOptions
            {
                Bucket = "bower-status-test",
                Region = "ap-southeast-2",
                CollectorId = "collector-status"
            }
        });

        async Task<string> StatusAsync(WebApplication app)
        {
            using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            using HttpResponseMessage response = await app.GetTestClient().SendAsync(request, cancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await response.Content.ReadAsStringAsync(cancellationToken);
        }

        Assert.DoesNotContain("\"output\":", await StatusAsync(none), StringComparison.Ordinal);
        string body = await StatusAsync(bucket);
        Assert.Contains("\"output\":\"s3\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("bower-status-test", body, StringComparison.Ordinal);
    }

    private sealed class ConcurrencyReportingOutput : Bower.Abstractions.IOutputAdapter, Bower.Abstractions.IOutputConcurrencyStatus
    {
        public string Id => "azure-logs-ingestion";

        public Task<Bower.Abstractions.DeliveryResult> DeliverAsync(
            IReadOnlyList<Bower.Abstractions.QueuedEvent> events,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new Bower.Abstractions.DeliveryResult(
                [], [.. events.Select(item => new Bower.Abstractions.DeliveryFailure(item.EventId, "destination-test", true, null))], null));

        public Bower.Abstractions.OutputConcurrencySnapshot? GetConcurrencySnapshot() =>
            new(Id, 2, 1, 4, 1, 163, 9, 3, 1, 0, 1, 2, 1, 1, TestEvents.Now.AddMinutes(2));
    }

    [Fact]
    public async Task Ingest_RateLimitsBursts()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(
            directory,
            Token,
            cancellationToken,
            settings => settings with { IngestRequestsPerSecond = 1 });
        HttpClient client = app.GetTestClient();

        List<HttpStatusCode> statuses = [];
        for (int index = 0; index < 4; index++)
        {
            using HttpRequestMessage request = Post(
                AuthenticationFailure() with { EventId = $"burst-{index}", EventOriginalId = $"burst-{index}" },
                Token);
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            statuses.Add(response.StatusCode);
        }

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    [Fact]
    public async Task ProducerTokens_AreRevocableWithoutRestart()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string sidecar = "sidecar-token-0123456789abcdefghijklmnop";
        string app = "app-token-0123456789abcdefghijklmnopqrstu";
        string tokensFile = Path.Combine(directory.Path, "tokens");
        File.WriteAllLines(tokensFile,
        [
            "# producer credentials",
            IngestAuthentication.TokensFileLine("sidecar-01", sidecar),
            IngestAuthentication.TokensFileLine("portal", app)
        ]);
        FakeClock clock = new(TestEvents.Now);
        IngestAuthentication authentication = new(null, tokensFile, clock);

        string? before = authentication.Authenticate(Request(sidecar));
        File.WriteAllLines(tokensFile, [IngestAuthentication.TokensFileLine("portal", app)]);
        File.SetLastWriteTimeUtc(tokensFile, DateTime.UtcNow.AddSeconds(5));
        clock.Advance(TimeSpan.FromSeconds(3));
        string? revoked = authentication.Authenticate(Request(sidecar));
        string? kept = authentication.Authenticate(Request(app));

        Assert.Equal("sidecar-01", before);
        Assert.Null(revoked);
        Assert.Equal("portal", kept);
        await Task.CompletedTask;
    }

    [Fact]
    public void ProducerTokens_RejectMalformedFile()
    {
        using TemporaryDirectory directory = new();
        string tokensFile = Path.Combine(directory.Path, "tokens");
        File.WriteAllText(tokensFile, "sidecar-01 not-a-hash\n");

        Assert.Throws<FormatException>(() => new IngestAuthentication(null, tokensFile));
    }

    [Fact]
    public async Task Collector_LoadsSignedPackAndReportsPolicyBundle()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = Bower.Integrity.DetachedSigner.GenerateKeyPair();
        string pack = Bower.Packs.PackArchive.Build(
            Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway"), privatePem, directory.Path);
        string publicKey = Path.Combine(directory.Path, "trusted.pem");
        string hmacKey = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(publicKey, publicPem);
        File.WriteAllText(hmacKey, Convert.ToBase64String(new byte[32]));
        await using WebApplication app = await StartAsync(
            directory,
            Token,
            cancellationToken,
            settings => settings with
            {
                Packs = [pack],
                PackTrustedKeyFiles = [publicKey],
                PrivacyHmacKeyFile = hmacKey
            });
        HttpClient client = app.GetTestClient();
        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        string status = await (await client.SendAsync(statusRequest, cancellationToken)).Content.ReadAsStringAsync(cancellationToken);
        using HttpRequestMessage post = Post(AuthenticationFailure(), Token);
        string accepted = await (await client.SendAsync(post, cancellationToken)).Content.ReadAsStringAsync(cancellationToken);

        Assert.Contains("linux-ssh-gateway", status, StringComparison.Ordinal);
        Assert.Contains("\"privacyProfile\":\"ssh-gateway-pseudonymised\"", status, StringComparison.Ordinal);
        Assert.Contains("\"ledger\":", status, StringComparison.Ordinal);
        Assert.Contains("accept", accepted, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_RefuseUnverifiedPacks()
    {
        CollectorSettings settings = BaseSettings("unused") with { Packs = ["x.bowerpack"] };

        Assert.Throws<InvalidOperationException>(settings.Validate);
    }

    private static Microsoft.AspNetCore.Http.HttpRequest Request(string token)
    {
        Microsoft.AspNetCore.Http.DefaultHttpContext context = new();
        context.Request.Headers.Authorization = $"Bearer {token}";
        return context.Request;
    }

    [Fact]
    public void Settings_RequireTokenOnNonLoopbackListener()
    {
        CollectorSettings settings = BaseSettings("unused") with
        {
            ListenUrl = "http://0.0.0.0:4319",
            IngestToken = null
        };

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(settings.Validate);
        Assert.Contains("BOWER_INGEST_TOKEN", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_AllowExplicitUnauthenticatedOptOut()
    {
        CollectorSettings settings = BaseSettings("unused") with
        {
            ListenUrl = "http://0.0.0.0:4319",
            IngestToken = null,
            AllowUnauthenticatedIngest = true
        };

        settings.Validate();
    }

    [Fact]
    public void Settings_RejectShortToken()
    {
        CollectorSettings settings = BaseSettings("unused") with { IngestToken = "short" };

        Assert.Throws<InvalidOperationException>(settings.Validate);
    }

    [Theory]
    [InlineData("@Microsoft.KeyVault(SecretUri=https://example.vault.azure.net/secrets/ingest/)")]
    [InlineData("  @microsoft.keyvault(SecretUri=https://example.vault.azure.net/secrets/ingest/)")]
    public void Settings_RejectUnresolvedKeyVaultReferenceWithoutEchoingIt(string reference)
    {
        CollectorSettings settings = BaseSettings("unused") with { IngestToken = reference };

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(settings.Validate);
        Assert.Contains("unresolved Key Vault or App Configuration reference", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(reference, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InlineProducerScopes_AllowOnlyTheConfiguredIdentity()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        const string scopes = """[{"producer":"default","application":{"name":"TestApplication","environment":"test"},"source":{"ipAddress":"192.0.2.10"}}]""";
        await using WebApplication app = await StartAsync(directory, Token, cancellation,
            settings => settings with { SingleTrustDomain = false, ProducerScopesJson = scopes });
        using HttpClient client = app.GetTestClient();
        SecurityEventEnvelope candidate = AuthenticationFailure();
        using HttpRequestMessage permitted = Post(candidate, Token);
        using HttpResponseMessage accepted = await client.SendAsync(permitted, cancellation);
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);

        using HttpRequestMessage forged = Post(candidate with
        {
            EventId = "different-event",
            Application = candidate.Application with { Name = "OtherApplication" }
        }, Token);
        using HttpResponseMessage denied = await client.SendAsync(forged, cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task InlineProducerScopes_InvalidConfigurationFailsClosedWithoutEchoingIt()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        const string invalid = "sensitive-configuration-marker";
        FormatException error = await Assert.ThrowsAsync<FormatException>(() => StartAsync(directory, Token, cancellation,
            settings => settings with { SingleTrustDomain = false, ProducerScopesJson = invalid }));
        Assert.DoesNotContain(invalid, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InlineProducerScopes_EmptyArrayDeniesIngest()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await StartAsync(directory, Token, cancellation,
            settings => settings with { SingleTrustDomain = false, ProducerScopesJson = "[]" });
        using HttpClient client = app.GetTestClient();
        using HttpRequestMessage request = Post(AuthenticationFailure(), Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task InlineProducerScopes_RejectsOversizedDocuments()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string oversized = new('x', Bower.Core.ProducerAuthorization.MaximumScopesBytes + 1);
        await Assert.ThrowsAsync<FormatException>(() => StartAsync(directory, Token, cancellation,
            settings => settings with { SingleTrustDomain = false, ProducerScopesJson = oversized }));
    }

    [Theory]
    [InlineData(true, null, "[]")]
    [InlineData(false, "scopes.json", "[]")]
    public void Settings_RejectConflictingProducerScopeSources(bool singleTrustDomain, string? file, string json)
    {
        CollectorSettings settings = BaseSettings("unused") with
        {
            SingleTrustDomain = singleTrustDomain,
            ProducerScopesFile = file,
            ProducerScopesJson = json
        };
        Assert.Throws<InvalidOperationException>(settings.Validate);
    }

    [Fact]
    public void Settings_ReadInlineScopesAndIncludeThemInConfigurationHash()
    {
        CollectorSettings original = BaseSettings("unused") with { SingleTrustDomain = false };
        CollectorSettings first = original with { ProducerScopesJson = "[]" };
        CollectorSettings second = original with { ProducerScopesJson = "[{\"producer\":\"different\"}]" };
        // Shared vector for the Rust collector's inline-scope configuration hash.
        Assert.Equal("sha256:82030a56551266744926a51e40db705ffc5c45500d52ecb28af907582a23c6d5", first.ConfigurationHash());
        Assert.NotEqual(original.ConfigurationHash(), first.ConfigurationHash());
        Assert.NotEqual(first.ConfigurationHash(), second.ConfigurationHash());

        CollectorSettings fromEnvironment = CollectorSettings.FromEnvironment(key => key switch
        {
            "BOWER_COLLECTOR_ID" => "test-collector",
            "BOWER_PRODUCER_SCOPES_JSON" => "[]",
            _ => null
        });
        Assert.Equal("[]", fromEnvironment.ProducerScopesJson);
    }

    [Theory]
    [InlineData("http://management.example.test", false)]
    [InlineData("https://management.example.test", true)]
    [InlineData("http://127.0.0.1:4320", true)]
    public void Settings_RequireHttpsForRemoteManagement(string endpoint, bool valid)
    {
        CollectorSettings settings = BaseSettings("unused") with
        {
            ManagementEndpoint = new Uri(endpoint),
            ManagementScope = "api://bower/.default"
        };

        if (valid)
        {
            settings.Validate();
        }
        else
        {
            Assert.Throws<InvalidOperationException>(settings.Validate);
        }
    }

    [Fact]
    public void Settings_ReadFromEnvironmentWithTokenFile()
    {
        using TemporaryDirectory directory = new();
        string tokenFile = Path.Combine(directory.Path, "token");
        File.WriteAllText(tokenFile, Token + "\n");
        Dictionary<string, string> environment = new()
        {
            ["BOWER_LISTEN_URL"] = "http://0.0.0.0:4319",
            ["BOWER_INGEST_TOKEN_FILE"] = tokenFile,
            ["BOWER_QUEUE_RETENTION_HOURS"] = "48",
            ["BOWER_AZURE_CREDENTIAL"] = "workload-identity"
        };

        CollectorSettings settings = CollectorSettings.FromEnvironment(
            name => environment.GetValueOrDefault(name));

        Assert.Equal(Token, settings.IngestToken);
        Assert.Equal(TimeSpan.FromHours(48), settings.DeliveredRetention);
        Assert.Equal(AzureCredentialMode.WorkloadIdentity, settings.AzureCredential);
    }

    [Fact]
    public async Task Ingest_ReportsSuppressionAndStatusShowsPipelineAndExpectedSources()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string policies = Path.Combine(directory.Path, "policies");
        Directory.CreateDirectory(policies);
        File.WriteAllText(Path.Combine(policies, "auth.yaml"), SuppressionTests.SuppressingPolicy);
        File.WriteAllText(Path.Combine(policies, "summary.yaml"), SuppressionTests.SummaryPolicy);
        string expectations = Path.Combine(directory.Path, "sources.json");
        File.WriteAllText(
            expectations,
            """
            {"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
              {"application":"TestApplication","environment":"test","maximumSilenceMinutes":5},
              {"application":"Payroll","environment":"production","maximumSilenceMinutes":5}]}
            """);
        await using WebApplication app = await StartAsync(
            directory,
            Token,
            cancellationToken,
            settings => settings with { PolicyDirectory = policies, SourceExpectationsPath = expectations });
        HttpClient client = app.GetTestClient();

        List<string> bodies = [];
        for (int index = 0; index < 3; index++)
        {
            using HttpRequestMessage request = Post(
                AuthenticationFailure() with { EventOriginalId = $"original-{index}" },
                Token);
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(cancellationToken));
        }

        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        statusRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage statusResponse = await client.SendAsync(statusRequest, cancellationToken);
        using JsonDocument status = JsonDocument.Parse(await statusResponse.Content.ReadAsStringAsync(cancellationToken));
        JsonElement pipeline = status.RootElement.GetProperty("pipeline");
        JsonElement sources = status.RootElement.GetProperty("sources");

        Assert.DoesNotContain("\"suppressed\"", bodies[0], StringComparison.Ordinal);
        Assert.Contains("\"suppressed\":true", bodies[2], StringComparison.Ordinal);
        Assert.Equal(3, pipeline.GetProperty("eventsIn").GetInt64());
        Assert.Equal(2, pipeline.GetProperty("eventsQueued").GetInt64());
        Assert.Equal(1, pipeline.GetProperty("suppressed").GetInt64());
        Assert.Equal(2, sources.GetArrayLength());
        Assert.Equal("active", sources[0].GetProperty("state").GetString());
        Assert.Equal("TestApplication", sources[0].GetProperty("application").GetString());
        Assert.Equal(JsonValueKind.Null, sources[1].GetProperty("lastSeenAt").ValueKind);
    }

    [Fact]
    public async Task SourceHealth_NeverSeenDeadlineSurvivesCollectorRestart()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        string expectations = Path.Combine(directory.Path, "sources.json");
        File.WriteAllText(
            expectations,
            """
            {"apiVersion":"bower.security/v1","kind":"SourceExpectations","sources":[
              {"application":"Payroll","environment":"production","maximumSilenceMinutes":1}]}
            """);
        CollectorSettings Adjust(CollectorSettings settings) => settings with { SourceExpectationsPath = expectations };

        await using (WebApplication first = await StartAsync(directory, Token, cancellationToken, Adjust, clock))
        {
            Assert.Equal(("pending", 0L, "healthy"), await SourceStateAsync(first, cancellationToken));
            clock.Advance(TimeSpan.FromMinutes(2));
            Assert.Equal(("never-seen", 120L, "degraded"), await SourceStateAsync(first, cancellationToken));
        }

        for (int restart = 1; restart <= 3; restart++)
        {
            await using WebApplication restarted = await StartAsync(directory, Token, cancellationToken, Adjust, clock);
            Assert.Equal(
                ("never-seen", 120L + ((restart - 1) * 30), "degraded"),
                await SourceStateAsync(restarted, cancellationToken));
            clock.Advance(TimeSpan.FromSeconds(30));
        }
    }

    private static async Task<(string? State, long SilentSeconds, string? Health)> SourceStateAsync(
        WebApplication app,
        CancellationToken cancellationToken)
    {
        HttpClient client = app.GetTestClient();
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        using JsonDocument status = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        using JsonDocument health = JsonDocument.Parse(await client.GetStringAsync("/health", cancellationToken));
        JsonElement source = Assert.Single(status.RootElement.GetProperty("sources").EnumerateArray());
        Assert.Equal(JsonValueKind.Null, source.GetProperty("lastSeenAt").ValueKind);
        return (
            source.GetProperty("state").GetString(),
            source.GetProperty("silentSeconds").GetInt64(),
            health.RootElement.GetProperty("status").GetString());
    }

    private static async Task<WebApplication> StartAsync(
        TemporaryDirectory directory,
        string? token,
        CancellationToken cancellationToken,
        Func<CollectorSettings, CollectorSettings>? adjust = null,
        TimeProvider? clock = null,
        IEventRedactor? redactor = null)
    {
        CollectorSettings settings = BaseSettings(directory.Path) with { IngestToken = token };
        settings = adjust?.Invoke(settings) ?? settings;
        WebApplication app = CollectorApplication.Build(
            settings,
            builder =>
            {
                builder.WebHost.UseTestServer();
                if (redactor is not null) builder.Services.AddSingleton(redactor);
                if (clock is not null)
                {
                    builder.Services.AddSingleton(clock);
                }
            });
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    private static CollectorSettings BaseSettings(string directory) =>
        new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "collector-test",
            SingleTrustDomain = true
        };

    private static HttpRequestMessage Post(SecurityEventEnvelope candidate, string token)
    {
        HttpRequestMessage request = new(HttpMethod.Post, "/v1/events")
        {
            Content = JsonContent.Create(candidate, options: BowerJson.Options)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static SecurityEventEnvelope AuthenticationFailure() =>
        TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, eventId: TestEvents.UniqueEventId());
}

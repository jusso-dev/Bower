using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Collector;
using Bower.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;

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
        Assert.Contains("redactandaccept", body, StringComparison.Ordinal);
        Assert.DoesNotContain("never-persist", body, StringComparison.Ordinal);
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
        Assert.Contains("queue-retention", statusBody, StringComparison.Ordinal);
        Assert.Contains("queue-maintenance", statusBody, StringComparison.Ordinal);
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

    private static async Task<WebApplication> StartAsync(
        TemporaryDirectory directory,
        string? token,
        CancellationToken cancellationToken,
        Func<CollectorSettings, CollectorSettings>? adjust = null)
    {
        CollectorSettings settings = BaseSettings(directory.Path) with { IngestToken = token };
        settings = adjust?.Invoke(settings) ?? settings;
        WebApplication app = CollectorApplication.Build(
            settings,
            builder => builder.WebHost.UseTestServer());
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
            CollectorId = "collector-test"
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
        TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, eventId: Guid.NewGuid().ToString());
}

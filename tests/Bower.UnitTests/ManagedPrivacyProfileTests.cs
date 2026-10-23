using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Azure.Core;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Integrity;
using Bower.Jobs;
using Bower.Persistence;
using Bower.Redaction.Privacy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class ManagedPrivacyProfileTests
{
    private const string CollectorId = "collector-test";
    private const string Token = "test-ingest-token-0123456789abcdef0123456789";
    private const string DeploymentPath = "/api/collectors/collector-test/privacy-profile/deployment";
    private static readonly byte[] HmacKey = new byte[32];

    [Fact]
    public void Settings_ValidateManagedSource()
    {
        using TemporaryDirectory directory = new();
        CollectorSettings managed = Settings(directory, "trusted.pem");

        managed.Validate();
        Assert.Contains(
            "must be local or management",
            Assert.Throws<InvalidOperationException>((managed with { PrivacyProfileSource = "remote" }).Validate).Message,
            StringComparison.Ordinal);
        Assert.Contains(
            "requires BOWER_MANAGEMENT_ENDPOINT",
            Assert.Throws<InvalidOperationException>((managed with { ManagementEndpoint = null }).Validate).Message,
            StringComparison.Ordinal);
        Assert.Contains(
            "BOWER_MANAGED_PRIVACY_TRUSTED_KEYS",
            Assert.Throws<InvalidOperationException>((managed with { ManagedPrivacyTrustedKeyFiles = [] }).Validate).Message,
            StringComparison.Ordinal);
        Assert.Contains(
            "BOWER_PRIVACY_PROFILE cannot be combined",
            Assert.Throws<InvalidOperationException>((managed with { PrivacyProfilePath = "profile.yaml" }).Validate).Message,
            StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>((managed with { ManagementScope = null }).Validate);
        // Local mode ignores the managed-only settings.
        (managed with { PrivacyProfileSource = PrivacyProfileSources.Local, ManagementEndpoint = null }).Validate();
    }

    [Fact]
    public void Settings_ReadManagedSourceFromEnvironment()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, string> environment = new()
        {
            ["BOWER_QUEUE_PATH"] = Path.Combine(directory.Path, "data", "bower.db"),
            ["BOWER_PRIVACY_PROFILE_SOURCE"] = "Management",
            ["BOWER_MANAGEMENT_ENDPOINT"] = "https://management.example.test",
            ["BOWER_MANAGEMENT_SCOPE"] = "api://bower/.default",
            ["BOWER_MANAGED_PRIVACY_TRUSTED_KEYS"] = "/keys/a.pem, /keys/b.pem"
        };

        CollectorSettings settings = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));
        CollectorSettings custom = CollectorSettings.FromEnvironment(name => name == "BOWER_MANAGED_PRIVACY_DIRECTORY"
            ? "/var/lib/bower/privacy"
            : environment.GetValueOrDefault(name));
        environment["BOWER_PRIVACY_PROFILE_SOURCE"] = "pack";
        InvalidOperationException invalid = Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name)));
        CollectorSettings local = CollectorSettings.FromEnvironment(name => name == "BOWER_PRIVACY_PROFILE_SOURCE"
            ? null
            : environment.GetValueOrDefault(name));

        Assert.True(settings.UsesManagedPrivacyProfile);
        Assert.Equal(["/keys/a.pem", "/keys/b.pem"], settings.ManagedPrivacyTrustedKeyFiles);
        Assert.Equal(Path.Combine(directory.Path, "data", "managed-privacy"), settings.ManagedPrivacyCacheDirectory);
        Assert.Equal("/var/lib/bower/privacy", custom.ManagedPrivacyCacheDirectory);
        Assert.Contains("BOWER_PRIVACY_PROFILE_SOURCE", invalid.Message, StringComparison.Ordinal);
        Assert.Equal(PrivacyProfileSources.Local, local.PrivacyProfileSource);
        // Local configuration hashes are unchanged by the new settings; management mode differs.
        Assert.Equal(local.ConfigurationHash(), (local with { ManagedPrivacyTrustedKeyFiles = [] }).ConfigurationHash());
        Assert.NotEqual(local.ConfigurationHash(), (local with { PrivacyProfileSource = "management" }).ConfigurationHash());
    }

    [Fact]
    public void Bundle_WithoutCacheUsesBuiltInDefaultAndKeepsHashSemantics()
    {
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out _));

        PolicyBundle managed = PolicyBundle.Load(settings);
        PolicyBundle local = PolicyBundle.Load(settings with
        {
            PrivacyProfileSource = PrivacyProfileSources.Local,
            ManagedPrivacyTrustedKeyFiles = []
        });

        Assert.Null(managed.PrivacyProfileHash);
        Assert.Null(managed.PrivacyProfile);
        Assert.Equal(PrivacyProfileSources.Management, managed.PrivacyProfileSource);
        Assert.Equal(local.Hash, managed.Hash);
    }

    [Fact]
    public void Bundle_LoadsVerifiedCacheWithTheSameHashAsALocalProfile()
    {
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem));
        string localProfile = Path.Combine(directory.Path, "profile.yaml");
        File.WriteAllText(localProfile, Content("1.0.0"));

        PolicyBundle managed = PolicyBundle.Load(settings);
        PolicyBundle local = PolicyBundle.Load(settings with
        {
            PrivacyProfileSource = PrivacyProfileSources.Local,
            PrivacyProfilePath = localProfile
        });

        Assert.Equal("contoso-app", managed.PrivacyProfile);
        Assert.Equal("1.0.0", managed.PrivacyProfileVersion);
        Assert.Equal(PrivacyProfileLoader.Load(Content("1.0.0"), HmacKey).Hash, managed.PrivacyProfileHash);
        Assert.Single(managed.Privacy.FieldRules);
        Assert.Equal(local.Hash, managed.Hash);
        Assert.Equal(local.PrivacyProfileHash, managed.PrivacyProfileHash);
    }

    [Theory]
    [InlineData("content")]
    [InlineData("contentHash")]
    [InlineData("signature")]
    [InlineData("collectorId")]
    [InlineData("signed-for-another-collector")]
    [InlineData("signed-wrong-hash")]
    [InlineData("untrusted-key")]
    [InlineData("missing-field")]
    [InlineData("truncated")]
    public void Bundle_TamperedCacheFailsClosed(string tamper)
    {
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Tampered(tamper, privatePem));

        ManagedPrivacyProfileException error = Assert.Throws<ManagedPrivacyProfileException>(() => PolicyBundle.Load(settings));
        Assert.Throws<ManagedPrivacyProfileException>(() => CollectorApplication.Build(
            settings, builder => builder.WebHost.UseTestServer(), credential: new StaticCredential()));

        Assert.Contains("Delete the cache file", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("actor.username", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Bundle_RejectsPackPrivacyProfileInManagedMode()
    {
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string pack = Bower.Packs.PackArchive.Build(
            Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway"), privatePem, directory.Path);
        string packKey = Path.Combine(directory.Path, "pack.pem");
        File.WriteAllText(packKey, publicPem);
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out _)) with
        {
            Packs = [pack],
            PackTrustedKeyFiles = [packKey]
        };

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PolicyBundle.Load(settings));
        Assert.Contains("pack privacy profiles", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_ReportsManagedPrivacyProfileInStatusAndRegistersSyncJob()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem)) with
        {
            IngestToken = Token
        };
        WriteCache(settings, Document(privatePem));
        await using WebApplication app = CollectorApplication.Build(
            settings, builder => builder.WebHost.UseTestServer(), credential: new StaticCredential());
        await CollectorApplication.InitializeAsync(app, ct);
        await app.StartAsync(ct);
        using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        string status = await (await app.GetTestClient().SendAsync(request, ct)).Content.ReadAsStringAsync(ct);

        string hash = PrivacyProfileLoader.Load(Content("1.0.0"), HmacKey).Hash;
        Assert.Contains("\"privacyProfile\":\"contoso-app\"", status, StringComparison.Ordinal);
        Assert.Contains("\"privacyProfileVersion\":\"1.0.0\"", status, StringComparison.Ordinal);
        Assert.Contains($"\"privacyProfileHash\":\"{hash}\"", status, StringComparison.Ordinal);
        Assert.Contains("\"privacyProfileSource\":\"management\"", status, StringComparison.Ordinal);
        Assert.Contains($"\"id\":\"{ManagedPrivacyProfileJob.Id}\"", status, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sync_SameHashIsANoOp()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] document = Document(privatePem);
        WriteCache(settings, document);
        // Different bytes (new issuedAt), same content hash: nothing to apply.
        byte[] reissued = Document(privatePem, issuedAt: "2026-10-24T09:00:00.0000000Z");
        Harness harness = new(settings, _ => Ok(reissued));

        await harness.Job.RunAsync(ct);

        Assert.Equal(document, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, harness.Lifetime.StopCalls);
        HttpRequestMessage request = Assert.Single(harness.Handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(DeploymentPath, request.RequestUri!.AbsolutePath);
        Assert.Equal(("Bearer", "test-token"), (request.Headers.Authorization!.Scheme, request.Headers.Authorization.Parameter));
    }

    [Fact]
    public async Task Sync_NewVersionIsStagedAtomicallyThenRestarts()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem));
        byte[] next = Document(privatePem, Content("1.1.0"), versionId: "11111111111111111111111111111111");
        Harness harness = new(settings, _ => Ok(next));

        await harness.Job.RunAsync(ct);

        Assert.Equal(next, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(1, harness.Lifetime.StopCalls);
        Assert.Equal(
            [ManagedPrivacyProfileCache.CacheFileName],
            Directory.GetFiles(settings.ManagedPrivacyCacheDirectory, "*", SearchOption.AllDirectories)
                .Select(Path.GetFileName));
        // The staged cache is what the restarted host verifies and loads.
        Assert.Equal("1.1.0", PolicyBundle.Load(settings).PrivacyProfileVersion);
    }

    [Fact]
    public async Task Sync_FirstAssignmentOnDefaultProfileIsStaged()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] document = Document(privatePem);
        Harness harness = new(settings, _ => Ok(document));

        await harness.Job.RunAsync(ct);

        Assert.Equal(document, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(1, harness.Lifetime.StopCalls);
    }

    [Theory]
    [InlineData("content")]
    [InlineData("signature")]
    [InlineData("signed-for-another-collector")]
    [InlineData("signed-wrong-hash")]
    [InlineData("signed-invalid-content")]
    [InlineData("untrusted-key")]
    [InlineData("truncated")]
    public async Task Sync_UnverifiedContentIsNeverWritten(string tamper)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] current = Document(privatePem);
        WriteCache(settings, current);
        Harness harness = new(settings, _ => Ok(Tampered(tamper, privatePem, Content("2.0.0"))));

        await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => harness.Job.RunAsync(ct));

        Assert.Equal(current, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Single(Directory.GetFiles(settings.ManagedPrivacyCacheDirectory));
        Assert.Equal(0, harness.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_UnverifiedFirstAssignmentLeavesNoCache()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        Harness harness = new(settings, _ => Ok(Tampered("signature", privatePem)));

        await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => harness.Job.RunAsync(ct));

        Assert.False(Directory.Exists(settings.ManagedPrivacyCacheDirectory));
        Assert.Equal(0, harness.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_NoContentClearsTheCacheAndRestarts()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem));
        Harness cleared = new(settings, _ => new HttpResponseMessage(HttpStatusCode.NoContent));

        await cleared.Job.RunAsync(ct);
        Harness alreadyDefault = new(settings, _ => new HttpResponseMessage(HttpStatusCode.NoContent));
        await alreadyDefault.Job.RunAsync(ct);

        Assert.False(File.Exists(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(1, cleared.Lifetime.StopCalls);
        Assert.Equal(0, alreadyDefault.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_NetworkAndServerFailuresKeepTheCurrentProfile()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] current = Document(privatePem);
        WriteCache(settings, current);
        Harness unreachable = new(settings, _ => throw new HttpRequestException("connection refused"));
        Harness unavailable = new(settings, _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        Harness notActive = new(settings, _ => new HttpResponseMessage(HttpStatusCode.Conflict));
        Harness oversized = new(settings, _ => Ok(new byte[ManagedPrivacyProfileCache.MaximumDocumentBytes + 1]));

        await Assert.ThrowsAsync<HttpRequestException>(() => unreachable.Job.RunAsync(ct));
        await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => unavailable.Job.RunAsync(ct));
        await notActive.Job.RunAsync(ct);
        await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => oversized.Job.RunAsync(ct));

        Assert.Equal(current, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, unreachable.Lifetime.StopCalls + unavailable.Lifetime.StopCalls
            + notActive.Lifetime.StopCalls + oversized.Lifetime.StopCalls);
    }

    [Fact]
    public void AtomicWrite_ReplacesTheFileAndLeavesNoTemporaryFiles()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "nested", ManagedPrivacyProfileCache.CacheFileName);

        ManagedPrivacyProfileCache.WriteAtomically(path, "first"u8);
        ManagedPrivacyProfileCache.WriteAtomically(path, "second"u8);

        Assert.Equal("second", File.ReadAllText(path));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
    }

    [Fact]
    public async Task Heartbeat_ReportsTheActivePrivacyProfileHash()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem));
        PolicyBundle managed = PolicyBundle.Load(settings);
        PolicyBundle local = PolicyBundle.Load(settings with
        {
            PrivacyProfileSource = PrivacyProfileSources.Local,
            ManagedPrivacyTrustedKeyFiles = []
        });

        string managedBody = await HeartbeatBodyAsync(settings, managed, ct);
        string defaultBody = await HeartbeatBodyAsync(settings, local, ct);

        Assert.Contains($"\"privacyProfileHash\":\"{managed.PrivacyProfileHash}\"", managedBody, StringComparison.Ordinal);
        Assert.Contains("\"privacyProfileHash\":\"default\"", defaultBody, StringComparison.Ordinal);
    }

    private static async Task<string> HeartbeatBodyAsync(CollectorSettings settings, PolicyBundle bundle, CancellationToken ct)
    {
        string? body = null;
        RecordingHandler handler = new(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                body = request.Content!.ReadAsStringAsync(ct).GetAwaiter().GetResult();
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        SqliteEventStore store = new(settings.QueuePath, settings.MaximumQueueBytes);
        await store.InitializeAsync(ct);
        ManagementHeartbeatJob job = new(
            new SingleClientFactory(handler),
            new StaticCredential(),
            store,
            new BackgroundJobCatalog(new RecurringJobRegistry()),
            settings,
            bundle,
            NullLogger<ManagementHeartbeatJob>.Instance);

        await job.RunAsync(ct);
        return body ?? throw new InvalidOperationException("No heartbeat was sent.");
    }

    internal static string Content(string version) => PrivacyProfileApiTests.Profile(version);

    private static CollectorSettings Settings(TemporaryDirectory directory, string trustedKeyFile)
    {
        string hmacKey = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(hmacKey, Convert.ToBase64String(HmacKey));
        return new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = CollectorId,
            // Discard port: a scheduled run during a test fails fast without a real server.
            ManagementEndpoint = new Uri("http://127.0.0.1:9"),
            ManagementScope = "api://bower/.default",
            PrivacyProfileSource = PrivacyProfileSources.Management,
            ManagedPrivacyTrustedKeyFiles = [trustedKeyFile],
            PrivacyHmacKeyFile = hmacKey
        };
    }

    private static string WriteTrustedKey(TemporaryDirectory directory, out string privatePem)
    {
        (privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string path = Path.Combine(directory.Path, "managed-privacy-trusted.pem");
        File.WriteAllText(path, publicPem);
        return path;
    }

    private static void WriteCache(CollectorSettings settings, byte[] document)
    {
        Directory.CreateDirectory(settings.ManagedPrivacyCacheDirectory);
        File.WriteAllBytes(ManagedPrivacyProfileCache.CachePath(settings), document);
    }

    private static byte[] Document(
        string privatePem,
        string? content = null,
        string collectorId = CollectorId,
        string? contentHash = null,
        string versionId = "0123456789abcdef0123456789abcdef",
        string issuedAt = "2026-10-24T00:00:00.0000000Z",
        string? signedContent = null)
    {
        content ??= Content("1.0.0");
        LoadedPrivacyProfile? loaded = null;
        try
        {
            loaded = PrivacyProfileLoader.Load(content, HmacKey);
        }
        catch (InvalidDataException)
        {
            // Deliberately invalid content: signed as-is with placeholder metadata.
        }

        string profileId = loaded?.Id ?? "contoso-app";
        string version = loaded?.Version ?? "9.9.9";
        contentHash ??= loaded?.Hash ?? "sha256:" + new string('0', 64);
        DetachedSignature signature = DetachedSigner.Sign(
            ManagedPrivacyProfileCache.SignedBytes(
                collectorId, versionId, profileId, version, contentHash, signedContent ?? content, issuedAt),
            privatePem);
        JsonObject document = new()
        {
            ["collectorId"] = collectorId,
            ["versionId"] = versionId,
            ["profileId"] = profileId,
            ["version"] = version,
            ["contentHash"] = contentHash,
            ["content"] = content,
            ["issuedAt"] = issuedAt,
            ["signature"] = new JsonObject
            {
                ["algorithm"] = signature.Algorithm,
                ["keyId"] = signature.KeyId,
                ["value"] = signature.Value
            }
        };
        return Encoding.UTF8.GetBytes(document.ToJsonString());
    }

    private static byte[] Tampered(string tamper, string privatePem, string? content = null)
    {
        content ??= Content("1.0.0");
        byte[] valid = Document(privatePem, content);
        JsonObject Mutate(Action<JsonObject> change)
        {
            JsonObject document = JsonNode.Parse(valid)!.AsObject();
            change(document);
            return document;
        }

        JsonObject? mutated = tamper switch
        {
            "content" => Mutate(document => document["content"] = content.Replace("remove", "allow", StringComparison.Ordinal)),
            "contentHash" => Mutate(document => document["contentHash"] = "sha256:" + new string('a', 64)),
            "signature" => Mutate(document => document["signature"]!["value"] =
                Convert.ToBase64String(new byte[64])),
            "collectorId" => Mutate(document => document["collectorId"] = "collector-other"),
            "missing-field" => Mutate(document => document.Remove("issuedAt")),
            _ => null
        };
        if (mutated is not null)
        {
            return Encoding.UTF8.GetBytes(mutated.ToJsonString());
        }

        return tamper switch
        {
            "signed-for-another-collector" => Document(privatePem, content, collectorId: "collector-other"),
            "signed-wrong-hash" => Document(privatePem, content, contentHash: "sha256:" + new string('b', 64)),
            "signed-invalid-content" => Document(
                privatePem, content.Replace("id.email", "not-a-detector", StringComparison.Ordinal)),
            "untrusted-key" => Document(DetachedSigner.GenerateKeyPair().PrivateKeyPem, content),
            "truncated" => valid[..(valid.Length / 2)],
            _ => throw new ArgumentOutOfRangeException(nameof(tamper), tamper, null)
        };
    }

    private static HttpResponseMessage Ok(byte[] body) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    private sealed class Harness
    {
        public Harness(CollectorSettings settings, Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            Handler = new RecordingHandler(respond);
            Job = new ManagedPrivacyProfileJob(
                new SingleClientFactory(Handler),
                new StaticCredential(),
                settings,
                PolicyBundle.Load(settings),
                Lifetime,
                NullLogger<ManagedPrivacyProfileJob>.Instance);
        }

        public RecordingHandler Handler { get; }

        public RecordingLifetime Lifetime { get; } = new();

        public ManagedPrivacyProfileJob Job { get; }
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://management.example.test/") };
    }

    private sealed class RecordingLifetime : IHostApplicationLifetime
    {
        public int StopCalls { get; private set; }

        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication() => StopCalls++;
    }

    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("test-token", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}

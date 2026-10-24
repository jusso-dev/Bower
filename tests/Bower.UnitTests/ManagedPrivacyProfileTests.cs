using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Azure.Core;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Integrity;
using Bower.Jobs;
using Bower.Packs;
using Bower.Persistence;
using Bower.Redaction.Privacy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
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

        PolicyBundle managed = PolicyBundle.Load(settings.PolicySources());
        PolicyBundle local = PolicyBundle.Load((settings with
        {
            PrivacyProfileSource = PrivacyProfileSources.Local,
            ManagedPrivacyTrustedKeyFiles = []
        }).PolicySources());

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

        PolicyBundle managed = PolicyBundle.Load(settings.PolicySources());
        PolicyBundle local = PolicyBundle.Load((settings with
        {
            PrivacyProfileSource = PrivacyProfileSources.Local,
            PrivacyProfilePath = localProfile
        }).PolicySources());

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

        ManagedPrivacyProfileException error = Assert.Throws<ManagedPrivacyProfileException>(() => PolicyBundle.Load(settings.PolicySources()));
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

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => PolicyBundle.Load(settings.PolicySources()));
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
    public async Task Sync_SameRevisionWithTheSameSignedFieldsIsANoOp()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] document = Document(privatePem);
        WriteCache(settings, document);
        // Re-signed (ECDSA signatures differ every time) but the same signed fields.
        byte[] refetched = Document(privatePem);
        Assert.NotEqual(document, refetched);
        Harness harness = new(settings, _ => Ok(refetched));

        await harness.Job.RunAsync(ct);

        Assert.Equal(document, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, harness.Lifetime.StopCalls);
        Assert.Equal(ManagedPrivacyProfileState.Assigned, harness.State.State);
        Assert.Equal(1, harness.State.Revision);
        HttpRequestMessage request = Assert.Single(harness.Handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(DeploymentPath, request.RequestUri!.AbsolutePath);
        Assert.Equal(("Bearer", "test-token"), (request.Headers.Authorization!.Scheme, request.Headers.Authorization.Parameter));
    }

    [Theory]
    [InlineData("issuedAt")]
    [InlineData("content")]
    [InlineData("cleared")]
    public async Task Sync_SameRevisionWithDifferentSignedFieldsIsRejected(string difference)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] current = Document(privatePem, revision: 4);
        WriteCache(settings, current);
        byte[] conflicting = difference switch
        {
            "issuedAt" => Document(privatePem, revision: 4, issuedAt: "2026-10-24T09:00:00.0000000Z"),
            "content" => Document(privatePem, Content("3.0.0"), revision: 4),
            _ => ClearedDocument(privatePem, 4)
        };
        Harness harness = new(settings, _ => Ok(conflicting));

        ManagedPrivacyProfileException error =
            await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => harness.Job.RunAsync(ct));

        Assert.Equal(
            "Managed privacy profile assignment revision 4 does not match the cached document.", error.Message);
        Assert.Equal(current, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, harness.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_NewVersionIsStagedAtomicallyThenRestarts()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem));
        byte[] next = Document(privatePem, Content("1.1.0"), versionId: "11111111111111111111111111111111", revision: 2);
        Harness harness = new(settings, _ => Ok(next));

        await harness.Job.RunAsync(ct);

        Assert.Equal(next, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(1, harness.Lifetime.StopCalls);
        Assert.Equal((ManagedPrivacyProfileState.RestartPending, 2L), (harness.State.State, harness.State.Revision));
        // Exit 75, not 0, so Restart=on-failure supervisors bring the collector back.
        Assert.True(ManagedPrivacyProfileJob.RestartRequested);
        Assert.Equal(
            [ManagedPrivacyProfileCache.CacheFileName],
            Directory.GetFiles(settings.ManagedPrivacyCacheDirectory, "*", SearchOption.AllDirectories)
                .Select(Path.GetFileName));
        // The staged cache is what the restarted host verifies and loads.
        Assert.Equal("1.1.0", PolicyBundle.Load(settings.PolicySources()).PrivacyProfileVersion);
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
    [InlineData("revision")]
    [InlineData("revision-zero")]
    [InlineData("revision-string")]
    [InlineData("missing-revision")]
    [InlineData("action")]
    [InlineData("unknown-action")]
    [InlineData("unsigned-extra-field")]
    [InlineData("cleared-with-profile-fields")]
    [InlineData("cleared-for-another-collector")]
    public async Task Sync_UnverifiedContentIsNeverWritten(string tamper)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] current = Document(privatePem);
        WriteCache(settings, current);
        // A newer revision, so only verification (not the high-water mark) can reject it.
        Harness harness = new(settings, _ => Ok(Tampered(tamper, privatePem, Content("2.0.0"), revision: 2)));

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

    [Theory]
    [InlineData("assigned")]
    [InlineData("cleared")]
    public async Task Sync_UnsignedNoContentNeverRemovesAVerifiedCache(string cachedAction)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] current = cachedAction == "assigned" ? Document(privatePem, revision: 3) : ClearedDocument(privatePem, 3);
        WriteCache(settings, current);
        Harness unsigned = new(settings, _ => new HttpResponseMessage(HttpStatusCode.NoContent));

        ManagedPrivacyProfileException error =
            await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => unsigned.Job.RunAsync(ct));

        Assert.Contains("204", error.Message, StringComparison.Ordinal);
        Assert.Equal(current, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, unsigned.Lifetime.StopCalls);
        Assert.True(unsigned.State.AcceptsEvents);
        Assert.Equal(cachedAction == "assigned" ? "1.0.0" : null, new Harness(settings, _ => Ok([])).Bundle.PrivacyProfileVersion);
    }

    [Fact]
    public async Task Sync_OlderSignedAssignmentIsRejected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] current = Document(privatePem, Content("2.0.0"), revision: 5);
        WriteCache(settings, current);
        // Codex probe: a validly signed older version with a forged-looking issuedAt.
        Harness rollback = new(settings, _ => Ok(Document(
            privatePem, Content("1.0.0"), issuedAt: "2000-01-01T00:00:00.0000000Z", revision: 4)));

        ManagedPrivacyProfileException error =
            await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => rollback.Job.RunAsync(ct));

        Assert.Equal(
            "Managed privacy profile assignment revision 4 is older than the cached revision 5.", error.Message);
        Assert.Equal(current, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, rollback.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_ReplayAfterRestartIsRejected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] old = Document(privatePem, Content("1.0.0"), revision: 1);
        byte[] current = Document(privatePem, Content("2.0.0"), revision: 2);
        WriteCache(settings, old);
        Harness first = new(settings, _ => Ok(current));
        await first.Job.RunAsync(ct);
        Assert.Equal(1, first.Lifetime.StopCalls);

        // The restarted process loads the high-water mark from the cache.
        Harness restarted = new(settings, _ => Ok(old));
        await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => restarted.Job.RunAsync(ct));

        Assert.Equal("2.0.0", restarted.Bundle.PrivacyProfileVersion);
        Assert.Equal(current, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, restarted.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_SignedClearIsPersistedAndReplayAfterClearIsRejected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        byte[] assigned = Document(privatePem, Content("2.0.0"), revision: 5);
        byte[] cleared = ClearedDocument(privatePem, 6);
        WriteCache(settings, assigned);

        Harness clearing = new(settings, _ => Ok(cleared));
        await clearing.Job.RunAsync(ct);
        Harness restarted = new(settings, _ => Ok(assigned));
        ManagedPrivacyProfileException replay =
            await Assert.ThrowsAsync<ManagedPrivacyProfileException>(() => restarted.Job.RunAsync(ct));

        Assert.Equal(1, clearing.Lifetime.StopCalls);
        Assert.Equal(cleared, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        // A cached explicit clear means the built-in default privacy profile.
        Assert.Null(restarted.Bundle.PrivacyProfileHash);
        Assert.Equal((ManagedPrivacyProfileState.Cleared, 6L), (restarted.State.State, restarted.State.Revision));
        Assert.True(restarted.State.AcceptsEvents);
        Assert.Contains("revision 5 is older than the cached revision 6", replay.Message, StringComparison.Ordinal);
        Assert.Equal(0, restarted.Lifetime.StopCalls);
    }

    [Fact]
    public async Task Sync_NewlySignedExplicitRollbackIsAccepted()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem, Content("2.0.0"), revision: 5));
        // An administrator re-assigns the older version: a new, higher revision.
        byte[] rollback = Document(privatePem, Content("1.0.0"), revision: 7);
        Harness harness = new(settings, _ => Ok(rollback));

        await harness.Job.RunAsync(ct);

        Assert.Equal(rollback, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(1, harness.Lifetime.StopCalls);
        Assert.Equal("1.0.0", new Harness(settings, _ => Ok([])).Bundle.PrivacyProfileVersion);
    }

    [Fact]
    public async Task Sync_NewerRevisionThatKeepsTheActiveProtectionIsRecordedWithoutRestart()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));
        WriteCache(settings, Document(privatePem, revision: 1));
        byte[] reassigned = Document(privatePem, revision: 3, issuedAt: "2026-10-24T05:00:00.0000000Z");
        Harness harness = new(settings, _ => Ok(reassigned));

        await harness.Job.RunAsync(ct);

        Assert.Equal(reassigned, File.ReadAllBytes(ManagedPrivacyProfileCache.CachePath(settings)));
        Assert.Equal(0, harness.Lifetime.StopCalls);
        Assert.Equal((ManagedPrivacyProfileState.Assigned, 3L), (harness.State.State, harness.State.Revision));
    }

    [Fact]
    public async Task FirstSync_WithoutCacheGatesIngestUntilResolved()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem));

        Harness unreachable = new(settings, _ => throw new HttpRequestException("connection refused"));
        await Assert.ThrowsAsync<HttpRequestException>(() => unreachable.Job.RunAsync(ct));
        Harness notActive = new(settings, _ => new HttpResponseMessage(HttpStatusCode.Conflict));
        await notActive.Job.RunAsync(ct);
        Harness neverAssigned = new(settings, _ => new HttpResponseMessage(HttpStatusCode.NoContent));
        Assert.False(neverAssigned.State.AcceptsEvents);
        await neverAssigned.Job.RunAsync(ct);
        Harness clearedBeforeFirstSync = new(settings, _ => Ok(ClearedDocument(privatePem, 2)));
        await clearedBeforeFirstSync.Job.RunAsync(ct);
        File.Delete(ManagedPrivacyProfileCache.CachePath(settings));
        Harness assigned = new(settings, _ => Ok(Document(privatePem)));
        await assigned.Job.RunAsync(ct);

        Assert.Equal((ManagedPrivacyProfileState.AwaitingFirstSync, false), (unreachable.State.State, unreachable.State.AcceptsEvents));
        Assert.Equal((ManagedPrivacyProfileState.AwaitingFirstSync, false), (notActive.State.State, notActive.State.AcceptsEvents));
        Assert.Equal((ManagedPrivacyProfileState.NeverAssigned, true), (neverAssigned.State.State, neverAssigned.State.AcceptsEvents));
        // Cleared before the first sync: the default is already running, no restart needed.
        Assert.Equal((ManagedPrivacyProfileState.Cleared, true), (clearedBeforeFirstSync.State.State, clearedBeforeFirstSync.State.AcceptsEvents));
        Assert.Equal(0, clearedBeforeFirstSync.Lifetime.StopCalls);
        // A first assignment is staged; ingest stays closed until the restart applies it.
        Assert.Equal((ManagedPrivacyProfileState.RestartPending, false), (assigned.State.State, assigned.State.AcceptsEvents));
        Assert.Equal(1, assigned.Lifetime.StopCalls);
    }

    [Fact]
    public async Task FirstSync_AllowDefaultOptInAcceptsBeforeResolution()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out _)) with
        {
            ManagedPrivacyAllowDefault = true
        };
        Harness harness = new(settings, _ => new HttpResponseMessage(HttpStatusCode.Conflict));

        await harness.Job.RunAsync(ct);

        Assert.Equal((ManagedPrivacyProfileState.DefaultAllowed, true), (harness.State.State, harness.State.AcceptsEvents));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Host_GatesIngestInManagementModeUntilTheProfileResolves(bool allowDefault, bool cached)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out string privatePem)) with
        {
            IngestToken = Token,
            SingleTrustDomain = true,
            ManagedPrivacyAllowDefault = allowDefault
        };
        if (cached)
        {
            WriteCache(settings, Document(privatePem, revision: 9));
        }

        await using WebApplication app = CollectorApplication.Build(
            settings, builder => builder.WebHost.UseTestServer(), credential: new StaticCredential());
        await CollectorApplication.InitializeAsync(app, ct);
        await app.StartAsync(ct);
        HttpClient client = app.GetTestClient();

        using HttpResponseMessage first = await client.SendAsync(Event(), ct);
        using HttpResponseMessage pack = await client.SendAsync(
            Authorized(new HttpRequestMessage(HttpMethod.Post, "/v1/packs/none/parsers/0/events")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            }), ct);
        using HttpResponseMessage unauthenticated = await client.PostAsync(
            "/v1/events", new StringContent("{}", Encoding.UTF8, "application/json"), ct);
        string status = await (await client.SendAsync(Authorized(new HttpRequestMessage(HttpMethod.Get, "/v1/status")), ct))
            .Content.ReadAsStringAsync(ct);
        app.Services.GetRequiredService<ManagedPrivacyProfileState>().MarkNeverAssigned();
        using HttpResponseMessage afterResolution = await client.SendAsync(Event(), ct);

        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        if (allowDefault || cached)
        {
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
            Assert.Contains(
                cached ? "\"managedPrivacyProfileState\":\"assigned\"" : "\"managedPrivacyProfileState\":\"default-allowed\"",
                status,
                StringComparison.Ordinal);
            Assert.Contains(cached ? "\"managedPrivacyProfileRevision\":9" : "\"managedPrivacyProfileRevision\":null", status, StringComparison.Ordinal);
            return;
        }

        Assert.Equal(HttpStatusCode.ServiceUnavailable, first.StatusCode);
        Assert.Equal("30", first.Headers.GetValues("Retry-After").Single());
        Assert.Contains(
            "Collector is waiting for its managed privacy profile from management; retry later.",
            await first.Content.ReadAsStringAsync(ct),
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, pack.StatusCode);
        Assert.Contains("\"managedPrivacyProfileState\":\"awaiting-first-sync\"", status, StringComparison.Ordinal);
        Assert.Contains("\"queued\":0", status, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Accepted, afterResolution.StatusCode);
    }

    [Fact]
    public async Task Host_RunsTheFirstSyncImmediatelyAtStartup()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        CollectorSettings settings = Settings(directory, WriteTrustedKey(directory, out _));
        await using WebApplication app = CollectorApplication.Build(
            settings, builder => builder.WebHost.UseTestServer(), credential: new StaticCredential());
        await CollectorApplication.InitializeAsync(app, ct);
        await app.StartAsync(ct);
        BackgroundJobCatalog jobs = app.Services.GetRequiredService<BackgroundJobCatalog>();

        // The discard-port endpoint refuses the connection, so the run fails fast; what
        // matters is that it ran without waiting for the next minute boundary.
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (jobs.List().Single(job => job.Id == ManagedPrivacyProfileJob.Id).LastRunAt is null
            && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(50, ct);
        }

        Assert.NotNull(jobs.List().Single(job => job.Id == ManagedPrivacyProfileJob.Id).LastRunAt);
    }

    private static HttpRequestMessage Authorized(HttpRequestMessage request)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return request;
    }

    private static HttpRequestMessage Event() =>
        Authorized(new HttpRequestMessage(HttpMethod.Post, "/v1/events")
        {
            Content = System.Net.Http.Json.JsonContent.Create(
                TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, eventId: Guid.NewGuid().ToString()),
                options: Bower.Contracts.BowerJson.Options)
        });

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
        PolicyBundle managed = PolicyBundle.Load(settings.PolicySources());
        PolicyBundle local = PolicyBundle.Load((settings with
        {
            PrivacyProfileSource = PrivacyProfileSources.Local,
            ManagedPrivacyTrustedKeyFiles = []
        }).PolicySources());

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
        string? signedContent = null,
        long revision = 1)
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
                collectorId, revision, "assigned", versionId, profileId, version, contentHash,
                signedContent ?? content, issuedAt),
            privatePem);
        JsonObject document = new()
        {
            ["collectorId"] = collectorId,
            ["assignmentRevision"] = revision,
            ["action"] = "assigned",
            ["versionId"] = versionId,
            ["profileId"] = profileId,
            ["version"] = version,
            ["contentHash"] = contentHash,
            ["content"] = content,
            ["issuedAt"] = issuedAt,
            ["signature"] = Signature(signature)
        };
        return Encoding.UTF8.GetBytes(document.ToJsonString());
    }

    /// <summary>A signed explicit clear: no profile fields.</summary>
    private static byte[] ClearedDocument(
        string privatePem,
        long revision,
        string collectorId = CollectorId,
        string issuedAt = "2026-10-24T01:00:00.0000000Z")
    {
        DetachedSignature signature = DetachedSigner.Sign(
            ManagedPrivacyProfileCache.SignedBytes(
                collectorId, revision, "cleared", null, null, null, null, null, issuedAt),
            privatePem);
        JsonObject document = new()
        {
            ["collectorId"] = collectorId,
            ["assignmentRevision"] = revision,
            ["action"] = "cleared",
            ["issuedAt"] = issuedAt,
            ["signature"] = Signature(signature)
        };
        return Encoding.UTF8.GetBytes(document.ToJsonString());
    }

    private static JsonObject Signature(DetachedSignature signature) => new()
    {
        ["algorithm"] = signature.Algorithm,
        ["keyId"] = signature.KeyId,
        ["value"] = signature.Value
    };

    private static byte[] Tampered(string tamper, string privatePem, string? content = null, long revision = 1)
    {
        content ??= Content("1.0.0");
        byte[] valid = Document(privatePem, content, revision: revision);
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
            "revision" => Mutate(document => document["assignmentRevision"] = revision + 100),
            "revision-zero" => Mutate(document => document["assignmentRevision"] = 0),
            "revision-string" => Mutate(document => document["assignmentRevision"] = revision.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            "missing-revision" => Mutate(document => document.Remove("assignmentRevision")),
            "action" => Mutate(document => document["action"] = "cleared"),
            "unknown-action" => Mutate(document => document["action"] = "rollback"),
            "unsigned-extra-field" => Mutate(document => document["note"] = "not signed"),
            _ => null
        };
        if (mutated is not null)
        {
            return Encoding.UTF8.GetBytes(mutated.ToJsonString());
        }

        return tamper switch
        {
            "signed-for-another-collector" => Document(privatePem, content, collectorId: "collector-other", revision: revision),
            "signed-wrong-hash" => Document(privatePem, content, contentHash: "sha256:" + new string('b', 64), revision: revision),
            "signed-invalid-content" => Document(
                privatePem, content.Replace("id.email", "not-a-detector", StringComparison.Ordinal), revision: revision),
            "untrusted-key" => Document(DetachedSigner.GenerateKeyPair().PrivateKeyPem, content, revision: revision),
            "cleared-with-profile-fields" => ClearedWithProfileFields(privatePem, revision),
            "cleared-for-another-collector" => ClearedDocument(privatePem, revision, collectorId: "collector-other"),
            "truncated" => valid[..(valid.Length / 2)],
            _ => throw new ArgumentOutOfRangeException(nameof(tamper), tamper, null)
        };
    }

    /// <summary>A validly signed clear with unsigned profile fields smuggled in.</summary>
    private static byte[] ClearedWithProfileFields(string privatePem, long revision)
    {
        JsonObject document = JsonNode.Parse(ClearedDocument(privatePem, revision))!.AsObject();
        document["content"] = Content("9.0.0");
        return Encoding.UTF8.GetBytes(document.ToJsonString());
    }

    private static HttpResponseMessage Ok(byte[] body) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    /// <summary>
    /// One collector process: the bundle and ingest gate are loaded from the cache as at
    /// start-up, so a new harness over the same settings models a restart.
    /// </summary>
    private sealed class Harness
    {
        public Harness(
            CollectorSettings settings,
            Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            Handler = new RecordingHandler(respond);
            VerifiedManagedPrivacyProfile? cached = null;
            Bundle = PolicyBundle.Load(settings.PolicySources(observed => cached = observed));
            State = new ManagedPrivacyProfileState(cached, settings.ManagedPrivacyAllowDefault);
            Job = new ManagedPrivacyProfileJob(
                new SingleClientFactory(Handler),
                new StaticCredential(),
                settings,
                Bundle,
                State,
                Lifetime,
                NullLogger<ManagedPrivacyProfileJob>.Instance);
        }

        public PolicyBundle Bundle { get; }

        public ManagedPrivacyProfileState State { get; }

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

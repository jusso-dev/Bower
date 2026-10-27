using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Integrity;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

/// <summary>
/// One-time enrolment tokens and key-bound collector credentials (#109): token lifecycle,
/// Pending approval, credential binding, revocation and rotation without downtime, on the
/// management API and end to end through the collector's heartbeat job.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class EnrolmentTests
{
    private const string CollectorId = "edge-onprem-01";
    private const string Environment = "production";
    private static readonly DateTimeOffset Start = new(2026, 10, 27, 0, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = ManagementApiTests.ApiJson;

    // A Rust-produced assertion (bower-collector `enrolment::create_assertion`) and its key:
    // the C# management API must accept what the Rust collector signs.
    private const string RustPublicKeyPem = RustAssertionVector.PublicKeyPem;

    [Fact]
    public async Task Tokens_AreCreatedByAdministratorsShownOnceAndStoredOnlyAsHashes()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);

        using HttpResponseMessage created = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            "/api/enrolment-tokens", new EnrolmentTokenRequest(Environment, "New on-prem gateway BWR-7"), ct);
        IssuedEnrolmentToken issued = (await created.Content.ReadFromJsonAsync<IssuedEnrolmentToken>(Json, ct))!;
        using HttpResponseMessage asOperator = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
            "/api/enrolment-tokens", new EnrolmentTokenRequest(Environment, "x"), ct);
        using HttpResponseMessage asApprover = await Client(app, BowerRoles.Approver).PostAsJsonAsync(
            "/api/enrolment-tokens", new EnrolmentTokenRequest(Environment, "x"), ct);
        using HttpResponseMessage tooLong = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            "/api/enrolment-tokens", new EnrolmentTokenRequest(Environment, "x", ExpiresInHours: 169), ct);
        string listed = await Client(app, BowerRoles.Viewer).GetStringAsync("/api/enrolment-tokens", ct);
        string audit = await Client(app, BowerRoles.Viewer).GetStringAsync("/api/audit", ct);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.StartsWith("bwe1.", issued.Token, StringComparison.Ordinal);
        Assert.Equal(Start.AddHours(24), issued.Record.ExpiresAt);
        Assert.Equal(EnrolmentTokenStatus.Active, issued.Record.Status);
        Assert.Equal(HttpStatusCode.Forbidden, asOperator.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, asApprover.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        Assert.Contains(issued.Record.Id, listed, StringComparison.Ordinal);
        // Never shown again, and never in the database: only the hash is stored.
        Assert.DoesNotContain(issued.Token, listed, StringComparison.Ordinal);
        Assert.DoesNotContain(issued.Token[22..], listed, StringComparison.Ordinal);
        Assert.Contains("enrolment-token.created", audit, StringComparison.Ordinal);
        Assert.False(DatabaseContains(directory, issued.Token[22..]));
        Assert.True(DatabaseContains(directory, CollectorEnrolment.HashToken(issued.Token)));
    }

    [Fact]
    public async Task Enrolment_LandsInPendingAndTheApprovalFlowIsUnchanged()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        string token = await CreateTokenAsync(app, ct);

        (HttpStatusCode status, IssuedCollectorCredential? issued, string privatePem) = await EnrolAsync(app, token, ct);
        HttpClient collector = Assertion(app, clock, issued!.CredentialId, privatePem);
        using HttpResponseMessage registered = await collector.PostAsJsonAsync(
            "/api/collectors/register", Registration(), ct);
        using HttpResponseMessage pendingHeartbeat = await Heartbeat(collector, ct);
        // Only an approver moves it on; a token is never an approval.
        using HttpResponseMessage approved = await Client(app, BowerRoles.Approver).PostAsJsonAsync(
            $"/api/approvals/{CollectorId}/approve", new ApprovalRequest("Matched server inventory BWR-7"), ct);
        using HttpResponseMessage activeHeartbeat = await Heartbeat(collector, ct);
        CollectorRecord? record = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorRecord>($"/api/collectors/{CollectorId}", Json, ct);
        string audit = await Client(app, BowerRoles.Viewer).GetStringAsync("/api/audit", ct);

        Assert.Equal(HttpStatusCode.Accepted, status);
        Assert.Equal(CollectorStatus.Pending, issued.Status);
        Assert.Equal(DetachedSigner.KeyIdFromPublicKeyPem(PublicKey(privatePem)), issued.CredentialId);
        Assert.Equal(Start + CollectorEnrolment.CredentialLifetime, issued.ExpiresAt);
        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, pendingHeartbeat.StatusCode);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal(HttpStatusCode.OK, activeHeartbeat.StatusCode);
        Assert.Equal(CollectorStatus.Active, record!.Status);
        Assert.Equal("enrolled:" + CollectorId, record.PrincipalObjectId);
        Assert.Contains("collector.enrolled", audit, StringComparison.Ordinal);
        Assert.Contains("enrolment-token.used", audit, StringComparison.Ordinal);
        Assert.Contains("collector.approved", audit, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UsedExpiredRevokedAndForgedTokens_AreRefusedAndAudited()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        string used = await CreateTokenAsync(app, ct);
        string expired = await CreateTokenAsync(app, ct, hours: 1);
        string revoked = await CreateTokenAsync(app, ct);
        string scoped = await CreateTokenAsync(app, ct, collectorId: "edge-other");
        string environment = await CreateTokenAsync(app, ct);
        string revokedId = revoked[5..21];

        (HttpStatusCode first, IssuedCollectorCredential? issued, string key) = await EnrolAsync(app, used, ct);
        // A lost response is retried with the same token, collector and key: the same exchange.
        (HttpStatusCode retried, IssuedCollectorCredential? again, _) = await EnrolAsync(app, used, ct, privatePem: key);
        (HttpStatusCode reused, _, _) = await EnrolAsync(app, used, ct);
        (HttpStatusCode otherCollector, _, _) = await EnrolAsync(app, used, ct, collectorId: "edge-02", privatePem: key);
        using HttpResponseMessage revoke = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            $"/api/enrolment-tokens/{revokedId}/revoke", new ApprovalRequest("Issued by mistake"), ct);
        using HttpResponseMessage revokeAgain = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            $"/api/enrolment-tokens/{revokedId}/revoke", new ApprovalRequest("Again"), ct);
        (HttpStatusCode revokedStatus, _, _) = await EnrolAsync(app, revoked, ct, collectorId: "edge-03");
        (HttpStatusCode wrongCollector, _, _) = await EnrolAsync(app, scoped, ct, collectorId: "edge-04");
        (HttpStatusCode wrongEnvironment, _, _) = await EnrolAsync(app, environment, ct, collectorId: "edge-05", environment: "test");
        (HttpStatusCode malformed, _, _) = await EnrolAsync(app, "not-a-token", ct, collectorId: "edge-06");
        (HttpStatusCode unknown, _, _) = await EnrolAsync(app, CollectorEnrolment.NewToken(out _), ct, collectorId: "edge-07");
        (HttpStatusCode forged, _, _) = await EnrolAsync(app, environment[..22] + new string('A', 43), ct, collectorId: "edge-08");
        clock.Advance(TimeSpan.FromHours(2));
        (HttpStatusCode expiredStatus, _, _) = await EnrolAsync(app, expired, ct, collectorId: "edge-09");
        // Refusals never consume: the environment-bound token still enrols where it belongs.
        (HttpStatusCode rightEnvironment, _, _) = await EnrolAsync(app, environment, ct, collectorId: "edge-05");
        AuditRecord[] audit = (await Client(app, BowerRoles.Viewer).GetFromJsonAsync<AuditRecord[]>("/api/audit", ct))!;
        EnrolmentTokenRecord[] tokens =
            (await Client(app, BowerRoles.Viewer).GetFromJsonAsync<EnrolmentTokenRecord[]>("/api/enrolment-tokens", Json, ct))!;

        Assert.Equal(HttpStatusCode.Accepted, first);
        Assert.Equal(HttpStatusCode.Accepted, retried);
        Assert.Equal(issued!.CredentialId, again!.CredentialId);
        Assert.Equal(HttpStatusCode.Unauthorized, reused);
        Assert.Equal(HttpStatusCode.Unauthorized, otherCollector);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, revokeAgain.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, revokedStatus);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCollector);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongEnvironment);
        Assert.Equal(HttpStatusCode.Unauthorized, malformed);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown);
        Assert.Equal(HttpStatusCode.Unauthorized, forged);
        Assert.Equal(HttpStatusCode.Unauthorized, expiredStatus);
        Assert.Equal(HttpStatusCode.Accepted, rightEnvironment);
        foreach (string code in new[]
                 {
                     EnrolmentRefusals.Used, EnrolmentRefusals.Revoked, EnrolmentRefusals.WrongCollector,
                     EnrolmentRefusals.WrongEnvironment, EnrolmentRefusals.Malformed, EnrolmentRefusals.Unknown,
                     EnrolmentRefusals.Invalid, EnrolmentRefusals.Expired
                 })
        {
            Assert.Contains(audit, item => item.Action == $"enrolment-token.refused:{code}");
        }

        Assert.Equal(2, audit.Count(item => item.Action == $"enrolment-token.refused:{EnrolmentRefusals.Used}"));
        Assert.Contains(audit, item => item.Action == "enrolment-token.revoked" && item.TargetId == revokedId);
        Assert.Equal(EnrolmentTokenStatus.Expired, tokens.Single(item => item.Id == expired[5..21]).Status);
        Assert.Equal(EnrolmentTokenStatus.Revoked, tokens.Single(item => item.Id == revokedId).Status);
        Assert.Equal(EnrolmentTokenStatus.Used, tokens.Single(item => item.Id == used[5..21]).Status);
        Assert.Equal(CollectorId, tokens.Single(item => item.Id == used[5..21]).UsedByCollectorId);
    }

    [Fact]
    public async Task Tokens_CannotTakeOverAnEntraCollectorOrUndoASuspension()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        using HttpResponseMessage entra = await Client(app, BowerRoles.Collector).PostAsJsonAsync(
            "/api/collectors/register", Registration("edge-entra"), ct);
        (HttpStatusCode takeover, _, _) = await EnrolAsync(app, await CreateTokenAsync(app, ct), ct, collectorId: "edge-entra");
        await EnrolAndApproveAsync(app, clock, ct);
        using HttpResponseMessage suspend = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/suspend", new ApprovalRequest("Incident 42"), ct);
        (HttpStatusCode reEnrol, _, _) = await EnrolAsync(app, await CreateTokenAsync(app, ct), ct);
        CollectorRecord? record = await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorRecord>($"/api/collectors/{CollectorId}", Json, ct);
        AuditRecord[] audit = (await Client(app, BowerRoles.Viewer).GetFromJsonAsync<AuditRecord[]>("/api/audit", ct))!;

        Assert.Equal(HttpStatusCode.Accepted, entra.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, takeover);
        Assert.Equal(HttpStatusCode.OK, suspend.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, reEnrol);
        Assert.Equal(CollectorStatus.Suspended, record!.Status);
        Assert.Contains(audit, item => item.Action == $"enrolment-token.refused:{EnrolmentRefusals.IdentityConflict}");
        Assert.Contains(audit, item => item.Action == $"enrolment-token.refused:{EnrolmentRefusals.CollectorNotEnrollable}");
    }

    [Fact]
    public async Task Credentials_AreBoundToTheirCollectorAndRefusedWhenForgedExpiredOrRevoked()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        (string credentialId, string privatePem) = await EnrolAndApproveAsync(app, clock, ct);
        (string otherPrivate, _, _) = DetachedSigner.GenerateKeyPair();
        string valid = ManagementAssertion.Create(CollectorId, credentialId, privatePem, clock.UtcNow);
        char last = valid[^2];
        string tampered = valid[..^2] + (last == 'A' ? 'B' : 'A') + valid[^1];

        using HttpResponseMessage ok = await Heartbeat(Assertion(app, clock, credentialId, privatePem), ct);
        using HttpResponseMessage otherCollector = await Heartbeat(
            Assertion(app, clock, credentialId, privatePem), ct, "edge-someone-else");
        using HttpResponseMessage forged = await Heartbeat(Bearer(app, tampered), ct);
        using HttpResponseMessage wrongKey = await Heartbeat(Assertion(app, clock, credentialId, otherPrivate), ct);
        using HttpResponseMessage stale = await Heartbeat(
            Bearer(app, ManagementAssertion.Create(CollectorId, credentialId, privatePem, clock.UtcNow.AddMinutes(-6))), ct);
        using HttpResponseMessage future = await Heartbeat(
            Bearer(app, ManagementAssertion.Create(CollectorId, credentialId, privatePem, clock.UtcNow.AddMinutes(6))), ct);
        using HttpResponseMessage claimsOther = await Heartbeat(
            Bearer(app, ManagementAssertion.Create("edge-someone-else", credentialId, privatePem, clock.UtcNow)), ct,
            "edge-someone-else");
        // Entra collectors have no credential to rotate.
        using HttpResponseMessage entraRotate = await Client(app, BowerRoles.Collector).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/rotate", new CollectorCredentialRotationRequest(PublicKey(otherPrivate)), ct);
        using HttpResponseMessage revokeAsOperator = await Client(app, BowerRoles.Operator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/{credentialId}/revoke", new ApprovalRequest("x"), ct);
        using HttpResponseMessage revoke = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/{credentialId}/revoke", new ApprovalRequest("Host decommissioned"), ct);
        // Revocation takes effect on the very next heartbeat.
        using HttpResponseMessage afterRevoke = await Heartbeat(Assertion(app, clock, credentialId, privatePem), ct);
        clock.Advance(CollectorEnrolment.CredentialLifetime);
        string audit = await Client(app, BowerRoles.Viewer).GetStringAsync("/api/audit", ct);

        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, otherCollector.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, forged.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongKey.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, future.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, claimsOther.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, entraRotate.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, revokeAsOperator.StatusCode);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, afterRevoke.StatusCode);
        Assert.Contains("collector.credential-revoked", audit, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredCredentials_AreRefused()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        (string credentialId, string privatePem) = await EnrolAndApproveAsync(app, clock, ct);

        clock.Advance(CollectorEnrolment.CredentialLifetime);
        using HttpResponseMessage expired = await Heartbeat(Assertion(app, clock, credentialId, privatePem), ct);
        CollectorCredentialRecord[] credentials = (await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorCredentialRecord[]>($"/api/collector-credentials?collectorId={CollectorId}", Json, ct))!;

        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        Assert.Equal(CollectorCredentialStatus.Expired, Assert.Single(credentials).Status);
    }

    [Fact]
    public async Task Rotation_KeepsTheOldCredentialValidUntilTheNewOneIsUsed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        (string oldId, string oldKey) = await EnrolAndApproveAsync(app, clock, ct);
        (string newKey, string newPublic, string newId) = DetachedSigner.GenerateKeyPair();

        using HttpResponseMessage rotated = await Assertion(app, clock, oldId, oldKey).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/rotate", new CollectorCredentialRotationRequest(newPublic), ct);
        IssuedCollectorCredential issued = (await rotated.Content.ReadFromJsonAsync<IssuedCollectorCredential>(Json, ct))!;
        // Until the collector switches, the old credential keeps working: no downtime.
        using HttpResponseMessage oldStillWorks = await Heartbeat(Assertion(app, clock, oldId, oldKey), ct);
        using HttpResponseMessage resent = await Assertion(app, clock, oldId, oldKey).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/rotate", new CollectorCredentialRotationRequest(newPublic), ct);
        using HttpResponseMessage newWorks = await Heartbeat(Assertion(app, clock, newId, newKey), ct);
        using HttpResponseMessage oldRetired = await Heartbeat(Assertion(app, clock, oldId, oldKey), ct);
        using HttpResponseMessage reuseRetiredKey = await Assertion(app, clock, newId, newKey).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/rotate", new CollectorCredentialRotationRequest(PublicKey(oldKey)), ct);
        CollectorCredentialRecord[] credentials = (await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorCredentialRecord[]>("/api/collector-credentials", Json, ct))!;
        string audit = await Client(app, BowerRoles.Viewer).GetStringAsync("/api/audit", ct);

        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        Assert.Equal(newId, issued.CredentialId);
        Assert.Equal(HttpStatusCode.OK, oldStillWorks.StatusCode);
        Assert.Equal(HttpStatusCode.OK, resent.StatusCode);
        Assert.Equal(HttpStatusCode.OK, newWorks.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, oldRetired.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, reuseRetiredKey.StatusCode);
        Assert.Equal(CollectorCredentialStatus.Retired, credentials.Single(item => item.Id == oldId).Status);
        Assert.Equal(CollectorCredentialStatus.Active, credentials.Single(item => item.Id == newId).Status);
        Assert.Equal("rotation", credentials.Single(item => item.Id == newId).Origin);
        Assert.Contains("collector.credential-rotated", audit, StringComparison.Ordinal);
        Assert.Contains("collector.credential-retired", audit, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Enrolment_IsRateLimitedPerAddress()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(
            directory, new FakeClock(Start), ct, "--BOWER_MANAGEMENT_ENROLMENT_RATE_PER_MINUTE=2");

        HttpStatusCode[] statuses = new HttpStatusCode[3];
        for (int index = 0; index < statuses.Length; index++)
        {
            statuses[index] = (await EnrolAsync(app, "not-a-token", ct)).Status;
        }

        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests], statuses);
    }

    [Fact]
    public async Task Collector_EnrolsReportsRotatesAndReEnrolsThroughTheHeartbeatJob()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        string token = await CreateTokenAsync(app, ct);
        CollectorSettings settings = EnrolmentSettings(directory, token);
        using ManagementEnrolment enrolment = new(
            new TestServerFactory(app), settings, Bower.Packs.PolicyBundle.Load(settings.PolicySources()), clock,
            NullLogger<ManagementEnrolment>.Instance);
        Bower.Persistence.SqliteEventStore store = new(settings.QueuePath, settings.MaximumQueueBytes, clock);
        await store.InitializeAsync(ct);
        ManagementHeartbeatJob job = new(
            new TestServerFactory(app),
            new EnrolledManagementCredential(enrolment, clock),
            store,
            new Bower.Jobs.BackgroundJobCatalog(new Bower.Jobs.RecurringJobRegistry()),
            settings,
            Bower.Packs.PolicyBundle.Load(settings.PolicySources()),
            NullLogger<ManagementHeartbeatJob>.Instance,
            enrolment: enrolment);

        await job.RunAsync(ct);
        CollectorRecord? pending = await GetCollectorAsync(app, ct);
        string credentialFile = Path.Combine(settings.ManagementCredentialDirectory, ManagementCredentialStore.FileName);
        string stored = await File.ReadAllTextAsync(credentialFile, ct);
        string firstCredential = enrolment.State!.CredentialId!;
        using HttpResponseMessage approved = await Client(app, BowerRoles.Approver).PostAsJsonAsync(
            $"/api/approvals/{CollectorId}/approve", new ApprovalRequest("Expected on-prem collector"), ct);
        clock.Advance(TimeSpan.FromMinutes(1));
        await job.RunAsync(ct);
        CollectorRecord? active = await GetCollectorAsync(app, ct);

        // Console- or command-triggered rotation, then the switch.
        (string rotateStatus, string rotateCode) = await enrolment.RotateAsync(ct);
        string secondCredential = enrolment.State!.CredentialId!;
        clock.Advance(TimeSpan.FromMinutes(1));
        await job.RunAsync(ct);
        CollectorRecord? afterRotation = await GetCollectorAsync(app, ct);

        // Scheduled rotation once 10 of the 30 days remain.
        clock.Advance(TimeSpan.FromDays(21));
        await job.RunAsync(ct);
        string thirdCredential = enrolment.State!.CredentialId!;
        clock.Advance(TimeSpan.FromMinutes(1));
        await job.RunAsync(ct);
        CollectorCredentialRecord[] credentials = (await Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<CollectorCredentialRecord[]>("/api/collector-credentials", Json, ct))!;

        // Revocation stops the next heartbeat; a new token re-enrols, back to Pending.
        using HttpResponseMessage revoked = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            $"/api/collectors/{CollectorId}/credentials/{thirdCredential}/revoke", new ApprovalRequest("Rebuild"), ct);
        DateTimeOffset lastSeen = (await GetCollectorAsync(app, ct))!.LastSeenAt;
        clock.Advance(TimeSpan.FromMinutes(1));
        await job.RunAsync(ct);
        DateTimeOffset afterRevocation = (await GetCollectorAsync(app, ct))!.LastSeenAt;
        await File.WriteAllTextAsync(settings.ManagementEnrolmentTokenFile!, await CreateTokenAsync(app, ct) + "\n", ct);
        await job.RunAsync(ct);
        CollectorRecord? reEnrolled = await GetCollectorAsync(app, ct);

        Assert.Equal(CollectorStatus.Pending, pending!.Status);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal(CollectorStatus.Active, active!.Status);
        Assert.Equal(ManagementCommandResults.Succeeded, rotateStatus);
        Assert.Equal(ManagementEnrolment.CredentialRotated, rotateCode);
        Assert.NotEqual(firstCredential, secondCredential);
        Assert.Equal(Start.AddMinutes(2), afterRotation!.LastSeenAt);
        Assert.NotEqual(secondCredential, thirdCredential);
        Assert.Equal(CollectorCredentialStatus.Retired, credentials.Single(item => item.Id == firstCredential).Status);
        Assert.Equal(CollectorCredentialStatus.Retired, credentials.Single(item => item.Id == secondCredential).Status);
        Assert.Equal(CollectorCredentialStatus.Active, credentials.Single(item => item.Id == thirdCredential).Status);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Equal(lastSeen, afterRevocation);
        Assert.Equal(CollectorStatus.Pending, reEnrolled!.Status);
        Assert.NotEqual(thirdCredential, enrolment.State!.CredentialId);
        // The credential file holds the key, never the token; and it is owner-only.
        Assert.DoesNotContain(token, stored, StringComparison.Ordinal);
        Assert.Contains(Sha256Hex.Of(token), stored, StringComparison.Ordinal);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(credentialFile));
        }
    }

    [Fact]
    public async Task Collector_DoesNotRetryARefusedToken()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Start);
        await using WebApplication app = await StartAsync(directory, clock, ct);
        CollectorSettings settings = EnrolmentSettings(directory, CollectorEnrolment.NewToken(out _));
        using ManagementEnrolment enrolment = new(
            new TestServerFactory(app), settings, Bower.Packs.PolicyBundle.Load(settings.PolicySources()), clock,
            NullLogger<ManagementEnrolment>.Instance);

        await enrolment.EnsureEnrolledAsync(ct);
        await enrolment.EnsureEnrolledAsync(ct);
        AuditRecord[] audit = (await Client(app, BowerRoles.Viewer).GetFromJsonAsync<AuditRecord[]>("/api/audit", ct))!;
        (string status, string code) = await enrolment.RotateAsync(ct);

        Assert.False(enrolment.Enrolled);
        Assert.Single(audit, item => item.Action.StartsWith("enrolment-token.refused:", StringComparison.Ordinal));
        Assert.Equal(ManagementCommandResults.Failed, status);
        Assert.Equal(ManagementEnrolment.NotEnrolled, code);
        Assert.Throws<Azure.Identity.CredentialUnavailableException>(() => enrolment.CreateAssertion());
    }

    [Fact]
    public void Settings_EnrolmentModeIsValidatedAndAdvertisesRotation()
    {
        using TemporaryDirectory directory = new();
        (_, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string keyFile = Path.Combine(directory.Path, "command.pub.pem");
        File.WriteAllText(keyFile, publicPem);
        CollectorSettings entra = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = CollectorId,
            ManagementEndpoint = new Uri("https://bower-api.example.test/"),
            ManagementScope = "api://bower/.default",
            ManagementCommandTrustedKeyFiles = [keyFile]
        };
        CollectorSettings enrolled = entra with
        {
            ManagementAuthentication = ManagementAuthenticationModes.Enrolment,
            ManagementScope = null,
            ManagementEnrolmentTokenFile = Path.Combine(directory.Path, "token")
        };

        enrolled.Validate();
        Assert.Throws<InvalidOperationException>(() => (enrolled with { ManagementEndpoint = null }).Validate());
        Assert.Throws<InvalidOperationException>(() => (entra with { ManagementEnrolmentTokenFile = "token" }).Validate());
        Assert.Throws<InvalidOperationException>(() => (entra with { ManagementAuthentication = "password" }).Validate());
        Assert.Throws<InvalidOperationException>(() => (entra with { ManagementScope = null }).Validate());
        Assert.NotEqual(entra.ConfigurationHash(), (enrolled with { ManagementScope = "api://bower/.default" }).ConfigurationHash());
        Assert.Equal(entra.ConfigurationHash(), (entra with { ManagementEnrolmentTokenFile = null }).ConfigurationHash());
        Assert.DoesNotContain(ManagementCommandTypes.RotateCredential, ManagementCommandTypes.Supported(entra));
        Assert.Equal(
            [ManagementCommandTypes.RunCanary, ManagementCommandTypes.Reload, ManagementCommandTypes.RotateCredential],
            ManagementCommandTypes.Supported(enrolled));
        Assert.Empty(ManagementCommandTypes.Supported(enrolled with { ManagementCommandTrustedKeyFiles = [] }));
        CollectorSettings fromEnvironment = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_QUEUE_PATH" => Path.Combine(directory.Path, "queue.db"),
            "BOWER_MANAGEMENT_ENDPOINT" => "https://bower-api.example.test/",
            "BOWER_MANAGEMENT_AUTH" => "Enrolment",
            "BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE" => "/etc/bower/enrolment-token",
            _ => null
        });
        Assert.True(fromEnvironment.UsesEnrolment);
        Assert.Equal("/etc/bower/enrolment-token", fromEnvironment.ManagementEnrolmentTokenFile);

        // The Rust collector pins the same hash (tests/enrolment.rs).
        CollectorSettings pinned = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = "queue.db",
            PolicyDirectory = "policies",
            CollectorId = "edge-01",
            ManagementEndpoint = new Uri("https://bower-api.example.test/"),
            ManagementAuthentication = ManagementAuthenticationModes.Enrolment
        };
        Assert.Equal("sha256:4e70f9ce806fbabf1922dd1d5b4fe7b753fe00ea9afcbeed18f07882dcb3204a", pinned.ConfigurationHash());
    }

    [Fact]
    public void Assertions_MatchManagementBytesAndThePinnedCrossRuntimeForm()
    {
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        byte[] collector = ManagementAssertion.SignedBytes(
            "collector-é<&>'\"+`東😀", keyId, "2026-10-27T00:00:00.0000000Z", "2026-10-27T00:05:00.0000000Z",
            new string('a', 32));
        byte[] management = CollectorEnrolment.AssertionBytes(
            "collector-é<&>'\"+`東😀", keyId, "2026-10-27T00:00:00.0000000Z", "2026-10-27T00:05:00.0000000Z",
            new string('a', 32));
        string pinned = Encoding.UTF8.GetString(ManagementAssertion.SignedBytes(
            "edge-01", "0123456789abcdef", "2026-10-27T00:00:00.0000000Z", "2026-10-27T00:05:00.0000000Z",
            new string('a', 32)));
        string created = ManagementAssertion.Create(CollectorId, keyId, privatePem, Start);

        Assert.Equal(collector, management);
        // The Rust collector pins the same text (enrolment.rs).
        Assert.Equal(
            "{\"collectorId\":\"edge-01\",\"credentialId\":\"0123456789abcdef\",\"expiresAt\":\"2026-10-27T00:05:00.0000000Z\"," +
            "\"issuedAt\":\"2026-10-27T00:00:00.0000000Z\",\"kind\":\"bower.collector-assertion/v1\"," +
            "\"nonce\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
            pinned);
        Assert.Null(CollectorEnrolment.TryReadAssertion(created, Start.AddMinutes(1), out CollectorAssertion? read));
        Assert.True(read!.VerifiedBy(publicPem));
        Assert.Equal(CollectorId, read.CollectorId);
        Assert.Equal(Start.AddMinutes(5), read.ExpiresAt);

        // What the Rust collector signs, the C# management API accepts.
        Assert.Null(CollectorEnrolment.TryReadAssertion(
            RustAssertionVector.Assertion, RustAssertionVector.Now, out CollectorAssertion? rust));
        Assert.True(rust!.VerifiedBy(RustPublicKeyPem));
        Assert.Equal(RustAssertionVector.CollectorId, rust.CollectorId);
        Assert.Equal(DetachedSigner.KeyIdFromPublicKeyPem(RustPublicKeyPem), rust.CredentialId);
    }

    [Fact]
    public void Assertions_InAnyOtherFormAreRefused()
    {
        (string privatePem, _, string keyId) = DetachedSigner.GenerateKeyPair();
        string valid = ManagementAssertion.Create(CollectorId, keyId, privatePem, Start);
        string[] parts = valid[5..].Split('.');
        string signature = parts[1];

        string Rewrite(string json) =>
            "bwc1." + System.Buffers.Text.Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json)) + "." + signature;

        string payload = Encoding.UTF8.GetString(System.Buffers.Text.Base64Url.DecodeFromChars(parts[0]));
        string spaced = payload.Replace(",", ", ", StringComparison.Ordinal);
        string extra = payload.Insert(1, "\"admin\":\"true\",");
        string wrongKind = payload.Replace("bower.collector-assertion/v1", "bower.collector-command/v1", StringComparison.Ordinal);
        string tooLong = ManagementAssertion.Create(CollectorId, keyId, privatePem, Start)
            .Replace("bwc1.", "bwc2.", StringComparison.Ordinal);

        Assert.Equal(CredentialRefusals.Malformed, CollectorEnrolment.TryReadAssertion(Rewrite(spaced), Start, out _));
        Assert.Equal(CredentialRefusals.Malformed, CollectorEnrolment.TryReadAssertion(Rewrite(extra), Start, out _));
        Assert.Equal(CredentialRefusals.Malformed, CollectorEnrolment.TryReadAssertion(Rewrite(wrongKind), Start, out _));
        Assert.Equal(CredentialRefusals.Malformed, CollectorEnrolment.TryReadAssertion(tooLong, Start, out _));
        Assert.Equal(CredentialRefusals.Malformed, CollectorEnrolment.TryReadAssertion(valid + "." + signature, Start, out _));
        Assert.Equal(CredentialRefusals.Malformed, CollectorEnrolment.TryReadAssertion(new string('x', 4096), Start, out _));
        Assert.Equal(CredentialRefusals.NotYetValid, CollectorEnrolment.TryReadAssertion(valid, Start.AddMinutes(-6), out _));
        Assert.Equal(CredentialRefusals.Expired, CollectorEnrolment.TryReadAssertion(valid, Start.AddMinutes(5), out _));
        string elevenMinutes = Rewrite(payload.Replace("2026-10-27T00:05:00", "2026-10-27T00:11:00", StringComparison.Ordinal));
        Assert.Equal(CredentialRefusals.InvalidLifetime, CollectorEnrolment.TryReadAssertion(elevenMinutes, Start, out _));
    }

    private static Task<WebApplication> StartAsync(TemporaryDirectory directory, FakeClock clock, CancellationToken ct) =>
        ManagementApiTests.StartAsync(directory, clock, ct, "--BOWER_MANAGEMENT_ENROLMENT_RATE_PER_MINUTE=1000");

    private static HttpClient Client(WebApplication app, string roles) => ManagementApiTests.Client(app, roles);

    private static async Task<string> CreateTokenAsync(
        WebApplication app,
        CancellationToken ct,
        int? hours = null,
        string? collectorId = null)
    {
        using HttpResponseMessage response = await Client(app, BowerRoles.Administrator).PostAsJsonAsync(
            "/api/enrolment-tokens",
            new EnrolmentTokenRequest(Environment, "Expected on-prem collector", collectorId, hours),
            ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<IssuedEnrolmentToken>(Json, ct))!.Token;
    }

    private static async Task<(HttpStatusCode Status, IssuedCollectorCredential? Credential, string PrivatePem)> EnrolAsync(
        WebApplication app,
        string token,
        CancellationToken ct,
        string collectorId = CollectorId,
        string environment = Environment,
        string? privatePem = null)
    {
        privatePem ??= DetachedSigner.GenerateKeyPair().PrivateKeyPem;
        using HttpResponseMessage response = await app.GetTestClient().PostAsJsonAsync(
            "/api/collectors/enrol",
            new CollectorEnrolmentRequest(token, collectorId, collectorId, environment, "0.1.0", "c", "p", PublicKey(privatePem)),
            ct);
        IssuedCollectorCredential? issued = response.StatusCode == HttpStatusCode.Accepted
            ? await response.Content.ReadFromJsonAsync<IssuedCollectorCredential>(Json, ct)
            : null;
        return (response.StatusCode, issued, privatePem);
    }

    private static async Task<(string CredentialId, string PrivatePem)> EnrolAndApproveAsync(
        WebApplication app,
        FakeClock clock,
        CancellationToken ct)
    {
        (HttpStatusCode status, IssuedCollectorCredential? issued, string privatePem) =
            await EnrolAsync(app, await CreateTokenAsync(app, ct), ct);
        Assert.Equal(HttpStatusCode.Accepted, status);
        using HttpResponseMessage registered = await Assertion(app, clock, issued!.CredentialId, privatePem)
            .PostAsJsonAsync("/api/collectors/register", Registration(), ct);
        using HttpResponseMessage approved = await Client(app, BowerRoles.Approver).PostAsJsonAsync(
            $"/api/approvals/{CollectorId}/approve", new ApprovalRequest("Expected collector"), ct);
        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        return (issued.CredentialId, privatePem);
    }

    private static HttpClient Assertion(WebApplication app, FakeClock clock, string credentialId, string privatePem) =>
        Bearer(app, ManagementAssertion.Create(CollectorId, credentialId, privatePem, clock.UtcNow));

    private static HttpClient Bearer(WebApplication app, string value)
    {
        HttpClient client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", value);
        return client;
    }

    private static Task<HttpResponseMessage> Heartbeat(HttpClient client, CancellationToken ct, string collectorId = CollectorId) =>
        client.PostAsJsonAsync(
            $"/api/collectors/{collectorId}/heartbeat",
            new CollectorHeartbeat("0.1.0", "c", "p", 0, "healthy", [], []) { SchemaVersion = 2 },
            ct);

    private static CollectorRegistration Registration(string collectorId = CollectorId) =>
        new(collectorId, collectorId, Environment, "0.1.0", "c", "p", [], []);

    private static Task<CollectorRecord?> GetCollectorAsync(WebApplication app, CancellationToken ct) =>
        Client(app, BowerRoles.Viewer).GetFromJsonAsync<CollectorRecord>($"/api/collectors/{CollectorId}", Json, ct);

    private static string PublicKey(string privatePem)
    {
        using System.Security.Cryptography.ECDsa key = System.Security.Cryptography.ECDsa.Create();
        key.ImportFromPem(privatePem);
        return key.ExportSubjectPublicKeyInfoPem();
    }

    private static CollectorSettings EnrolmentSettings(TemporaryDirectory directory, string token)
    {
        string tokenFile = Path.Combine(directory.Path, "enrolment-token");
        File.WriteAllText(tokenFile, token + "\n");
        return new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "collector", "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = CollectorId,
            Environment = Environment,
            ManagementEndpoint = new Uri("http://localhost/"),
            ManagementAuthentication = ManagementAuthenticationModes.Enrolment,
            ManagementEnrolmentTokenFile = tokenFile
        };
    }

    /// <summary>True when any SQLite file of the management database contains <paramref name="text"/>.</summary>
    private static bool DatabaseContains(TemporaryDirectory directory, string text)
    {
        byte[] needle = Encoding.ASCII.GetBytes(text);
        foreach (string file in Directory.GetFiles(directory.Path, "management.db*"))
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using MemoryStream copy = new();
            stream.CopyTo(copy);
            if (copy.ToArray().AsSpan().IndexOf(needle) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Hands the collector the in-process management API.</summary>
    private sealed class TestServerFactory(WebApplication app) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => app.GetTestClient();
    }
}

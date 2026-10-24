using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Collector;
using Bower.Integrity;
using Bower.Management.Api;
using Microsoft.AspNetCore.Builder;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class PrivacyProfileApiTests
{
    private const string VersionId = "0123456789abcdef0123456789abcdef";

    [Theory]
    [InlineData("POST", "/api/privacy-profiles/validate", "")]
    [InlineData("POST", "/api/privacy-profiles/validate", BowerRoles.Viewer)]
    [InlineData("POST", "/api/privacy-profiles/validate", BowerRoles.Collector)]
    [InlineData("POST", "/api/privacy-profiles/preview", BowerRoles.Viewer)]
    [InlineData("POST", "/api/privacy-profiles/preview", BowerRoles.Collector)]
    [InlineData("GET", "/api/privacy-profiles", "")]
    [InlineData("GET", "/api/privacy-profiles", BowerRoles.Collector)]
    [InlineData("GET", "/api/privacy-profiles/versions/" + VersionId, BowerRoles.Collector)]
    [InlineData("POST", "/api/privacy-profiles", BowerRoles.Viewer)]
    [InlineData("POST", "/api/privacy-profiles", BowerRoles.Collector)]
    [InlineData("POST", "/api/privacy-profiles/versions/" + VersionId + "/approve", BowerRoles.Operator)]
    [InlineData("POST", "/api/privacy-profiles/versions/" + VersionId + "/approve", BowerRoles.Viewer)]
    [InlineData("POST", "/api/privacy-profiles/versions/" + VersionId + "/approve", BowerRoles.Collector)]
    [InlineData("POST", "/api/privacy-profiles/versions/" + VersionId + "/reject", BowerRoles.Operator)]
    [InlineData("POST", "/api/privacy-profiles/versions/" + VersionId + "/reject", BowerRoles.Collector)]
    [InlineData("GET", "/api/privacy-profiles/assignments", BowerRoles.Collector)]
    [InlineData("GET", "/api/privacy-profiles/assignments", "")]
    [InlineData("POST", "/api/collectors/edge-01/privacy-profile", BowerRoles.Approver)]
    [InlineData("POST", "/api/collectors/edge-01/privacy-profile", BowerRoles.Operator)]
    [InlineData("POST", "/api/collectors/edge-01/privacy-profile", BowerRoles.Collector)]
    [InlineData("POST", "/api/collectors/edge-01/privacy-profile/clear", BowerRoles.Approver)]
    [InlineData("POST", "/api/collectors/edge-01/privacy-profile/clear", BowerRoles.Collector)]
    [InlineData("GET", "/api/collectors/edge-01/privacy-profile/deployment", BowerRoles.Administrator)]
    [InlineData("GET", "/api/collectors/edge-01/privacy-profile/deployment", BowerRoles.Viewer)]
    [InlineData("GET", "/api/collectors/edge-01/privacy-profile/deployment", "")]
    public async Task Endpoints_DenyRolesOutsideTheirPolicy(string method, string path, string roles)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        using HttpRequestMessage request = new(new HttpMethod(method), path);
        if (method == "POST")
        {
            request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        }

        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles).SendAsync(request, ct);

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"{method} {path} as '{roles}' returned {response.StatusCode}");
    }

    [Fact]
    public async Task Validate_SummarisesValidProfilesAndReportsLoaderErrors()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        HttpClient operatorClient = ManagementApiTests.Client(app, BowerRoles.Operator);

        PrivacyProfileValidation valid = await ValidateAsync(operatorClient, Profile("1.0.0"), ct);
        PrivacyProfileValidation unknown = await ValidateAsync(
            operatorClient, Profile("1.0.0").Replace("id.email", "nope", StringComparison.Ordinal), ct);
        PrivacyProfileValidation badVersion = await ValidateAsync(operatorClient, Profile("1.0"), ct);
        PrivacyProfileValidation leadingZero = await ValidateAsync(operatorClient, Profile("1.01.0"), ct);
        PrivacyProfileValidation oversized = await ValidateAsync(
            operatorClient, Profile("1.0.0") + "# " + new string('x', 270_000) + "\n", ct);
        PrivacyProfileValidation empty = await ValidateAsync(operatorClient, " ", ct);
        await SubmitAsync(operatorClient, Profile("1.0.0"), ct);
        PrivacyProfileValidation notGreater = await ValidateAsync(operatorClient, Profile("1.0.0"), ct);

        Assert.True(valid.Valid);
        Assert.Empty(valid.Errors);
        Assert.Equal("contoso-app", valid.ProfileId);
        Assert.Equal("1.0.0", valid.Version);
        Assert.StartsWith("sha256:", valid.ContentHash, StringComparison.Ordinal);
        Assert.Equal(1, valid.DetectorOverrides);
        Assert.Equal(1, valid.FieldRules);
        Assert.Empty(valid.CustomDetectors);
        Assert.Equal(0, valid.SecretFieldNames);
        Assert.Equal(["Unknown detector id 'nope'."], unknown.Errors);
        Assert.False(unknown.Valid);
        Assert.Equal(["Privacy profile version must be MAJOR.MINOR.PATCH."], badVersion.Errors);
        Assert.Equal(["Privacy profile version must be MAJOR.MINOR.PATCH."], leadingZero.Errors);
        Assert.Equal(["Privacy profile exceeds 256 KiB."], oversized.Errors);
        Assert.Equal(["Privacy profile content is required."], empty.Errors);
        Assert.False(notGreater.Valid);
        Assert.Equal(["Privacy profile version must be greater than 1.0.0."], notGreater.Errors);
    }

    [Fact]
    public void Inspector_SummarisesAndPreviewsCustomDetectors()
    {
        string content = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "privacy", "custom-redaction-example.yaml"));

        PrivacyProfileValidation validation = PrivacyProfileInspector.Validate(content);
        PrivacyProfilePreview preview = PrivacyProfileInspector.Preview(content, """{"msg":"EMP-123456 opened","sessionKey":"s"}""");

        Assert.True(validation.Valid);
        Assert.Equal(
            ["custom.employee-id:Mask", "custom.customer-ref:Hmac", "custom.internal-ticket:Replace"],
            validation.CustomDetectors.Select(detector => $"{detector.Id}:{detector.Action}"));
        Assert.Equal("Contoso employee numbers (EMP- and six digits).", validation.CustomDetectors[0].Description);
        Assert.Equal(3, validation.SecretFieldNames);
        Assert.True(preview.Valid);
        Assert.DoesNotContain("EMP-123456", preview.Redacted!, StringComparison.Ordinal);
        Assert.Contains(preview.Findings, finding => finding.DetectorId == "custom.employee-id" && finding.Action == "Masked");
        Assert.Contains(preview.Findings, finding => finding.DetectorId == "field-name-secret" && finding.Path == "$.sessionKey");
    }

    [Fact]
    public async Task Preview_RedactsSampleWithRandomKeyAndPersistsNothing()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        HttpClient operatorClient = ManagementApiTests.Client(app, BowerRoles.Operator);
        string sample = """{"actor":{"username":"alice"},"message":"mail bob@example.com now"}""";

        PrivacyProfilePreview first = await PreviewAsync(operatorClient, Profile("1.0.0"), sample, ct);
        PrivacyProfilePreview second = await PreviewAsync(operatorClient, Profile("1.0.0"), sample, ct);
        PrivacyProfilePreview invalidSample = await PreviewAsync(operatorClient, Profile("1.0.0"), "not json", ct);
        PrivacyProfilePreview invalidProfile = await PreviewAsync(operatorClient, "kind: nope", sample, ct);
        using HttpResponseMessage oversized = await operatorClient.PostAsJsonAsync(
            "/api/privacy-profiles/preview",
            new PrivacyProfilePreviewRequest(Profile("1.0.0"), new string('a', 65_537)),
            ct);
        PrivacyProfileVersionSummary[]? versions = await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<PrivacyProfileVersionSummary[]>("/api/privacy-profiles", ManagementApiTests.ApiJson, ct);
        AuditRecord[]? audit = await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<AuditRecord[]>("/api/audit", ct);

        Assert.True(first.Valid);
        Assert.DoesNotContain("bob@example.com", first.Redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", first.Redacted, StringComparison.Ordinal);
        Assert.Contains(first.Findings, item => item.DetectorId == "id.email" && item.Action == "Removed");
        Assert.Contains(first.Findings, item => item.Path.Contains("username", StringComparison.Ordinal) && item.Action == "HMAC");
        // A fresh HMAC key per request: preview pseudonyms never repeat or match production.
        Assert.NotEqual(first.Redacted, second.Redacted);
        Assert.False(invalidSample.Valid);
        Assert.Equal(["Preview sample is not valid JSON."], invalidSample.Errors);
        Assert.False(invalidProfile.Valid);
        Assert.Null(invalidProfile.Redacted);
        Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
        Assert.Empty(versions!);
        Assert.Empty(audit!);
    }

    [Fact]
    public async Task Submit_EnforcesMonotonicVersionsChangeSummaryAndContent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        HttpClient author = ManagementApiTests.Client(app, BowerRoles.Operator, "alice");

        using HttpResponseMessage created = await Submit(author, Profile("1.9.0"), "Initial profile", ct);
        PrivacyProfileVersionDetail? detail =
            await created.Content.ReadFromJsonAsync<PrivacyProfileVersionDetail>(ManagementApiTests.ApiJson, ct);
        using HttpResponseMessage same = await Submit(author, Profile("1.9.0"), "again", ct);
        using HttpResponseMessage lower = await Submit(author, Profile("1.8.12"), "older", ct);
        using HttpResponseMessage numeric = await Submit(author, Profile("1.10.0"), "numeric order", ct);
        using HttpResponseMessage otherProfile = await Submit(author, Profile("0.1.0", "other-app"), "independent", ct);
        using HttpResponseMessage badVersion = await Submit(author, Profile("2.0.0-beta"), "pre-release", ct);
        using HttpResponseMessage noSummary = await Submit(author, Profile("3.0.0"), " ", ct);
        using HttpResponseMessage longSummary = await Submit(author, Profile("3.0.0"), new string('s', 501), ct);
        using HttpResponseMessage invalid = await Submit(
            author, Profile("3.0.0").Replace("hmac", "scramble", StringComparison.Ordinal), "bad action", ct);
        using HttpResponseMessage oversized = await Submit(
            author, Profile("3.0.0") + "# " + new string('x', 270_000) + "\n", "too big", ct);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal($"/api/privacy-profiles/versions/{detail!.Id}", created.Headers.Location?.OriginalString);
        Assert.Matches("^[0-9a-f]{32}$", detail.Id);
        Assert.Equal(PrivacyProfileVersionStatus.PendingReview, detail.Status);
        Assert.Equal("alice", detail.AuthorObjectId);
        Assert.Equal("Contoso application telemetry", detail.Description);
        Assert.Equal(Profile("1.9.0"), detail.Content);
        Assert.Null(detail.PreviousApprovedVersionId);
        Assert.Equal("Privacy profile version must be greater than 1.9.0.", await ErrorAsync(same, ct));
        Assert.Equal("Privacy profile version must be greater than 1.9.0.", await ErrorAsync(lower, ct));
        Assert.Equal(HttpStatusCode.Created, numeric.StatusCode);
        Assert.Equal(HttpStatusCode.Created, otherProfile.StatusCode);
        Assert.Equal("Privacy profile version must be MAJOR.MINOR.PATCH.", await ErrorAsync(badVersion, ct));
        Assert.Equal(HttpStatusCode.BadRequest, noSummary.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, longSummary.StatusCode);
        Assert.Equal("Unknown privacy action 'scramble'.", await ErrorAsync(invalid, ct));
        Assert.Equal("Privacy profile exceeds 256 KiB.", await ErrorAsync(oversized, ct));
    }

    [Fact]
    public async Task Review_EnforcesTwoPersonRuleAndPendingReviewState()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        HttpClient alice = ManagementApiTests.Client(app, BowerRoles.Approver, "alice");
        HttpClient bob = ManagementApiTests.Client(app, BowerRoles.Approver, "bob");
        HttpClient carol = ManagementApiTests.Client(app, BowerRoles.Administrator, "carol");

        PrivacyProfileVersionDetail first = await SubmitAsync(alice, Profile("1.0.0"), ct);
        using HttpResponseMessage selfApprove = await Review(alice, first.Id, "approve", "Looks right", ct);
        using HttpResponseMessage selfReject = await Review(alice, first.Id, "reject", "Withdraw", ct);
        using HttpResponseMessage noReason = await Review(bob, first.Id, "reject", " ", ct);
        using HttpResponseMessage rejected = await Review(bob, first.Id, "reject", "Too broad", ct);
        using HttpResponseMessage approveRejected = await Review(carol, first.Id, "approve", "Override", ct);
        PrivacyProfileVersionDetail second = await SubmitAsync(alice, Profile("1.1.0"), ct);
        using HttpResponseMessage approved = await Review(bob, second.Id, "approve", "Change BWR-7", ct);
        PrivacyProfileVersionDetail? approvedDetail =
            await approved.Content.ReadFromJsonAsync<PrivacyProfileVersionDetail>(ManagementApiTests.ApiJson, ct);
        using HttpResponseMessage approveAgain = await Review(carol, second.Id, "approve", "Twice", ct);
        using HttpResponseMessage rejectApproved = await Review(carol, second.Id, "reject", "Too late", ct);
        using HttpResponseMessage missing = await Review(bob, VersionId, "approve", "Missing", ct);
        using HttpResponseMessage malformed = await Review(bob, "not-a-version", "approve", "Missing", ct);
        PrivacyProfileVersionDetail third = await SubmitAsync(carol, Profile("1.2.0"), ct);
        PrivacyProfileVersionSummary[]? summaries = await alice.GetFromJsonAsync<PrivacyProfileVersionSummary[]>(
            "/api/privacy-profiles", ManagementApiTests.ApiJson, ct);
        AuditRecord[]? audit = await alice.GetFromJsonAsync<AuditRecord[]>("/api/audit", ct);

        Assert.Equal(HttpStatusCode.Conflict, selfApprove.StatusCode);
        Assert.Equal("The author of a privacy profile version cannot review it.", await ErrorAsync(selfApprove, ct));
        Assert.Equal("The author of a privacy profile version cannot review it.", await ErrorAsync(selfReject, ct));
        Assert.Equal(HttpStatusCode.BadRequest, noReason.StatusCode);
        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, approveRejected.StatusCode);
        Assert.Equal(
            "Only privacy profile versions pending review can be approved or rejected.",
            await ErrorAsync(approveRejected, ct));
        Assert.Equal(PrivacyProfileVersionStatus.Approved, approvedDetail!.Status);
        Assert.Equal("Change BWR-7", approvedDetail.ReviewReason);
        Assert.NotNull(approvedDetail.ReviewedAt);
        Assert.Equal(HttpStatusCode.Conflict, approveAgain.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, rejectApproved.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, malformed.StatusCode);
        // Previous approved version skips the rejected 1.0.0.
        PrivacyProfileVersionDetail? thirdDetail = await alice.GetFromJsonAsync<PrivacyProfileVersionDetail>(
            $"/api/privacy-profiles/versions/{third.Id}", ManagementApiTests.ApiJson, ct);
        Assert.Equal(second.Id, thirdDetail!.PreviousApprovedVersionId);
        Assert.Equal(["1.2.0", "1.1.0", "1.0.0"], summaries!.Select(item => item.Version));
        Assert.Equal(
            [PrivacyProfileVersionStatus.PendingReview, PrivacyProfileVersionStatus.Approved, PrivacyProfileVersionStatus.Rejected],
            summaries!.Select(item => item.Status));
        Assert.Equal(3, audit!.Count(item => item.Action == "privacy-profile.submitted"));
        AuditRecord rejection = Assert.Single(audit!, item => item.Action == "privacy-profile.rejected");
        Assert.Equal(("privacy-profile-version", first.Id, "bob"), (rejection.TargetType, rejection.TargetId, rejection.ActorObjectId));
        AuditRecord approval = Assert.Single(audit!, item => item.Action == "privacy-profile.approved");
        Assert.Equal(second.Id, approval.TargetId);
    }

    [Fact]
    public async Task Assign_RequiresApprovedVersionAndNonRevokedCollectorAndTracksSync()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator, "carol");
        HttpClient author = ManagementApiTests.Client(app, BowerRoles.Operator, "alice");
        await RegisterActiveAsync(collector, admin, "edge-01", ct);
        await RegisterActiveAsync(collector, admin, "edge-02", ct);
        PrivacyProfileVersionDetail pending = await SubmitAsync(author, Profile("1.0.0"), ct);

        using HttpResponseMessage assignPending = await Assign(admin, "edge-01", pending.Id, "Roll out", ct);
        await Review(admin, pending.Id, "approve", "Reviewed", ct);
        using HttpResponseMessage noReason = await Assign(admin, "edge-01", pending.Id, "", ct);
        using HttpResponseMessage unknownCollector = await Assign(admin, "edge-99", pending.Id, "Roll out", ct);
        using HttpResponseMessage unknownVersion = await Assign(admin, "edge-01", VersionId, "Roll out", ct);
        using HttpResponseMessage malformedVersion = await Assign(admin, "edge-01", "../x", "Roll out", ct);
        using HttpResponseMessage assigned = await Assign(admin, "edge-01", pending.Id, "Roll out BWR-9", ct);
        CollectorRecord? drifted = await assigned.Content.ReadFromJsonAsync<CollectorRecord>(ManagementApiTests.ApiJson, ct);
        CollectorRecord inSync = await HeartbeatAsync(collector, "edge-01", pending.ContentHash, ct);
        CollectorRecord onDefault = await HeartbeatAsync(collector, "edge-01", "default", ct);
        using HttpResponseMessage badHash = await collector.PostAsJsonAsync(
            "/api/collectors/edge-01/heartbeat",
            Heartbeat() with { PrivacyProfileHash = "md5:abc" },
            ct);
        using HttpResponseMessage upperHash = await collector.PostAsJsonAsync(
            "/api/collectors/edge-01/heartbeat",
            Heartbeat() with { PrivacyProfileHash = pending.ContentHash.ToUpperInvariant() },
            ct);
        PrivacyProfileVersionSummary[]? whileAssigned = await admin.GetFromJsonAsync<PrivacyProfileVersionSummary[]>(
            "/api/privacy-profiles", ManagementApiTests.ApiJson, ct);
        using HttpResponseMessage cleared = await admin.PostAsJsonAsync(
            "/api/collectors/edge-01/privacy-profile/clear", new ApprovalRequest("Back to default"), ct);
        CollectorRecord? unassigned = await cleared.Content.ReadFromJsonAsync<CollectorRecord>(ManagementApiTests.ApiJson, ct);
        await admin.PostAsJsonAsync("/api/collectors/edge-02/revoke", new ApprovalRequest("Decommissioned"), ct);
        using HttpResponseMessage assignRevoked = await Assign(admin, "edge-02", pending.Id, "Roll out", ct);
        PrivacyProfileAssignment[]? history = await admin.GetFromJsonAsync<PrivacyProfileAssignment[]>(
            "/api/privacy-profiles/assignments", ManagementApiTests.ApiJson, ct);
        AuditRecord[]? audit = await admin.GetFromJsonAsync<AuditRecord[]>("/api/audit", ct);

        Assert.Equal(HttpStatusCode.Conflict, assignPending.StatusCode);
        Assert.Equal("Only approved privacy profile versions can be assigned.", await ErrorAsync(assignPending, ct));
        Assert.Equal(HttpStatusCode.BadRequest, noReason.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknownCollector.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknownVersion.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, malformedVersion.StatusCode);
        Assert.Equal(HttpStatusCode.OK, assigned.StatusCode);
        Assert.Equal(
            new DesiredPrivacyProfile(pending.Id, "contoso-app", "1.0.0", pending.ContentHash),
            drifted!.DesiredPrivacyProfile);
        Assert.False(drifted.PrivacyProfileInSync);
        Assert.True(inSync.PrivacyProfileInSync);
        Assert.Equal(pending.ContentHash, inSync.ReportedPrivacyProfileHash);
        Assert.False(onDefault.PrivacyProfileInSync);
        Assert.Equal(HttpStatusCode.BadRequest, badHash.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, upperHash.StatusCode);
        Assert.Equal(1, Assert.Single(whileAssigned!).AssignedCollectors);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);
        Assert.Null(unassigned!.DesiredPrivacyProfile);
        Assert.Null(unassigned.PrivacyProfileInSync);
        Assert.Equal(HttpStatusCode.Conflict, assignRevoked.StatusCode);
        Assert.Equal("Revoked collectors cannot be assigned a privacy profile.", await ErrorAsync(assignRevoked, ct));
        Assert.Equal(["cleared", "assigned"], history!.Select(item => item.Action));
        Assert.Equal(("edge-01", pending.Id, "contoso-app", "1.0.0"),
            (history![1].CollectorId, history[1].VersionId, history[1].ProfileId, history[1].Version));
        Assert.Null(history[0].VersionId);
        Assert.Equal("Back to default", history[0].Reason);
        AuditRecord assignAudit = Assert.Single(audit!, item => item.Action == "collector.privacy-profile-assigned");
        Assert.Equal(("collector", "edge-01", "carol"), (assignAudit.TargetType, assignAudit.TargetId, assignAudit.ActorObjectId));
        Assert.Single(audit!, item => item.Action == "collector.privacy-profile-cleared");
    }

    [Fact]
    public async Task Deployment_IsSignedOverExactlyTheSpecifiedFieldsForTheBoundActiveCollector()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        string keyFile = Path.Combine(directory.Path, "profile-signing.pem");
        await File.WriteAllTextAsync(keyFile, privatePem, ct);
        await using WebApplication app = await ManagementApiTests.StartAsync(
            directory, ct, $"--{ManagedPrivacyProfileSigner.KeyFileSetting}={keyFile}");
        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector);
        HttpClient impostor = ManagementApiTests.Client(app, BowerRoles.Collector, "impostor");
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator, "carol");
        HttpClient author = ManagementApiTests.Client(app, BowerRoles.Operator, "alice");
        await RegisterActiveAsync(collector, admin, "edge-01", ct);
        await collector.PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration("edge-pending", "edge-pending", "test", "0.1.0", "c", "p", [], []),
            ct);
        const string DeploymentPath = "/api/collectors/edge-01/privacy-profile/deployment";

        using HttpResponseMessage none = await collector.GetAsync(DeploymentPath, ct);
        PrivacyProfileVersionDetail version = await SubmitAsync(author, Profile("1.0.0"), ct);
        await Review(admin, version.Id, "approve", "Reviewed", ct);
        await Assign(admin, "edge-01", version.Id, "Roll out", ct);
        using HttpResponseMessage signed = await collector.GetAsync(DeploymentPath, ct);
        byte[] body = await signed.Content.ReadAsByteArrayAsync(ct);
        using HttpResponseMessage wrongPrincipal = await impostor.GetAsync(DeploymentPath, ct);
        using HttpResponseMessage pendingCollector = await collector.GetAsync(
            "/api/collectors/edge-pending/privacy-profile/deployment", ct);
        using HttpResponseMessage unknown = await collector.GetAsync(
            "/api/collectors/edge-99/privacy-profile/deployment", ct);
        await admin.PostAsJsonAsync("/api/collectors/edge-01/suspend", new ApprovalRequest("maintenance"), ct);
        using HttpResponseMessage suspended = await collector.GetAsync(DeploymentPath, ct);

        Assert.Equal(HttpStatusCode.NoContent, none.StatusCode);
        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, wrongPrincipal.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, pendingCollector.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, suspended.StatusCode);

        JsonObject document = JsonNode.Parse(body)!.AsObject();
        Assert.Equal(
            ["collectorId", "content", "contentHash", "issuedAt", "profileId", "signature", "version", "versionId"],
            document.Select(item => item.Key).Order(StringComparer.Ordinal));
        DetachedSignature signature = document["signature"].Deserialize<DetachedSignature>(JsonSerializerOptions.Web)!;
        Assert.Equal(("ES256", keyId), (signature.Algorithm, signature.KeyId));
        Assert.Equal("edge-01", (string?)document["collectorId"]);
        Assert.Equal(version.Id, (string?)document["versionId"]);
        Assert.Equal(version.ContentHash, (string?)document["contentHash"]);
        Assert.Equal(Profile("1.0.0"), (string?)document["content"]);
        string issuedAt = (string)document["issuedAt"]!;
        Assert.Equal(
            DateTimeOffset.Parse(issuedAt, System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime()
                .ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            issuedAt);

        // The signature covers the canonical JSON of every field except the signature itself.
        document.Remove("signature");
        byte[] canonical = CanonicalJson.Bytes(document);
        Assert.True(DetachedSigner.Verify(canonical, signature, [publicPem]));
        Assert.Equal(
            canonical,
            ManagedPrivacyProfileSigner.SignedBytes(
                "edge-01", version.Id, "contoso-app", "1.0.0", version.ContentHash, Profile("1.0.0"), issuedAt));
        foreach (string field in document.Select(item => item.Key).ToArray())
        {
            JsonObject tampered = document.DeepClone().AsObject();
            tampered[field] = (string)tampered[field]! + "x";
            Assert.False(DetachedSigner.Verify(CanonicalJson.Bytes(tampered), signature, [publicPem]), field);
        }

        Assert.False(DetachedSigner.Verify(canonical, signature, [DetachedSigner.GenerateKeyPair().PublicKeyPem]));
        // The collector verifier accepts the API's signed deployment unchanged.
        VerifiedManagedPrivacyProfile verified = ManagedPrivacyProfileCache.Verify(
            body, "edge-01", [publicPem], new byte[32], "k1");
        Assert.Equal((version.Id, version.ContentHash), (verified.VersionId, verified.ContentHash));
    }

    [Fact]
    public async Task Deployment_WithoutSigningKeyReturns503WhileEverythingElseWorks()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        HttpClient collector = ManagementApiTests.Client(app, BowerRoles.Collector);
        HttpClient admin = ManagementApiTests.Client(app, BowerRoles.Administrator, "carol");
        await RegisterActiveAsync(collector, admin, "edge-01", ct);
        const string DeploymentPath = "/api/collectors/edge-01/privacy-profile/deployment";

        using HttpResponseMessage none = await collector.GetAsync(DeploymentPath, ct);
        PrivacyProfileVersionDetail version = await SubmitAsync(
            ManagementApiTests.Client(app, BowerRoles.Operator, "alice"), Profile("1.0.0"), ct);
        await Review(admin, version.Id, "approve", "Reviewed", ct);
        using HttpResponseMessage assigned = await Assign(admin, "edge-01", version.Id, "Roll out", ct);
        using HttpResponseMessage unavailable = await collector.GetAsync(DeploymentPath, ct);

        Assert.Equal(HttpStatusCode.NoContent, none.StatusCode);
        Assert.Equal(HttpStatusCode.OK, assigned.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("Managed privacy profile signing is not configured.", await ErrorAsync(unavailable, ct));
    }

    [Fact]
    public void SigningKey_ThatIsNotAP256PrivateKeyFailsStartup()
    {
        using TemporaryDirectory directory = new();
        string publicOnly = Path.Combine(directory.Path, "public.pem");
        File.WriteAllText(publicOnly, DetachedSigner.GenerateKeyPair().PublicKeyPem);

        InvalidOperationException missing = Assert.Throws<InvalidOperationException>(
            () => ManagedPrivacyProfileSigner.FromFile(Path.Combine(directory.Path, "absent.pem")));
        InvalidOperationException notPrivate = Assert.Throws<InvalidOperationException>(
            () => ManagedPrivacyProfileSigner.FromFile(publicOnly));

        Assert.Contains(ManagedPrivacyProfileSigner.KeyFileSetting, missing.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", notPrivate.Message, StringComparison.Ordinal);
        Assert.False(ManagedPrivacyProfileSigner.FromFile(null).Configured);
    }

    internal static string Profile(string version, string id = "contoso-app") =>
        $"""
        apiVersion: bower.security/v1
        kind: PrivacyProfile
        metadata:
          id: {id}
          version: {version}
          description: Contoso application telemetry
        detectors:
          id.email: remove
        fields:
          - path: actor.username
            action: hmac

        """;

    internal static CollectorHeartbeat Heartbeat(string? privacyProfileHash = null) =>
        new("0.1.0", "c", "p", 0, "healthy", [], [], PrivacyProfileHash: privacyProfileHash);

    internal static async Task RegisterActiveAsync(HttpClient collector, HttpClient admin, string id, CancellationToken ct)
    {
        using HttpResponseMessage registered = await collector.PostAsJsonAsync(
            "/api/collectors/register",
            new CollectorRegistration(id, id, "test", "0.1.0", "c", "p", [], []),
            ct);
        using HttpResponseMessage approved = await admin.PostAsJsonAsync(
            $"/api/approvals/{id}/approve", new ApprovalRequest("Expected collector"), ct);
        using HttpResponseMessage heartbeat = await collector.PostAsJsonAsync(
            $"/api/collectors/{id}/heartbeat", Heartbeat(), ct);
        Assert.Equal(HttpStatusCode.OK, heartbeat.StatusCode);
    }

    private static async Task<CollectorRecord> HeartbeatAsync(
        HttpClient collector, string id, string privacyProfileHash, CancellationToken ct)
    {
        using HttpResponseMessage response = await collector.PostAsJsonAsync(
            $"/api/collectors/{id}/heartbeat", Heartbeat(privacyProfileHash), ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<CollectorRecord>(ManagementApiTests.ApiJson, ct))!;
    }

    private static async Task<PrivacyProfileValidation> ValidateAsync(HttpClient client, string content, CancellationToken ct)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "/api/privacy-profiles/validate", new PrivacyProfileContentRequest(content), ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<PrivacyProfileValidation>(ManagementApiTests.ApiJson, ct))!;
    }

    private static async Task<PrivacyProfilePreview> PreviewAsync(
        HttpClient client, string content, string sample, CancellationToken ct)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "/api/privacy-profiles/preview", new PrivacyProfilePreviewRequest(content, sample), ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<PrivacyProfilePreview>(ManagementApiTests.ApiJson, ct))!;
    }

    internal static Task<HttpResponseMessage> Submit(HttpClient client, string content, string summary, CancellationToken ct) =>
        client.PostAsJsonAsync("/api/privacy-profiles", new PrivacyProfileSubmission(content, summary), ct);

    internal static async Task<PrivacyProfileVersionDetail> SubmitAsync(HttpClient client, string content, CancellationToken ct)
    {
        using HttpResponseMessage response = await Submit(client, content, "Change summary", ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<PrivacyProfileVersionDetail>(ManagementApiTests.ApiJson, ct))!;
    }

    internal static Task<HttpResponseMessage> Review(
        HttpClient client, string id, string decision, string reason, CancellationToken ct) =>
        client.PostAsJsonAsync($"/api/privacy-profiles/versions/{id}/{decision}", new ApprovalRequest(reason), ct);

    internal static Task<HttpResponseMessage> Assign(
        HttpClient client, string collectorId, string versionId, string reason, CancellationToken ct) =>
        client.PostAsJsonAsync(
            $"/api/collectors/{collectorId}/privacy-profile",
            new PrivacyProfileAssignmentRequest(versionId, reason),
            ct);

    private static async Task<string?> ErrorAsync(HttpResponseMessage response, CancellationToken ct) =>
        (await response.Content.ReadFromJsonAsync<ErrorResponse>(ManagementApiTests.ApiJson, ct))?.Error;
}

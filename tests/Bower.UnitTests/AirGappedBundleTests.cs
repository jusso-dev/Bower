using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Bower.Abstractions;
using Bower.Evidence;
using Bower.Integrity;
using Bower.Management.Api;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;

namespace Bower.UnitTests;

/// <summary>
/// Air-gapped signed export/import bundles (#111) and Offline site fleet view (#113):
/// ECDSA P-256 signing, bundle hash chaining, AES-256-GCM encryption, tamper detection,
/// Management API RBAC + chain continuity + OfflineSite fleet state.
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class AirGappedBundleTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task BundleCreateVerifyAndChain_DetectsTamperingUntrustedKeysAndSequenceGaps()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using SqliteTemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        (_, string untrustedPublicPem, _) = DetachedSigner.GenerateKeyPair();

        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 1024 * 1024);
        await store.InitializeAsync(cancellation);
        await store.EnqueueAsync(new QueuedEvent("air-1", "fp-air-1", "{\"eventId\":\"air-1\",\"eventType\":\"authentication_failure\"}", Now), cancellation);
        await store.EnqueueAsync(new QueuedEvent("air-2", "fp-air-2", "{\"eventId\":\"air-2\",\"eventType\":\"authentication_failure\"}", Now.AddSeconds(1)), cancellation);

        IReadOnlyList<LedgerEvent> batch1 = await store.ReadLedgerEventsAsync(0, 100, cancellation);
        string bundle1Path = Path.Combine(directory.Path, "site-a-001.bowerbundle");
        AirGappedExportResult export1 = AirGappedBundle.Create(
            bundle1Path,
            BuildManifest("bundle-1", "site-a-01", 1, AirGappedBundleManifest.GenesisBundleHash, batch1),
            batch1.Select(item => item.Payload),
            privatePem);
        await store.RecordExportBundleAsync(new ExportBundleCursor(
            export1.BundleSequence, export1.BundleId, export1.FromLedgerSequence, export1.ToLedgerSequence, export1.BundleHash, Now), cancellation);

        // Verify bundle 1 succeeds with trusted key and fails with untrusted key.
        AirGappedBundleVerification ok1 = AirGappedBundle.Verify(
            bundle1Path, [publicPem], expectedSequence: 1, expectedPreviousBundleHash: AirGappedBundleManifest.GenesisBundleHash);
        Assert.True(ok1.Valid, ok1.Error);
        Assert.Equal(2, ok1.Manifest!.EventCount);
        Assert.Equal(2, AirGappedBundle.ReadVerifiedEvents(bundle1Path, [publicPem]).Count);

        Assert.False(AirGappedBundle.Verify(bundle1Path, [untrustedPublicPem]).Valid);

        // Enqueue a third event and export chained bundle 2 from cursor.
        await store.EnqueueAsync(new QueuedEvent("air-3", "fp-air-3", "{\"eventId\":\"air-3\",\"eventType\":\"role_membership_changed\"}", Now.AddSeconds(2)), cancellation);
        ExportBundleCursor? cursor = await store.GetLastExportBundleAsync(cancellation);
        Assert.NotNull(cursor);
        IReadOnlyList<LedgerEvent> batch2 = await store.ReadLedgerEventsAsync(cursor!.ToLedgerSequence, 100, cancellation);
        Assert.Single(batch2);

        string bundle2Path = Path.Combine(directory.Path, "site-a-002.bowerbundle");
        AirGappedExportResult export2 = AirGappedBundle.Create(
            bundle2Path,
            BuildManifest("bundle-2", "site-a-01", cursor.BundleSequence + 1, cursor.BundleHash, batch2),
            batch2.Select(item => item.Payload),
            privatePem);
        Assert.Equal(2, export2.BundleSequence);

        // Chain verification passes with bundle1 hash and fails on wrong previous hash.
        Assert.True(AirGappedBundle.Verify(bundle2Path, [publicPem], expectedSequence: 2, expectedPreviousBundleHash: export1.BundleHash).Valid);
        Assert.False(AirGappedBundle.Verify(bundle2Path, [publicPem], expectedSequence: 2, expectedPreviousBundleHash: "sha256:wrong").Valid);
        Assert.False(AirGappedBundle.Verify(bundle2Path, [publicPem], expectedSequence: 3, expectedPreviousBundleHash: export1.BundleHash).Valid);

        // Tamper with events.ndjson inside bundle 2 -> verification must fail closed.
        string tamperedPath = Path.Combine(directory.Path, "tampered.bowerbundle");
        File.Copy(bundle2Path, tamperedPath);
        using (ZipArchive zip = ZipFile.Open(tamperedPath, ZipArchiveMode.Update))
        {
            zip.GetEntry("events.ndjson")!.Delete();
            ZipArchiveEntry forged = zip.CreateEntry("events.ndjson");
            using StreamWriter writer = new(forged.Open(), Encoding.UTF8);
            writer.Write("{\"eventId\":\"forged\"}\n");
        }

        AirGappedBundleVerification tampered = AirGappedBundle.Verify(tamperedPath, [publicPem]);
        Assert.False(tampered.Valid);
    }

    [Fact]
    public void BundleEncryption_Aes256Gcm_HidesPlaintextAndRejectsWrongKey()
    {
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
        string bundlePath = Path.Combine(directory.Path, "encrypted.bowerbundle");

        AirGappedBundleManifest manifest = new(
            AirGappedBundleManifest.CurrentKind,
            "bundle-enc-1",
            "site-b-01",
            "site-b-host",
            "site-b",
            "1.0.1",
            "sha256:pol",
            "default",
            1,
            AirGappedBundleManifest.GenesisBundleHash,
            1,
            1,
            "sha256:head",
            1,
            0,
            0,
            string.Empty,
            true,
            Now.ToString("O"));

        AirGappedExportResult created = AirGappedBundle.Create(
            bundlePath,
            manifest,
            ["{\"eventId\":\"enc-evt-1\",\"marker\":\"secret-free-redacted-line\"}"],
            privatePem,
            key);
        Assert.True(created.Encrypted);

        // Plaintext marker must not appear raw in the archive bytes.
        string rawZipAscii = Encoding.Latin1.GetString(File.ReadAllBytes(bundlePath));
        Assert.DoesNotContain("secret-free-redacted-line", rawZipAscii, StringComparison.Ordinal);

        Assert.False(AirGappedBundle.Verify(bundlePath, [publicPem]).Valid);
        Assert.False(AirGappedBundle.Verify(bundlePath, [publicPem], decryptionKey: wrongKey).Valid);
        Assert.True(AirGappedBundle.Verify(bundlePath, [publicPem], decryptionKey: key).Valid);
        string line = Assert.Single(AirGappedBundle.ReadVerifiedEvents(bundlePath, [publicPem], key));
        Assert.Contains("enc-evt-1", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManagementApiOfflineImport_EnforcesRbacSignaturesChainContinuityAndShowsOfflineSiteInFleet()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        (string untrustedPriv, _, _) = DetachedSigner.GenerateKeyPair();
        string pubPath = Path.Combine(directory.Path, "offline.pub.pem");
        await File.WriteAllTextAsync(pubPath, publicPem, cancellation);

        await using WebApplication app = await ManagementApiTests.StartAsync(
            directory,
            cancellation,
            $"--{OfflineSiteTrustKeys.SettingName}={pubPath}");

        HttpClient viewer = ManagementApiTests.Client(app, BowerRoles.Viewer, "viewer-oid");
        HttpClient oper = ManagementApiTests.Client(app, BowerRoles.Operator, "operator-oid");

        string bundle1Path = Path.Combine(directory.Path, "b1.bowerbundle");
        AirGappedExportResult exp1 = AirGappedBundle.Create(
            bundle1Path,
            new AirGappedBundleManifest(
                AirGappedBundleManifest.CurrentKind, "b1", "airgap-site-01", "airgap-host", "scif-south",
                "1.0.1", "sha256:pol1", "default", 1, AirGappedBundleManifest.GenesisBundleHash,
                1, 10, "sha256:head10", 1, 0, 0, string.Empty, false, Now.ToString("O")),
            ["{\"eventId\":\"e1\"}"],
            privatePem);
        SignedOfflineSiteReport report1 = AirGappedBundle.Verify(bundle1Path, [publicPem]).OfflineReport!;

        // Viewer is forbidden from importing.
        using HttpResponseMessage forbidden = await viewer.PostAsJsonAsync("/api/fleet/offline-import", report1, cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        // Untrusted signer is rejected with 400.
        string badBundlePath = Path.Combine(directory.Path, "bad.bowerbundle");
        AirGappedBundle.Create(
            badBundlePath,
            new AirGappedBundleManifest(
                AirGappedBundleManifest.CurrentKind, "b-bad", "airgap-site-01", "airgap-host", "scif-south",
                "1.0.1", "sha256:pol1", "default", 1, AirGappedBundleManifest.GenesisBundleHash,
                1, 10, "sha256:head10", 1, 0, 0, string.Empty, false, Now.ToString("O")),
            ["{\"eventId\":\"e1\"}"],
            untrustedPriv);
        (_, string untrustedPub, _) = DetachedSigner.GenerateKeyPair();
        using (ZipArchive zip = ZipFile.OpenRead(badBundlePath))
        {
            using StreamReader sr = new(zip.GetEntry("status-report.json")!.Open());
            SignedOfflineSiteReport untrustedReport = System.Text.Json.JsonSerializer.Deserialize(
                await sr.ReadToEndAsync(cancellation), AirGappedBundleJsonContext.Default.SignedOfflineSiteReport)!;
            using HttpResponseMessage badResp = await oper.PostAsJsonAsync("/api/fleet/offline-import", untrustedReport, cancellation);
            Assert.Equal(HttpStatusCode.BadRequest, badResp.StatusCode);
        }

        // Valid import succeeds and shows as Offline site in /api/fleet (#113).
        using HttpResponseMessage ok1 = await oper.PostAsJsonAsync("/api/fleet/offline-import", report1, cancellation);
        Assert.Equal(HttpStatusCode.OK, ok1.StatusCode);
        FleetCollector imported = (await ok1.Content.ReadFromJsonAsync<FleetCollector>(ManagementApiTests.ApiJson, cancellation))!;
        Assert.Equal(FleetStates.OfflineSite, imported.State);
        Assert.Equal("Offline site", imported.Label);
        Assert.Equal("offline-bundle", imported.Path);

        FleetRecord fleet = (await viewer.GetFromJsonAsync<FleetRecord>("/api/fleet", ManagementApiTests.ApiJson, cancellation))!;
        Assert.Contains(fleet.Collectors, c => c.Id == "airgap-site-01" && c.State == FleetStates.OfflineSite);

        // Replaying bundle 1 fails with 409 Conflict (replay protection).
        using HttpResponseMessage replay = await oper.PostAsJsonAsync("/api/fleet/offline-import", report1, cancellation);
        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);

        // Skipping sequence 2 -> importing sequence 3 fails with 409 Conflict (gap detection).
        string bundle3Path = Path.Combine(directory.Path, "b3.bowerbundle");
        AirGappedBundle.Create(
            bundle3Path,
            new AirGappedBundleManifest(
                AirGappedBundleManifest.CurrentKind, "b3", "airgap-site-01", "airgap-host", "scif-south",
                "1.0.1", "sha256:pol1", "default", 3, exp1.BundleHash,
                11, 20, "sha256:head20", 1, 0, 0, string.Empty, false, Now.AddHours(1).ToString("O")),
            ["{\"eventId\":\"e2\"}"],
            privatePem);
        SignedOfflineSiteReport report3 = AirGappedBundle.Verify(bundle3Path, [publicPem]).OfflineReport!;
        using HttpResponseMessage gap = await oper.PostAsJsonAsync("/api/fleet/offline-import", report3, cancellation);
        Assert.Equal(HttpStatusCode.Conflict, gap.StatusCode);

        // Audit log recorded the import.
        List<AuditRecord> audits = (await viewer.GetFromJsonAsync<List<AuditRecord>>("/api/audit", ManagementApiTests.ApiJson, cancellation))!;
        Assert.Contains(audits, a => a.Action == "fleet.offline-bundle-imported" && a.TargetId == "airgap-site-01");
    }

    private static AirGappedBundleManifest BuildManifest(
        string bundleId,
        string collectorId,
        long sequence,
        string previousHash,
        IReadOnlyList<LedgerEvent> events) =>
        new(
            AirGappedBundleManifest.CurrentKind,
            bundleId,
            collectorId,
            "airgap-host",
            "site-a",
            "1.0.1",
            "sha256:pol",
            "default",
            sequence,
            previousHash,
            events[0].Sequence,
            events[^1].Sequence,
            events[^1].ChainHash,
            events.Count,
            events.Count,
            0,
            string.Empty,
            false,
            Now.ToString("O"));
}

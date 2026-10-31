using System.Formats.Asn1;
using System.Net.Security;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Bower.Source.Syslog;

namespace Bower.UnitTests;

/// <summary>
/// Certificate, client CA and revocation list rotation on a live TLS listener, and the
/// certificates it must refuse. Certificates are generated per test; nothing is written
/// outside a temporary directory.
/// </summary>
public sealed class SyslogTlsRotationTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Fact]
    public async Task ServerCertificateRotation_AppliesWithoutRestartOrDroppingOpenSessions()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 first = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 second = Pki.Issue(ca, "localhost", client: false, notAfter: Now.AddDays(90));
        using X509Certificate2 sender = Pki.Issue(ca, "firewall-01", client: true);
        pki.WriteServer(first);
        pki.WriteAuthorities(ca);
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation);

        Connection open = await Connection.OpenAsync(source, sender, cancellation);
        Assert.Equal(first.Thumbprint, open.ServerThumbprint);
        await open.SendAsync("before rotation", cancellation);
        await sink.WaitForAsync(1, cancellation);

        pki.WriteServer(second);
        SyslogListenerStatus status = await WaitFor(source, value => value.TlsReloads == 1, cancellation);
        Assert.Equal(second.NotAfter.ToUniversalTime(), status.ServerCertificateNotAfter!.Value.UtcDateTime);

        Connection fresh = await Connection.OpenAsync(source, sender, cancellation);
        Assert.Equal(second.Thumbprint, fresh.ServerThumbprint);
        await fresh.SendAsync("new session", cancellation);
        // The session opened before the rotation keeps its connection and its frames.
        await open.SendAsync("after rotation", cancellation);
        await sink.WaitForAsync(3, cancellation);
        status = source.Snapshot()[0];
        Assert.Equal(0, status.TlsSessionsClosed);
        Assert.Equal(0, status.TlsHandshakeFailures);
        await open.DisposeAsync();
        await fresh.DisposeAsync();
    }

    [Fact]
    public async Task OneBundleFile_ServesTheCertificateAndKeyAndRotatesAtomically()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 first = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 second = Pki.Issue(ca, "localhost", client: false);
        string bundle = Path.Combine(directory.Path, "server-bundle.pem");
        File.WriteAllText(bundle, first.ExportCertificatePem() + "\n" + first.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());
        string listener = Listener(pki, mutual: false, revocationList: false)
            .Replace(JsonSerializer.Serialize(pki.Certificate), JsonSerializer.Serialize(bundle), StringComparison.Ordinal)
            .Replace(JsonSerializer.Serialize(pki.Key), JsonSerializer.Serialize(bundle), StringComparison.Ordinal);
        await using SyslogSource source = new(SyslogSourceConfigurationLoader.Parse(SyslogSourceTests.Config(listener)), new SyslogSourceTests.FakeSink())
        {
            TlsReloadInterval = TimeSpan.FromMilliseconds(10)
        };
        await source.StartAsync(cancellation);
        await using (Connection connection = await Connection.OpenAsync(source, null, cancellation))
        {
            Assert.Equal(first.Thumbprint, connection.ServerThumbprint);
        }

        File.WriteAllText(bundle + ".new", second.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem() + "\n" + second.ExportCertificatePem());
        File.Move(bundle + ".new", bundle, overwrite: true);
        await WaitFor(source, value => value.TlsReloads == 1, cancellation);
        await using Connection rotated = await Connection.OpenAsync(source, null, cancellation);
        Assert.Equal(second.Thumbprint, rotated.ServerThumbprint);
    }

    [Fact]
    public async Task FailedReload_KeepsLastGoodMaterialUntilTheFilesAreValid()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 first = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 second = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 unrelated = Pki.Issue(ca, "localhost", client: false);
        pki.WriteServer(first);
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation, mutual: false);

        // A certificate written before its key: the pair does not match, so nothing changes.
        File.WriteAllText(pki.Certificate, second.ExportCertificatePem());
        File.WriteAllText(pki.Key, unrelated.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());
        long failures = (await WaitFor(source, value => value.TlsReloadFailures >= 1, cancellation)).TlsReloadFailures;
        await using (Connection stillFirst = await Connection.OpenAsync(source, null, cancellation))
        {
            Assert.Equal(first.Thumbprint, stillFirst.ServerThumbprint);
        }

        // A truncated file is another failure, not an outage.
        File.WriteAllText(pki.Key, "-----BEGIN PRIVATE KEY-----\nAAAA");
        await WaitFor(source, value => value.TlsReloadFailures > failures, cancellation);

        pki.WriteServer(second);
        await WaitFor(source, value => value.TlsReloads == 1, cancellation);
        await using Connection rotated = await Connection.OpenAsync(source, null, cancellation);
        Assert.Equal(second.Thumbprint, rotated.ServerThumbprint);
        Assert.Equal(0, source.Snapshot()[0].TlsHandshakeFailures);
    }

    [Fact]
    public async Task ClientAuthorityRotation_OverlapsThenClosesSessionsOfTheRemovedAuthority()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 oldCa = Pki.Authority("old-ca");
        using X509Certificate2 newCa = Pki.Authority("new-ca");
        using X509Certificate2 server = Pki.Issue(oldCa, "localhost", client: false);
        using X509Certificate2 oldSender = Pki.Issue(oldCa, "firewall-01", client: true);
        using X509Certificate2 newSender = Pki.Issue(newCa, "firewall-01", client: true);
        pki.WriteServer(server);
        pki.WriteAuthorities(oldCa);
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation);

        Connection old = await Connection.OpenAsync(source, oldSender, cancellation);
        await old.SendAsync("old authority", cancellation);
        await sink.WaitForAsync(1, cancellation);
        Assert.False(await Connection.TryDeliverAsync(source, newSender, "too early", cancellation));
        await WaitFor(source, value => value.TlsHandshakeFailures == 1, cancellation);

        // Overlap: both authorities in one bundle; the open session continues.
        pki.WriteAuthorities(oldCa, newCa);
        await WaitFor(source, value => value.TlsReloads == 1, cancellation);
        Assert.True(await Connection.TryDeliverAsync(source, newSender, "new authority", cancellation));
        await old.SendAsync("old during overlap", cancellation);
        await sink.WaitForAsync(3, cancellation);

        // Removal: the old authority's open session is closed before its next frame is used.
        pki.WriteAuthorities(newCa);
        await WaitFor(source, value => value.TlsReloads == 2, cancellation);
        await old.SendAsync("old after removal", cancellation);
        await WaitFor(source, value => value.TlsSessionsClosed == 1, cancellation);
        Assert.Equal(0, await old.ReadAsync(cancellation));
        Assert.False(await Connection.TryDeliverAsync(source, oldSender, "old reconnect", cancellation));
        Assert.True(await Connection.TryDeliverAsync(source, newSender, "new after removal", cancellation));
        await sink.WaitForAsync(4, cancellation);
        Assert.DoesNotContain(sink.Records, record => record.Contains("old after removal", StringComparison.Ordinal));
        Assert.DoesNotContain(sink.Records, record => record.Contains("old reconnect", StringComparison.Ordinal));
        await old.DisposeAsync();
    }

    [Fact]
    public async Task RevocationList_RefusesListedSendersAndClosesTheirOpenSessions()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 good = Pki.Issue(ca, "firewall-01", client: true);
        using X509Certificate2 stolen = Pki.Issue(ca, "firewall-02", client: true);
        pki.WriteServer(server);
        pki.WriteAuthorities(ca);
        pki.WriteRevocations(Pki.RevocationList(ca, [stolen]));
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation, revocationList: true);
        Assert.Equal(Now.AddDays(7).UtcDateTime, source.Snapshot()[0].ClientRevocationListNextUpdate!.Value.UtcDateTime, TimeSpan.FromSeconds(1));

        Assert.False(await Connection.TryDeliverAsync(source, stolen, "revoked", cancellation));
        SyslogListenerStatus status = await WaitFor(source, value => value.TlsRevoked == 1, cancellation);
        Assert.Equal(1, status.TlsHandshakeFailures);
        Connection open = await Connection.OpenAsync(source, good, cancellation);
        await open.SendAsync("good sender", cancellation);
        await sink.WaitForAsync(1, cancellation);

        // Emergency revocation of a sender that is already connected.
        pki.WriteRevocations(Pki.RevocationList(ca, [stolen, good], number: 2));
        await WaitFor(source, value => value.TlsReloads == 1, cancellation);
        await open.SendAsync("after revocation", cancellation);
        await WaitFor(source, value => value.TlsSessionsClosed == 1, cancellation);
        Assert.False(await Connection.TryDeliverAsync(source, good, "reconnect", cancellation));
        Assert.Single(sink.Records);
        await open.DisposeAsync();
    }

    [Theory]
    [InlineData("stale")]
    [InlineData("forged")]
    [InlineData("unknown-issuer")]
    public async Task RevocationList_FailsClosedWhenRevocationStatusCannotBeEstablished(string kind)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 other = Pki.Authority("other-ca");
        using X509Certificate2 impostor = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 sender = Pki.Issue(kind == "unknown-issuer" ? other : ca, "firewall-01", client: true);
        pki.WriteServer(server);
        pki.WriteAuthorities(ca, other);
        pki.WriteRevocations(kind switch
        {
            // Past nextUpdate: an attacker could be replaying an old list.
            "stale" => Pki.RevocationList(ca, [], thisUpdate: Now.AddDays(-9), nextUpdate: Now.AddDays(-2)),
            // Same issuer name, different key: the signature does not verify.
            "forged" => Pki.RevocationList(impostor, []),
            // The sender's CA has no list at all.
            _ => Pki.RevocationList(ca, [])
        });
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation, revocationList: true);

        Assert.False(await Connection.TryDeliverAsync(source, sender, "unverifiable", cancellation));
        await WaitFor(source, value => value.TlsRevoked == 1, cancellation);
        Assert.Empty(sink.Records);
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("not-yet-valid")]
    [InlineData("server-purpose-only")]
    [InlineData("expired-authority")]
    public async Task ClientCertificates_OutsideTheirValidityOrPurposeAreRefused(string kind)
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 expiredCa = Pki.Authority("expired-ca", notBefore: Now.AddDays(-30), notAfter: Now.AddDays(-1));
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 sender = kind switch
        {
            "expired" => Pki.Issue(ca, "firewall-01", client: true, notBefore: Now.AddDays(-10), notAfter: Now.AddDays(-1)),
            "not-yet-valid" => Pki.Issue(ca, "firewall-01", client: true, notBefore: Now.AddDays(1), notAfter: Now.AddDays(10)),
            "server-purpose-only" => Pki.Issue(ca, "firewall-01", client: false),
            _ => Pki.Issue(expiredCa, "firewall-01", client: true, notBefore: Now.AddDays(-20), notAfter: Now.AddDays(-2))
        };
        pki.WriteServer(server);
        pki.WriteAuthorities(ca, expiredCa);
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation);

        Assert.False(await Connection.TryDeliverAsync(source, sender, "refused", cancellation));
        await WaitFor(source, value => value.TlsHandshakeFailures == 1, cancellation);
        Assert.Empty(sink.Records);
    }

    [Fact]
    public async Task RevocationList_RequiresAuthorityAndRefusesUnreadableListsWithoutLeakingThem()
    {
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        pki.WriteServer(server);
        pki.WriteAuthorities(ca);
        string listener = Listener(pki, mutual: false, revocationList: true);
        InvalidDataException config = Assert.Throws<InvalidDataException>(() => SyslogSourceConfigurationLoader.Parse(SyslogSourceTests.Config(listener)));
        Assert.Contains("clientCertificateRevocationListFile requires", config.Message, StringComparison.Ordinal);

        File.WriteAllText(pki.Revocations, "-----BEGIN X509 CRL-----\nc2VjcmV0LWxpc3Q=\n-----END X509 CRL-----\n");
        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using SyslogSource source = await Start(pki, new SyslogSourceTests.FakeSink(), TestContext.Current.CancellationToken, revocationList: true);
        });
        Assert.Equal("Syslog listener edge: TLS certificate or key could not be loaded.", failure.Message);
    }

    [Fact]
    public void RevocationListParser_ReadsPemAndDerAndRefusesUnsupportedLists()
    {
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 rsaCa = Pki.RsaAuthority("rsa-ca");
        using X509Certificate2 sender = Pki.Issue(ca, "firewall-01", client: true);
        byte[] ecdsa = Pki.RevocationList(ca, [sender]);
        byte[] rsa = new CertificateRevocationListBuilder().Build(rsaCa, 1, Now.AddDays(1), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);

        CertificateRevocationList der = Assert.Single(CertificateRevocationList.Load(ecdsa));
        Assert.True(der.IsSignedBy(ca));
        Assert.False(der.IsSignedBy(rsaCa));
        Assert.True(der.IsRevoked(sender.SerialNumberBytes.Span));
        // A sign-padded serial (leading zero byte) is the same number.
        Assert.True(der.IsRevoked([0, .. sender.SerialNumberBytes.Span]));
        Assert.Equal(ca.SubjectName.RawData, der.Issuer);

        string pem = PemEncoding.WriteString("X509 CRL", ecdsa) + "\n" + PemEncoding.WriteString("X509 CRL", rsa);
        IReadOnlyList<CertificateRevocationList> both = CertificateRevocationList.Load(Encoding.ASCII.GetBytes(pem));
        Assert.Equal(2, both.Count);
        Assert.True(both[1].IsSignedBy(rsaCa));

        // RSA-PSS lists, critical extensions (delta lists) and a missing nextUpdate are refused.
        byte[] pss = new CertificateRevocationListBuilder().Build(rsaCa, 1, Now.AddDays(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.ThrowsAny<CryptographicException>(() => CertificateRevocationList.Load(pss));
        Assert.ThrowsAny<CryptographicException>(() => CertificateRevocationList.Load(Pki.HandBuiltList(ca, criticalExtension: true, nextUpdate: true)));
        Assert.ThrowsAny<CryptographicException>(() => CertificateRevocationList.Load(Pki.HandBuiltList(ca, criticalExtension: false, nextUpdate: false)));
        Assert.Single(CertificateRevocationList.Load(Pki.HandBuiltList(ca, criticalExtension: false, nextUpdate: true)));
        Assert.ThrowsAny<Exception>(() => CertificateRevocationList.Load([0x30, 0x03, 0x02, 0x01]));
    }

    [Fact]
    public async Task SameNameReKeyedAuthority_UsesOnlyTheListSignedByTheIssuingKey()
    {
        // A CA re-keyed under the same subject: during the overlap the bundle holds both CA
        // certificates and the file holds both lists. Each sender is judged by the list its
        // own issuer's key signed; a same-name list signed by the other key is ignored.
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 oldCa = Pki.Authority("syslog-ca");
        using X509Certificate2 newCa = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(oldCa, "localhost", client: false);
        using X509Certificate2 oldSender = Pki.Issue(oldCa, "firewall-01", client: true);
        using X509Certificate2 newSender = Pki.Issue(newCa, "firewall-02", client: true);
        using X509Certificate2 revokedNew = Pki.Issue(newCa, "firewall-03", client: true);
        pki.WriteServer(server);
        pki.WriteAuthorities(oldCa, newCa);
        pki.WriteRevocationLists(Pki.RevocationList(oldCa, []), Pki.RevocationList(newCa, [revokedNew]));
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation, revocationList: true);

        Assert.True(await Connection.TryDeliverAsync(source, oldSender, "old key", cancellation));
        Assert.True(await Connection.TryDeliverAsync(source, newSender, "new key", cancellation));
        Assert.False(await Connection.TryDeliverAsync(source, revokedNew, "revoked by new key", cancellation));
        await WaitFor(source, value => value.TlsRevoked == 1, cancellation);
        await sink.WaitForAsync(2, cancellation);

        // Only the new key's list left: the old key's senders have no list and fail closed.
        pki.WriteRevocationLists(Pki.RevocationList(newCa, [revokedNew], number: 2));
        await WaitFor(source, value => value.TlsReloads >= 1, cancellation);
        Assert.False(await Connection.TryDeliverAsync(source, oldSender, "old key without a list", cancellation));
        Assert.True(await Connection.TryDeliverAsync(source, newSender, "new key still listed", cancellation));
        await WaitFor(source, value => value.TlsRevoked == 2, cancellation);
    }

    [Fact]
    public async Task CriticalIssuingDistributionPoint_ScopesTheListToItsDistributionPoint()
    {
        // AD CS and other enterprise CAs mark the issuing distribution point critical.
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        const string Point = "http://crl.example.test/syslog-ca.crl";
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 sender = Pki.Issue(ca, "firewall-01", client: true, distributionPoint: Point);
        using X509Certificate2 revoked = Pki.Issue(ca, "firewall-02", client: true, distributionPoint: Point);
        using X509Certificate2 elsewhere = Pki.Issue(ca, "firewall-03", client: true, distributionPoint: "http://crl.example.test/other.crl");
        pki.WriteServer(server);
        pki.WriteAuthorities(ca);
        pki.WriteRevocationLists(Pki.ScopedList(ca, [revoked], writer =>
        {
            Pki.FullName(writer, Point);
            writer.WriteBoolean(true, new Asn1Tag(TagClass.ContextSpecific, 1)); // onlyContainsUserCerts
        }));
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation, revocationList: true);

        Assert.True(await Connection.TryDeliverAsync(source, sender, "in scope", cancellation));
        Assert.False(await Connection.TryDeliverAsync(source, revoked, "listed", cancellation));
        // A list for another distribution point does not establish this sender's status.
        Assert.False(await Connection.TryDeliverAsync(source, elsewhere, "out of scope", cancellation));
        await WaitFor(source, value => value.TlsRevoked == 2, cancellation);
        Assert.Single(sink.Records);
    }

    public static TheoryData<string, string> UnsupportedScopes => new()
    {
        { "reasons", "client revocation lists limited to some revocation reasons are not supported." },
        { "indirect", "indirect client revocation lists are not supported." },
        { "relative", "client revocation list distribution points relative to the issuer are not supported." }
    };

    [Theory]
    [MemberData(nameof(UnsupportedScopes))]
    public async Task UnsupportedListScope_StopsStartWithAClearMessage(string scope, string message)
    {
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        pki.WriteServer(server);
        pki.WriteAuthorities(ca);
        pki.WriteRevocationLists(Pki.ScopedList(ca, [], writer =>
        {
            switch (scope)
            {
                case "reasons":
                    writer.WriteBitString([0x60], 1, new Asn1Tag(TagClass.ContextSpecific, 3));
                    break;
                case "indirect":
                    writer.WriteBoolean(true, new Asn1Tag(TagClass.ContextSpecific, 4));
                    break;
                default:
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("2.5.4.3");
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, "relative");
                    }

                    break;
            }
        }));
        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using SyslogSource source = await Start(pki, new SyslogSourceTests.FakeSink(), TestContext.Current.CancellationToken, revocationList: true);
        });
        Assert.Equal($"Syslog listener edge: {message}", failure.Message);
    }

    [Fact]
    public async Task ValidSenderUnderAnExpiredAuthority_IsRefusedAndItsOpenSessionClosed()
    {
        // The sender's certificate is valid, but the only trusted copy of its CA has expired
        // (a CA certificate re-issued with the same key and subject was not deployed).
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 current = Pki.AuthorityWithKey("syslog-ca", caKey, Now.AddDays(-60), Now.AddDays(30));
        using X509Certificate2 expired = Pki.AuthorityWithKey("syslog-ca", caKey, Now.AddDays(-60), Now.AddDays(-1));
        using X509Certificate2 server = Pki.Issue(current, "localhost", client: false);
        using X509Certificate2 sender = Pki.Issue(current, "firewall-01", client: true);
        pki.WriteServer(server);
        pki.WriteAuthorities(current);
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation);
        Connection open = await Connection.OpenAsync(source, sender, cancellation);
        await open.SendAsync("trusted", cancellation);
        await sink.WaitForAsync(1, cancellation);

        pki.WriteAuthorities(expired);
        await WaitFor(source, value => value.TlsReloads >= 1, cancellation);
        await open.SendAsync("after the anchor expired", cancellation);
        await WaitFor(source, value => value.TlsSessionsClosed == 1, cancellation);
        Assert.False(await Connection.TryDeliverAsync(source, sender, "reconnect", cancellation));
        Assert.Single(sink.Records);
        await open.DisposeAsync();
    }

    [Fact]
    public async Task NonRegularFile_IsRefusedWithoutBlockingAndTheLastGoodMaterialStays()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "FIFOs are a Unix file type.");
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        using X509Certificate2 server = Pki.Issue(ca, "localhost", client: false);
        using X509Certificate2 sender = Pki.Issue(ca, "firewall-01", client: true);
        pki.WriteServer(server);
        pki.WriteAuthorities(ca);
        SyslogSourceTests.FakeSink sink = new();
        await using SyslogSource source = await Start(pki, sink, cancellation);

        string fifo = Path.Combine(directory.Path, "fifo");
        using (System.Diagnostics.Process mkfifo = System.Diagnostics.Process.Start("mkfifo", fifo)!)
        {
            await mkfifo.WaitForExitAsync(cancellation);
        }

        File.Move(fifo, pki.Authorities, overwrite: true);
        await WaitFor(source, value => value.TlsReloadFailures >= 1, cancellation);
        Assert.True(await Connection.TryDeliverAsync(source, sender, "last good material", cancellation));
        pki.WriteAuthorities(ca);
        await sink.WaitForAsync(1, cancellation);
        Assert.Equal(0, source.Snapshot()[0].TlsReloads);
    }

    [Fact]
    public async Task RepeatedReloads_DisposeSupersededMaterialOnceNoHandshakeHoldsIt()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        Pki pki = new(directory.Path);
        using X509Certificate2 ca = Pki.Authority("syslog-ca");
        SyslogSourceTests.FakeSink sink = new();
        using (X509Certificate2 first = Pki.Issue(ca, "localhost", client: false))
        {
            pki.WriteServer(first);
        }

        await using SyslogSource source = await Start(pki, sink, cancellation, mutual: false);
        for (int index = 1; index <= 10; index++)
        {
            using X509Certificate2 next = Pki.Issue(ca, "localhost", client: false);
            pki.WriteBundle(next);
            await WaitFor(source, value => value.TlsReloads == index, cancellation);
        }

        Assert.Equal(1, source.TlsMaterialsAlive("edge"));

        // A handshake in flight holds its generation across a reload.
        using TcpClient pending = new(AddressFamily.InterNetwork);
        await pending.ConnectAsync(source.Endpoints["edge"], cancellation);
        await WaitFor(source, value => value.ActiveConnections == 1, cancellation);
        using (X509Certificate2 next = Pki.Issue(ca, "localhost", client: false))
        {
            pki.WriteBundle(next);
        }

        await WaitFor(source, value => value.TlsReloads == 11, cancellation);
        Assert.Equal(2, source.TlsMaterialsAlive("edge"));
        pending.Close();
        await WaitFor(source, value => value.ActiveConnections == 0, cancellation);
        Assert.Equal(1, source.TlsMaterialsAlive("edge"));
    }

    private static async Task<SyslogSource> Start(Pki pki, SyslogSourceTests.FakeSink sink, CancellationToken cancellation,
        bool mutual = true, bool revocationList = false)
    {
        SyslogSource source = new(SyslogSourceConfigurationLoader.Parse(SyslogSourceTests.Config(Listener(pki, mutual, revocationList))), sink)
        {
            RetryDelay = TimeSpan.FromMilliseconds(20),
            TlsReloadInterval = TimeSpan.FromMilliseconds(10)
        };
        try
        {
            await source.StartAsync(cancellation);
        }
        catch
        {
            await source.DisposeAsync();
            throw;
        }

        return source;
    }

    private static string Listener(Pki pki, bool mutual, bool revocationList)
    {
        string tls = $$"""{"certificateFile": {{JsonSerializer.Serialize(pki.Certificate)}}, "privateKeyFile": {{JsonSerializer.Serialize(pki.Key)}}""";
        tls += mutual ? $$""", "clientCertificateAuthorityFile": {{JsonSerializer.Serialize(pki.Authorities)}}""" : "";
        tls += revocationList ? $$""", "clientCertificateRevocationListFile": {{JsonSerializer.Serialize(pki.Revocations)}}""" : "";
        return $$"""
            "id": "edge", "protocol": "tls", "address": "127.0.0.1", "port": 0,
            "allowedSenders": ["127.0.0.1"], "maximumMessageBytes": 512, "idleTimeoutSeconds": 30,
            "tls": {{tls}}},
            "routes": [{"appName": "sshd", "pack": "linux-ssh-gateway", "parser": 0}]
            """;
    }

    private static async Task<SyslogListenerStatus> WaitFor(SyslogSource source, Func<SyslogListenerStatus, bool> condition, CancellationToken cancellation)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (true)
        {
            SyslogListenerStatus status = source.Snapshot()[0];
            if (condition(status))
            {
                return status;
            }

            await Task.Delay(20, timeout.Token);
        }
    }

    /// <summary>A client TLS session that records the server certificate it was shown.</summary>
    private sealed class Connection : IAsyncDisposable
    {
        private readonly TcpClient tcp;
        private readonly SslStream stream;

        private Connection(TcpClient tcp, SslStream stream, string serverThumbprint)
        {
            this.tcp = tcp;
            this.stream = stream;
            ServerThumbprint = serverThumbprint;
        }

        public string ServerThumbprint { get; }

        public static async Task<Connection> OpenAsync(SyslogSource source, X509Certificate2? client, CancellationToken cancellation)
        {
            TcpClient tcp = new(AddressFamily.InterNetwork);
            await tcp.ConnectAsync(source.Endpoints["edge"], cancellation);
            string? seen = null;
            // The tests check which certificate the server presents, not its trust: the
            // sender-side name and chain checks are the sender's configuration.
            SslStream stream = new(tcp.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) =>
            {
                seen = certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()).Thumbprint;
                return certificate is not null;
            });
            try
            {
                await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    ClientCertificates = client is null ? null : new X509CertificateCollection(new X509Certificate[] { client }),
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }, cancellation);
            }
            catch
            {
                await stream.DisposeAsync();
                tcp.Dispose();
                throw;
            }

            return new Connection(tcp, stream, seen!);
        }

        /// <summary>True when a fresh session accepted the frame and stayed open.</summary>
        public static async Task<bool> TryDeliverAsync(SyslogSource source, X509Certificate2 client, string message, CancellationToken cancellation)
        {
            try
            {
                await using Connection connection = await OpenAsync(source, client, cancellation);
                await connection.SendAsync(message, cancellation);
                // TLS 1.3 reports a refused client certificate only on the next read.
                using CancellationTokenSource wait = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                wait.CancelAfter(TimeSpan.FromMilliseconds(500));
                try
                {
                    return await connection.ReadAsync(wait.Token) != 0;
                }
                catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
                {
                    return true;
                }
            }
            catch (Exception exception) when (exception is AuthenticationException or IOException or SocketException)
            {
                return false;
            }
        }

        public async Task SendAsync(string message, CancellationToken cancellation) =>
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"<38>Oct 11 22:14:15 gw01 sshd: {message}\n"), cancellation);

        public async Task<int> ReadAsync(CancellationToken cancellation)
        {
            try
            {
                return await stream.ReadAsync(new byte[1], cancellation);
            }
            catch (IOException)
            {
                return 0;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await stream.DisposeAsync();
            tcp.Dispose();
        }
    }

    /// <summary>Generated test PKI written as PEM files, as an operator would deploy them.</summary>
    private sealed class Pki(string directory)
    {
        public string Certificate { get; } = Path.Combine(directory, "server.pem");

        public string Key { get; } = Path.Combine(directory, "server-key.pem");

        public string Authorities { get; } = Path.Combine(directory, "client-ca.pem");

        public string Revocations { get; } = Path.Combine(directory, "client-ca.crl");

        public void WriteServer(X509Certificate2 certificate)
        {
            // Key first, then certificate: each file replaced atomically by rename.
            Replace(Key, certificate.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());
            Replace(Certificate, certificate.ExportCertificatePem());
        }

        public void WriteAuthorities(params X509Certificate2[] authorities) =>
            Replace(Authorities, string.Join('\n', authorities.Select(authority => authority.ExportCertificatePem())));

        public void WriteRevocations(byte[] der) => Replace(Revocations, PemEncoding.WriteString("X509 CRL", der));

        public void WriteRevocationLists(params byte[][] lists) =>
            Replace(Revocations, string.Join('\n', lists.Select(list => PemEncoding.WriteString("X509 CRL", list))));

        /// <summary>Key and certificate in the two configured files, written in one step each but key first.</summary>
        public void WriteBundle(X509Certificate2 certificate)
        {
            string bundle = certificate.ExportCertificatePem() + "\n" + certificate.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem();
            Replace(Key, bundle);
            Replace(Certificate, bundle);
        }

        public static X509Certificate2 AuthorityWithKey(string name, ECDsa key, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request.CreateSelfSigned(notBefore, notAfter);
        }

        private static void Replace(string path, string content)
        {
            string staging = path + ".new";
            File.WriteAllText(staging, content);
            File.Move(staging, path, overwrite: true);
        }

        public static X509Certificate2 Authority(string name, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request.CreateSelfSigned(notBefore ?? Now.AddDays(-30), notAfter ?? Now.AddDays(30));
        }

        public static X509Certificate2 RsaAuthority(string name)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        }

        public static X509Certificate2 Issue(X509Certificate2 authority, string name, bool client,
            DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, string? distributionPoint = null)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1")], false));
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(authority, true, false));
            if (distributionPoint is not null)
            {
                request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([distributionPoint]));
            }

            if (!client)
            {
                SubjectAlternativeNameBuilder names = new();
                names.AddDnsName(name);
                names.AddIpAddress(System.Net.IPAddress.Loopback);
                request.CertificateExtensions.Add(names.Build());
            }

            byte[] serial = RandomNumberGenerator.GetBytes(16);
            serial[0] &= 0x7F;
            DateTimeOffset start = notBefore ?? Now.AddDays(-1);
            DateTimeOffset end = notAfter ?? Now.AddDays(30);
            // An issued certificate cannot outlive its issuer.
            if (end > authority.NotAfter)
            {
                end = authority.NotAfter;
            }

            using X509Certificate2 issued = request.Create(authority, start, end, serial);
            return issued.CopyWithPrivateKey(key);
        }

        public static byte[] RevocationList(X509Certificate2 authority, X509Certificate2[] revoked, int number = 1,
            DateTimeOffset? thisUpdate = null, DateTimeOffset? nextUpdate = null)
        {
            CertificateRevocationListBuilder builder = new();
            foreach (X509Certificate2 certificate in revoked)
            {
                builder.AddEntry(certificate, Now.AddMinutes(-1));
            }

            return builder.Build(authority, new BigInteger(number), nextUpdate ?? Now.AddDays(7), HashAlgorithmName.SHA256,
                thisUpdate: thisUpdate ?? Now.AddMinutes(-5));
        }

        /// <summary>
        /// An ECDSA list with a critical issuing distribution point (RFC 5280 5.2.5), as AD CS and
        /// other enterprise CAs write; <paramref name="scope"/> writes the IDP's fields.
        /// </summary>
        public static byte[] ScopedList(X509Certificate2 authority, X509Certificate2[] revoked, Action<AsnWriter> scope)
        {
            AsnWriter tbs = new(AsnEncodingRules.DER);
            using (tbs.PushSequence())
            {
                tbs.WriteInteger(1);
                WriteEcdsaSha256(tbs);
                tbs.WriteEncodedValue(authority.SubjectName.RawData);
                tbs.WriteUtcTime(Now.AddMinutes(-5));
                tbs.WriteUtcTime(Now.AddDays(1));
                if (revoked.Length > 0)
                {
                    using (tbs.PushSequence())
                    {
                        foreach (X509Certificate2 certificate in revoked)
                        {
                            using (tbs.PushSequence())
                            {
                                tbs.WriteIntegerUnsigned(certificate.SerialNumberBytes.Span);
                                tbs.WriteUtcTime(Now.AddMinutes(-1));
                            }
                        }
                    }
                }

                AsnWriter point = new(AsnEncodingRules.DER);
                using (point.PushSequence())
                {
                    scope(point);
                }

                using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                using (tbs.PushSequence())
                using (tbs.PushSequence())
                {
                    tbs.WriteObjectIdentifier("2.5.29.28");
                    tbs.WriteBoolean(true);
                    tbs.WriteOctetString(point.Encode());
                }
            }

            return Sign(authority, tbs.Encode());
        }

        /// <summary>IDP <c>distributionPoint</c> = <c>fullName</c> with one URI.</summary>
        public static void FullName(AsnWriter writer, string uri)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, uri, new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }

        private static byte[] Sign(X509Certificate2 authority, byte[] signedPart)
        {
            using ECDsa key = authority.GetECDsaPrivateKey()!;
            byte[] signature = key.SignData(signedPart, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            AsnWriter list = new(AsnEncodingRules.DER);
            using (list.PushSequence())
            {
                list.WriteEncodedValue(signedPart);
                WriteEcdsaSha256(list);
                list.WriteBitString(signature);
            }

            return list.Encode();
        }

        private static void WriteEcdsaSha256(AsnWriter writer)
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.10045.4.3.2");
            }
        }

        /// <summary>A minimal ECDSA list built by hand, to cover encodings the builder never writes.</summary>
        public static byte[] HandBuiltList(X509Certificate2 authority, bool criticalExtension, bool nextUpdate)
        {
            AsnWriter tbs = new(AsnEncodingRules.DER);
            using (tbs.PushSequence())
            {
                tbs.WriteInteger(1);
                WriteAlgorithm(tbs);
                tbs.WriteEncodedValue(authority.SubjectName.RawData);
                tbs.WriteUtcTime(Now.AddMinutes(-5));
                if (nextUpdate)
                {
                    tbs.WriteUtcTime(Now.AddDays(1));
                }

                if (criticalExtension)
                {
                    using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    using (tbs.PushSequence())
                    using (tbs.PushSequence())
                    {
                        // deltaCRLIndicator
                        tbs.WriteObjectIdentifier("2.5.29.27");
                        tbs.WriteBoolean(true);
                        AsnWriter base_ = new(AsnEncodingRules.DER);
                        base_.WriteInteger(1);
                        tbs.WriteOctetString(base_.Encode());
                    }
                }
            }

            byte[] signedPart = tbs.Encode();
            using ECDsa key = authority.GetECDsaPrivateKey()!;
            byte[] signature = key.SignData(signedPart, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            AsnWriter list = new(AsnEncodingRules.DER);
            using (list.PushSequence())
            {
                list.WriteEncodedValue(signedPart);
                WriteAlgorithm(list);
                list.WriteBitString(signature);
            }

            return list.Encode();

            static void WriteAlgorithm(AsnWriter writer)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.10045.4.3.2");
                }
            }
        }
    }
}

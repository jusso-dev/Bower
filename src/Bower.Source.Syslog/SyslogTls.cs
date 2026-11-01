using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Bower.Source.Syslog;

/// <summary>
/// One TLS listener's certificate, key, client CAs and revocation lists. A background loop
/// (<see cref="Refresh"/>) reads the files and swaps in new material when they change; the
/// connection and frame paths only read the current reference. A change that cannot be
/// loaded keeps the last good material, is counted once per distinct content, and is
/// retried every interval. Superseded material is disposed once no handshake holds it.
/// </summary>
internal sealed class SyslogTlsSource : IDisposable
{
    private readonly SyslogListenerOptions options;
    private SyslogTlsMaterial current;
    private byte[] stamp;
    private string? lastFailure;
    private long reloads;
    private long reloadFailures;
    private int alive;

    /// <summary>Loads the initial material; any failure stops listener start-up.</summary>
    public SyslogTlsSource(SyslogListenerOptions options)
    {
        this.options = options;
        SyslogTlsFiles files = SyslogTlsMaterial.ReadFilesOrThrow(options);
        current = SyslogTlsMaterial.Load(options, files, 1, Track());
        stamp = files.Stamp;
    }

    public long Reloads => Interlocked.Read(ref reloads);

    public long ReloadFailures => Interlocked.Read(ref reloadFailures);

    /// <summary>Generations created and not yet disposed (the current one plus any held by a handshake).</summary>
    public int MaterialsAlive => Volatile.Read(ref alive);

    /// <summary>The current material, for reading its generation and dates only (no handles).</summary>
    public SyslogTlsMaterial Peek => Volatile.Read(ref current);

    /// <summary>The current material, held until <see cref="SyslogTlsMaterial.Release"/>.</summary>
    public SyslogTlsMaterial Acquire()
    {
        while (true)
        {
            SyslogTlsMaterial material = Volatile.Read(ref current);
            if (material.TryAcquire())
            {
                return material;
            }
        }
    }

    /// <summary>
    /// Reads the files once and swaps in new material when their content changed. Called by
    /// one background loop only; never on a connection or frame path.
    /// </summary>
    public void Refresh()
    {
        SyslogTlsFiles files;
        try
        {
            files = SyslogTlsMaterial.ReadFiles(options);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            Failed("read:" + exception.GetType().Name);
            return;
        }

        if (files.Stamp.AsSpan().SequenceEqual(stamp))
        {
            lastFailure = null;
            return;
        }

        SyslogTlsMaterial next;
        try
        {
            next = SyslogTlsMaterial.Load(options, files, Peek.Generation + 1, Track());
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // The stamp stays put, so the same files are tried again next interval (a
            // rotation that is still being written completes) but counted once.
            Failed(Convert.ToHexString(files.Stamp));
            return;
        }

        SyslogTlsMaterial previous = Interlocked.Exchange(ref current, next);
        stamp = files.Stamp;
        lastFailure = null;
        // Publish completion only after releasing the source's old reference. An in-flight
        // handshake can still hold the old generation until that handshake ends.
        previous.Release();
        Interlocked.Increment(ref reloads);
    }

    public void Dispose() => Volatile.Read(ref current).Release();

    private void Failed(string key)
    {
        if (!string.Equals(key, lastFailure, StringComparison.Ordinal))
        {
            lastFailure = key;
            Interlocked.Increment(ref reloadFailures);
        }
    }

    private Action Track()
    {
        Interlocked.Increment(ref alive);
        return () => Interlocked.Decrement(ref alive);
    }
}

/// <summary>Every configured TLS file, read once, and the digest of exactly those bytes.</summary>
internal sealed record SyslogTlsFiles(byte[] Certificate, byte[] Key, byte[]? Authorities, byte[]? RevocationLists, byte[] Stamp);

/// <summary>
/// Loaded TLS material for one generation. Reference counted: the source holds one
/// reference and each handshake or re-validation holds another; the certificates and keys
/// are disposed when the last is released.
/// </summary>
internal sealed class SyslogTlsMaterial
{
    /// <summary>Largest certificate, key, CA bundle or revocation list file read.</summary>
    public const int MaximumFileBytes = 8 * 1024 * 1024;

    private static readonly Oid ClientAuthentication = new("1.3.6.1.5.5.7.3.2");

    private readonly SslStreamCertificateContext serverContext;
    private readonly X509Certificate2 server;
    private readonly X509Certificate2Collection owned;
    private readonly X509ChainPolicy? clientPolicy;
    private readonly IReadOnlyList<CertificateRevocationList> revocationLists;
    private readonly Action? disposed;
    private int references = 1;

    private SyslogTlsMaterial(
        long generation,
        X509Certificate2 server,
        X509Certificate2Collection owned,
        SslStreamCertificateContext serverContext,
        X509ChainPolicy? clientPolicy,
        IReadOnlyList<CertificateRevocationList> revocationLists,
        DateTimeOffset? clientCertificateAuthorityNotAfter,
        Action? disposed)
    {
        Generation = generation;
        this.server = server;
        this.owned = owned;
        this.serverContext = serverContext;
        this.clientPolicy = clientPolicy;
        this.revocationLists = revocationLists;
        this.disposed = disposed;
        ServerCertificateNotAfter = new DateTimeOffset(server.NotAfter.ToUniversalTime());
        ClientCertificateAuthorityNotAfter = clientCertificateAuthorityNotAfter;
        ClientRevocationListNextUpdate = revocationLists.Count == 0
            ? null
            : revocationLists.Min(list => list.NextUpdate);
    }

    public long Generation { get; }

    public DateTimeOffset ServerCertificateNotAfter { get; }

    /// <summary>Earliest expiry among the trusted client CAs.</summary>
    public DateTimeOffset? ClientCertificateAuthorityNotAfter { get; }

    /// <summary>Earliest <c>nextUpdate</c> among the revocation lists.</summary>
    public DateTimeOffset? ClientRevocationListNextUpdate { get; }

    public bool TryAcquire()
    {
        int seen;
        do
        {
            seen = Volatile.Read(ref references);
            if (seen == 0)
            {
                return false;
            }
        }
        while (Interlocked.CompareExchange(ref references, seen + 1, seen) != seen);
        return true;
    }

    public void Release()
    {
        if (Interlocked.Decrement(ref references) != 0)
        {
            return;
        }

        foreach (X509Certificate2 certificate in serverContext.IntermediateCertificates)
        {
            certificate.Dispose();
        }

        foreach (X509Certificate2 certificate in owned)
        {
            certificate.Dispose();
        }

        server.Dispose();
        disposed?.Invoke();
    }

    /// <summary>Reads every configured file once (regular, non-empty files only).</summary>
    public static SyslogTlsFiles ReadFiles(SyslogListenerOptions options)
    {
        SyslogTlsOptions tls = options.Tls!;
        byte[] certificate = ReadBounded(tls.CertificateFile);
        // One bundle file may hold both the certificate chain and the key.
        byte[] key = string.Equals(tls.PrivateKeyFile, tls.CertificateFile, StringComparison.Ordinal)
            ? certificate
            : ReadBounded(tls.PrivateKeyFile);
        byte[]? authorities = tls.ClientCertificateAuthorityFile is { } authorityFile ? ReadBounded(authorityFile) : null;
        byte[]? lists = tls.ClientCertificateRevocationListFile is { } listFile ? ReadBounded(listFile) : null;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (byte[]? part in new[] { certificate, key, authorities, lists })
        {
            hash.AppendData(part is null ? [0] : SHA256.HashData(part));
        }

        return new SyslogTlsFiles(certificate, key, authorities, lists, hash.GetHashAndReset());
    }

    /// <summary><see cref="ReadFiles"/> with the start-up error message (no path or content).</summary>
    public static SyslogTlsFiles ReadFilesOrThrow(SyslogListenerOptions options)
    {
        try
        {
            return ReadFiles(options);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw new InvalidOperationException($"Syslog listener {options.Id}: TLS certificate or key could not be loaded.");
        }
    }

    /// <summary>Checks that a listener's TLS files load, as start-up and a reload pre-check do.</summary>
    public static void Validate(SyslogListenerOptions options) =>
        Load(options, ReadFilesOrThrow(options), 0, null).Release();

    public static SyslogTlsMaterial Load(SyslogListenerOptions options, SyslogTlsFiles files, long generation, Action? disposed)
    {
        X509Certificate2Collection owned = [];
        X509Certificate2? server = null;
        try
        {
            string certificateText = Encoding.UTF8.GetString(files.Certificate);
            X509Certificate2Collection chain = [];
            chain.ImportFromPem(certificateText);
            owned.AddRange(chain);
            using X509Certificate2 pem = X509Certificate2.CreateFromPem(certificateText, Encoding.UTF8.GetString(files.Key));
            // Re-import so the key is usable by SslStream on every platform (PEM keys are ephemeral).
            server = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
            X509Certificate2Collection intermediates = [.. chain.Skip(1)];
            X509ChainPolicy? clientPolicy = null;
            DateTimeOffset? authorityNotAfter = null;
            if (files.Authorities is { } authorityBytes)
            {
                X509Certificate2Collection authorities = [];
                authorities.ImportFromPem(Encoding.UTF8.GetString(authorityBytes));
                owned.AddRange(authorities);
                if (authorities.Count == 0)
                {
                    throw new CryptographicException("No client certificate authority.");
                }

                // Client chains are built by SslStream with this policy, which adds the
                // intermediates the sender supplies; only the configured CAs are trusted and
                // an expired CA fails the chain. Revocation is checked by Bower, offline.
                clientPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck
                };
                clientPolicy.CustomTrustStore.AddRange(authorities);
                clientPolicy.ApplicationPolicy.Add(ClientAuthentication);
                authorityNotAfter = authorities.Min(authority => new DateTimeOffset(authority.NotAfter.ToUniversalTime()));
            }

            IReadOnlyList<CertificateRevocationList> lists = files.RevocationLists is { } listBytes
                ? CertificateRevocationList.Load(listBytes)
                : [];
            return new SyslogTlsMaterial(generation, server,
                owned, SslStreamCertificateContext.Create(server, intermediates, offline: true),
                clientPolicy, lists, authorityNotAfter, disposed);
        }
        catch (UnsupportedRevocationListException unsupported)
        {
            Discard();
            throw new InvalidOperationException($"Syslog listener {options.Id}: {unsupported.Message}");
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            Discard();
            // Never echo key material, file contents or the underlying parser message.
            throw new InvalidOperationException($"Syslog listener {options.Id}: TLS certificate or key could not be loaded.");
        }

        void Discard()
        {
            server?.Dispose();
            foreach (X509Certificate2 certificate in owned)
            {
                certificate.Dispose();
            }

            disposed?.Invoke();
        }
    }

    /// <summary>
    /// Reads one TLS file. Refuses directories and anything that is not a non-empty regular
    /// file (a FIFO, device or socket reports no size and is never opened, so a read cannot block).
    /// </summary>
    internal static byte[] ReadBounded(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists || info.Length <= 0 || info.Length > MaximumFileBytes)
        {
            throw new IOException("TLS file is missing, empty, too large or not a regular file.");
        }

        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (!stream.CanSeek || stream.Length <= 0 || stream.Length > MaximumFileBytes)
        {
            throw new IOException("TLS file is not a regular file.");
        }

        byte[] bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    /// <summary>Handshake options for one connection; its accepted client chain is kept in <paramref name="session"/>.</summary>
    public SslServerAuthenticationOptions CreateOptions(SyslogTlsSession session, TimeProvider clock) => new()
    {
        ServerCertificateContext = serverContext,
        // Same protocol floor as the Rust port (rustls: TLS 1.2 and 1.3).
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        ClientCertificateRequired = clientPolicy is not null,
        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        CertificateChainPolicy = clientPolicy?.Clone(),
        RemoteCertificateValidationCallback = clientPolicy is null
            ? null
            : (_, certificate, chain, errors) => Accept(certificate, chain, errors, clock.GetUtcNow(), session)
    };

    private bool Accept(X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors, DateTimeOffset now, SyslogTlsSession session)
    {
        if (certificate is not X509Certificate2 leaf || chain is null || errors != SslPolicyErrors.None)
        {
            return false;
        }

        X509Certificate2? issuer = chain.ChainElements.Count > 1 ? chain.ChainElements[1].Certificate : null;
        if (!NotRevoked(leaf, issuer, now))
        {
            session.Revoked = true;
            return false;
        }

        session.Accept(this, leaf, chain);
        return true;
    }

    /// <summary>
    /// Validates an open session's client certificate against this material: its chain to a
    /// currently trusted, unexpired CA, the validity of every certificate and the lists.
    /// </summary>
    public bool StillTrusted(SyslogTlsSession session, DateTimeOffset now)
    {
        if (clientPolicy is null)
        {
            return true;
        }

        if (session.Leaf is null)
        {
            return false;
        }

        using X509Chain chain = new() { ChainPolicy = clientPolicy.Clone() };
        chain.ChainPolicy.ExtraStore.AddRange(session.Intermediates);
        try
        {
            if (!chain.Build(session.Leaf))
            {
                return false;
            }

            X509Certificate2? issuer = chain.ChainElements.Count > 1 ? chain.ChainElements[1].Certificate : null;
            if (!NotRevoked(session.Leaf, issuer, now))
            {
                return false;
            }

            session.Accept(this, session.Leaf, chain);
            return true;
        }
        finally
        {
            foreach (X509ChainElement element in chain.ChainElements)
            {
                if (!ReferenceEquals(element.Certificate, session.Leaf))
                {
                    element.Certificate.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// End-entity revocation (identical in the Rust port). With lists configured, the lists
    /// that apply are those naming the leaf's issuer, whose scope covers the leaf and whose
    /// signature verifies with the key of the CA that actually issued the leaf; lists with
    /// the same issuer name but another key (a re-keyed CA during overlap) are ignored. The
    /// client is refused when no such list exists, when one lists its serial number, or
    /// when none is current (all past <c>nextUpdate</c>).
    /// </summary>
    private bool NotRevoked(X509Certificate2 leaf, X509Certificate2? issuer, DateTimeOffset now)
    {
        if (revocationLists.Count == 0)
        {
            return true;
        }

        if (issuer is null)
        {
            return false;
        }

        IReadOnlyList<byte[]> distributionPoints = CertificateRevocationList.DistributionPoints(leaf);
        bool any = false;
        bool current = false;
        foreach (CertificateRevocationList list in revocationLists)
        {
            if (!list.Issuer.AsSpan().SequenceEqual(leaf.IssuerName.RawData)
                || !list.Covers(distributionPoints)
                || !list.IsSignedBy(issuer))
            {
                continue;
            }

            any = true;
            if (list.IsRevoked(leaf.SerialNumberBytes.Span))
            {
                return false;
            }

            current |= list.NextUpdate >= now;
        }

        return any && current;
    }
}

/// <summary>One TLS connection's accepted client chain, kept to validate it again after a reload.</summary>
internal sealed class SyslogTlsSession : IDisposable
{
    public X509Certificate2? Leaf { get; private set; }

    public X509Certificate2Collection Intermediates { get; } = [];

    public long Generation { get; private set; }

    /// <summary>When the session must be validated again even without a reload: the first expiry in its chain or list.</summary>
    public DateTimeOffset RevalidateAt { get; private set; } = DateTimeOffset.MaxValue;

    public bool Revoked { get; set; }

    public void Dispose()
    {
        Leaf?.Dispose();
        foreach (X509Certificate2 intermediate in Intermediates)
        {
            intermediate.Dispose();
        }
    }

    public void Accept(SyslogTlsMaterial material, X509Certificate2 leaf, X509Chain chain)
    {
        if (!ReferenceEquals(Leaf, leaf))
        {
            Dispose();
            Leaf = X509CertificateLoader.LoadCertificate(leaf.RawData);
            Intermediates.Clear();
            for (int index = 1; index < chain.ChainElements.Count - 1; index++)
            {
                Intermediates.Add(X509CertificateLoader.LoadCertificate(chain.ChainElements[index].Certificate.RawData));
            }
        }

        Generation = material.Generation;
        DateTimeOffset expiry = chain.ChainElements.Min(element => new DateTimeOffset(element.Certificate.NotAfter.ToUniversalTime()));
        RevalidateAt = material.ClientRevocationListNextUpdate is { } next && next < expiry ? next : expiry;
    }
}

/// <summary>A revocation list Bower cannot apply correctly; the message names the feature, never content.</summary>
internal sealed class UnsupportedRevocationListException(string message) : CryptographicException(message);

/// <summary>
/// An X.509 v2 certificate revocation list (RFC 5280 section 5): issuer, validity, scope,
/// revoked serial numbers and the signature, verified against the issuing CA at use.
/// A critical issuing distribution point is processed: a list limited to CA or attribute
/// certificates never covers a sender, and a list naming distribution points covers only
/// certificates whose CRL distribution points name one of them. Indirect lists, lists
/// limited to some revocation reasons, relative distribution point names, delta lists and
/// other critical extensions are refused with a clear message, as are signature
/// algorithms other than RSA PKCS#1 v1.5 and ECDSA with SHA-256/384/512.
/// </summary>
internal sealed class CertificateRevocationList
{
    private const int MaximumLists = 64;
    private const string IssuingDistributionPoint = "2.5.29.28";
    private const string CrlDistributionPoints = "2.5.29.31";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, isConstructed: true);

    private readonly HashSet<string> revoked;
    private readonly byte[] signedPart;
    private readonly byte[] signature;
    private readonly HashAlgorithmName hash;
    private readonly bool ecdsa;
    private readonly IReadOnlyList<byte[]> scopeNames;
    private readonly bool coversSenders;
    private readonly ConcurrentDictionary<string, bool> verified = new(StringComparer.Ordinal);

    private CertificateRevocationList(byte[] issuer, DateTimeOffset nextUpdate, HashSet<string> revoked,
        byte[] signedPart, byte[] signature, HashAlgorithmName hash, bool ecdsa, IReadOnlyList<byte[]> scopeNames,
        bool coversSenders)
    {
        Issuer = issuer;
        NextUpdate = nextUpdate;
        this.revoked = revoked;
        this.signedPart = signedPart;
        this.signature = signature;
        this.hash = hash;
        this.ecdsa = ecdsa;
        this.scopeNames = scopeNames;
        this.coversSenders = coversSenders;
    }

    /// <summary>DER-encoded issuer name, compared byte for byte with a certificate's issuer.</summary>
    public byte[] Issuer { get; }

    public DateTimeOffset NextUpdate { get; }

    /// <summary>One or more PEM <c>X509 CRL</c> blocks, or a single DER list.</summary>
    public static IReadOnlyList<CertificateRevocationList> Load(byte[] bytes)
    {
        List<CertificateRevocationList> lists = [];
        string text = Encoding.ASCII.GetString(bytes);
        if (!text.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            lists.Add(Parse(bytes));
            return lists;
        }

        ReadOnlySpan<char> remaining = text;
        while (PemEncoding.TryFind(remaining, out PemFields fields))
        {
            if (remaining[fields.Label].SequenceEqual("X509 CRL"))
            {
                if (lists.Count == MaximumLists)
                {
                    throw new CryptographicException("Too many revocation lists.");
                }

                lists.Add(Parse(Convert.FromBase64String(remaining[fields.Base64Data].ToString())));
            }

            remaining = remaining[fields.Location.End..];
        }

        return lists.Count == 0 ? throw new CryptographicException("No revocation list.") : lists;
    }

    public static CertificateRevocationList Parse(byte[] der)
    {
        try
        {
            return ParseDer(der);
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("Malformed revocation list.", exception);
        }
    }

    /// <summary>
    /// The <c>fullName</c> general names (DER) of a certificate's CRL distribution points;
    /// points with a separate CRL issuer are skipped (indirect lists are not supported).
    /// </summary>
    public static IReadOnlyList<byte[]> DistributionPoints(X509Certificate2 certificate)
    {
        List<byte[]> names = [];
        if (certificate.Extensions[CrlDistributionPoints] is not { } extension)
        {
            return names;
        }

        try
        {
            AsnReader outer = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader points = outer.ReadSequence();
            while (points.HasData)
            {
                AsnReader point = points.ReadSequence();
                List<byte[]> pointNames = [];
                bool indirect = false;
                while (point.HasData)
                {
                    Asn1Tag tag = point.PeekTag();
                    if (tag.HasSameClassAndValue(Context0))
                    {
                        pointNames.AddRange(ReadDistributionPointName(point.ReadSequence(Context0), throwUnsupported: false));
                    }
                    else
                    {
                        indirect |= tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2));
                        _ = point.ReadEncodedValue();
                    }
                }

                if (!indirect)
                {
                    names.AddRange(pointNames);
                }
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension names no point; a list that requires one does not cover it.
        }

        return names;
    }

    /// <summary>Whether this list's scope includes an end-entity certificate with these distribution point names.</summary>
    public bool Covers(IReadOnlyList<byte[]> distributionPoints) =>
        coversSenders && (scopeNames.Count == 0
            || distributionPoints.Any(name => scopeNames.Any(scope => scope.AsSpan().SequenceEqual(name))));

    public bool IsRevoked(ReadOnlySpan<byte> bigEndianSerial) => revoked.Contains(Serial(bigEndianSerial));

    /// <summary>Signature check against the issuing CA (which must allow CRL signing), cached per CA.</summary>
    public bool IsSignedBy(X509Certificate2 issuer) =>
        verified.GetOrAdd(issuer.GetCertHashString(HashAlgorithmName.SHA256), _ =>
        {
            if (issuer.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } usage
                && !usage.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign))
            {
                return false;
            }

            try
            {
                if (ecdsa)
                {
                    using ECDsa? key = issuer.GetECDsaPublicKey();
                    return key?.VerifyData(signedPart, signature, hash, DSASignatureFormat.Rfc3279DerSequence) == true;
                }

                using RSA? rsa = issuer.GetRSAPublicKey();
                return rsa?.VerifyData(signedPart, signature, hash, RSASignaturePadding.Pkcs1) == true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        });

    private static CertificateRevocationList ParseDer(byte[] der)
    {
        AsnReader outer = new(der, AsnEncodingRules.DER);
        AsnReader list = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        byte[] signedPart = list.ReadEncodedValue().ToArray();
        string algorithm = ReadAlgorithm(list);
        byte[] signature = list.ReadBitString(out int unusedBits);
        list.ThrowIfNotEmpty();
        if (unusedBits != 0)
        {
            throw new CryptographicException("Invalid revocation list signature.");
        }

        (HashAlgorithmName hash, bool ecdsa) = algorithm switch
        {
            "1.2.840.113549.1.1.11" => (HashAlgorithmName.SHA256, false),
            "1.2.840.113549.1.1.12" => (HashAlgorithmName.SHA384, false),
            "1.2.840.113549.1.1.13" => (HashAlgorithmName.SHA512, false),
            "1.2.840.10045.4.3.2" => (HashAlgorithmName.SHA256, true),
            "1.2.840.10045.4.3.3" => (HashAlgorithmName.SHA384, true),
            "1.2.840.10045.4.3.4" => (HashAlgorithmName.SHA512, true),
            _ => throw new UnsupportedRevocationListException(
                "client revocation list signature algorithm is not supported (RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512).")
        };

        AsnReader tbs = new AsnReader(signedPart, AsnEncodingRules.DER).ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
        {
            if (!tbs.TryReadInt32(out int version) || version != 1)
            {
                throw new CryptographicException("Unsupported revocation list version.");
            }
        }

        if (ReadAlgorithm(tbs) != algorithm)
        {
            throw new CryptographicException("Revocation list signature algorithms differ.");
        }

        byte[] issuer = tbs.ReadEncodedValue().ToArray();
        _ = ReadTime(tbs);
        // RFC 5280 requires nextUpdate.
        DateTimeOffset nextUpdate = tbs.HasData && IsTime(tbs.PeekTag())
            ? ReadTime(tbs)
            : throw new CryptographicException("Revocation list has no nextUpdate.");
        HashSet<string> revoked = new(StringComparer.Ordinal);
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            AsnReader entries = tbs.ReadSequence();
            while (entries.HasData)
            {
                AsnReader entry = entries.ReadSequence();
                revoked.Add(Serial(entry.ReadIntegerBytes().Span));
                _ = ReadTime(entry);
                if (entry.HasData)
                {
                    foreach ((string oid, bool critical, _) in ReadExtensions(entry.ReadSequence()))
                    {
                        if (critical)
                        {
                            throw new UnsupportedRevocationListException(
                                $"client revocation list entry has an unsupported critical extension ({oid}).");
                        }
                    }
                }

                entry.ThrowIfNotEmpty();
            }
        }

        List<byte[]> scopeNames = [];
        bool coversSenders = true;
        if (tbs.HasData)
        {
            AsnReader explicitExtensions = tbs.ReadSequence(Context0);
            foreach ((string oid, bool critical, byte[] value) in ReadExtensions(explicitExtensions.ReadSequence()))
            {
                if (oid == IssuingDistributionPoint)
                {
                    (scopeNames, coversSenders) = ReadIssuingDistributionPoint(value);
                }
                else if (oid == "2.5.29.27")
                {
                    throw new UnsupportedRevocationListException("delta client revocation lists are not supported.");
                }
                else if (critical)
                {
                    throw new UnsupportedRevocationListException(
                        $"client revocation list has an unsupported critical extension ({oid}).");
                }
            }

            explicitExtensions.ThrowIfNotEmpty();
        }

        tbs.ThrowIfNotEmpty();
        return new CertificateRevocationList(issuer, nextUpdate, revoked, signedPart, signature, hash, ecdsa, scopeNames, coversSenders);
    }

    /// <summary>
    /// IssuingDistributionPoint (RFC 5280 5.2.5): returns the <c>fullName</c> scope and whether
    /// end-entity certificates are in scope. Unsupported scopes throw with their name.
    /// </summary>
    private static (List<byte[]> Names, bool CoversSenders) ReadIssuingDistributionPoint(byte[] value)
    {
        AsnReader outer = new(value, AsnEncodingRules.DER);
        AsnReader point = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        List<byte[]> names = [];
        bool coversSenders = true;
        if (point.HasData && point.PeekTag().HasSameClassAndValue(Context0))
        {
            names.AddRange(ReadDistributionPointName(point.ReadSequence(Context0), throwUnsupported: true));
        }

        for (int tag = 1; tag <= 5 && point.HasData; tag++)
        {
            if (!point.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, tag)))
            {
                continue;
            }

            if (tag == 3)
            {
                throw new UnsupportedRevocationListException(
                    "client revocation lists limited to some revocation reasons are not supported.");
            }

            bool set = point.ReadBoolean(new Asn1Tag(TagClass.ContextSpecific, tag));
            if (set && tag == 4)
            {
                throw new UnsupportedRevocationListException("indirect client revocation lists are not supported.");
            }

            // onlyContainsCACerts or onlyContainsAttributeCerts: never a sender certificate.
            coversSenders &= !(set && tag is 2 or 5);
        }

        point.ThrowIfNotEmpty();
        return (names, coversSenders);
    }

    private static List<byte[]> ReadDistributionPointName(AsnReader name, bool throwUnsupported)
    {
        List<byte[]> names = [];
        if (name.PeekTag().HasSameClassAndValue(Context0))
        {
            AsnReader fullName = name.ReadSequence(Context0);
            while (fullName.HasData)
            {
                names.Add(fullName.ReadEncodedValue().ToArray());
            }
        }
        else if (throwUnsupported)
        {
            throw new UnsupportedRevocationListException(
                "client revocation list distribution points relative to the issuer are not supported.");
        }
        else
        {
            _ = name.ReadEncodedValue();
        }

        name.ThrowIfNotEmpty();
        return names;
    }

    private static List<(string Oid, bool Critical, byte[] Value)> ReadExtensions(AsnReader extensions)
    {
        List<(string, bool, byte[])> read = [];
        while (extensions.HasData)
        {
            AsnReader extension = extensions.ReadSequence();
            string oid = extension.ReadObjectIdentifier();
            bool critical = extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && extension.ReadBoolean();
            byte[] value = extension.ReadOctetString();
            extension.ThrowIfNotEmpty();
            read.Add((oid, critical, value));
        }

        return read;
    }

    /// <summary>The algorithm OID; supported algorithms carry no parameters other than RSA's NULL.</summary>
    private static string ReadAlgorithm(AsnReader reader)
    {
        AsnReader algorithm = reader.ReadSequence();
        string oid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData && algorithm.PeekTag().HasSameClassAndValue(Asn1Tag.Null))
        {
            algorithm.ReadNull();
        }

        return algorithm.HasData ? oid + "+parameters" : oid;
    }

    private static bool IsTime(Asn1Tag tag) =>
        tag.HasSameClassAndValue(Asn1Tag.UtcTime) || tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    private static DateTimeOffset ReadTime(AsnReader reader) =>
        reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();

    /// <summary>Serial number as hex without leading zero bytes (sign padding or not).</summary>
    private static string Serial(ReadOnlySpan<byte> bigEndian)
    {
        int start = 0;
        while (start < bigEndian.Length - 1 && bigEndian[start] == 0)
        {
            start++;
        }

        return Convert.ToHexString(bigEndian[start..]);
    }
}

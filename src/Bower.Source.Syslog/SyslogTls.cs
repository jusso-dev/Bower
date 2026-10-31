using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Bower.Source.Syslog;

/// <summary>
/// One TLS listener's certificate, key, client CAs and revocation lists, reloaded when the
/// files change. New handshakes use the newest valid material; a reload that fails (a
/// half-written file, a key that does not match, an unreadable revocation list) keeps the
/// last good material and is counted. Rotation therefore needs no restart and drops no
/// open connection.
/// </summary>
internal sealed class SyslogTlsSource
{
    private readonly SyslogListenerOptions options;
    private readonly TimeProvider clock;
    private readonly TimeSpan checkInterval;
    private readonly Lock gate = new();
    private SyslogTlsMaterial current;
    private byte[] stamp;
    private long nextCheckTicks;
    private long reloads;
    private long reloadFailures;

    /// <summary>Loads the initial material; any failure stops listener start-up.</summary>
    public SyslogTlsSource(SyslogListenerOptions options, TimeProvider clock, TimeSpan checkInterval)
    {
        this.options = options;
        this.clock = clock;
        this.checkInterval = checkInterval;
        stamp = Stamp(options.Tls!);
        current = SyslogTlsMaterial.Load(options, 1);
        nextCheckTicks = clock.GetUtcNow().UtcTicks + checkInterval.Ticks;
    }

    public long Reloads => Interlocked.Read(ref reloads);

    public long ReloadFailures => Interlocked.Read(ref reloadFailures);

    /// <summary>The newest valid material, checking the files at most once per interval.</summary>
    public SyslogTlsMaterial Current
    {
        get
        {
            long now = clock.GetUtcNow().UtcTicks;
            if (now < Interlocked.Read(ref nextCheckTicks))
            {
                return Volatile.Read(ref current);
            }

            lock (gate)
            {
                if (now < nextCheckTicks)
                {
                    return current;
                }

                Interlocked.Exchange(ref nextCheckTicks, now + checkInterval.Ticks);
                byte[] next = Stamp(options.Tls!);
                if (next.AsSpan().SequenceEqual(stamp))
                {
                    return current;
                }

                // Remember the attempted content either way: a bad file is retried when it
                // changes again, not on every connection.
                stamp = next;
                try
                {
                    Volatile.Write(ref current, SyslogTlsMaterial.Load(options, current.Generation + 1));
                    Interlocked.Increment(ref reloads);
                }
                catch (InvalidOperationException)
                {
                    Interlocked.Increment(ref reloadFailures);
                }

                return current;
            }
        }
    }

    /// <summary>Digest of every configured file's bytes; a missing or unreadable file has its own marker.</summary>
    private static byte[] Stamp(SyslogTlsOptions tls)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (string? path in new[] { tls.CertificateFile, tls.PrivateKeyFile, tls.ClientCertificateAuthorityFile, tls.ClientCertificateRevocationListFile })
        {
            byte[] digest;
            try
            {
                digest = path is null ? [0] : SHA256.HashData(SyslogTlsMaterial.ReadBounded(path));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
            {
                digest = [1];
            }

            hash.AppendData(digest);
        }

        return hash.GetHashAndReset();
    }
}

/// <summary>Loaded, immutable TLS material for one generation.</summary>
internal sealed class SyslogTlsMaterial
{
    /// <summary>Largest certificate, key, CA bundle or revocation list file read.</summary>
    public const int MaximumFileBytes = 8 * 1024 * 1024;

    private static readonly Oid ClientAuthentication = new("1.3.6.1.5.5.7.3.2");

    private readonly SslStreamCertificateContext serverContext;
    private readonly X509ChainPolicy? clientPolicy;
    private readonly IReadOnlyList<CertificateRevocationList> revocationLists;

    private SyslogTlsMaterial(
        long generation,
        SslStreamCertificateContext serverContext,
        X509ChainPolicy? clientPolicy,
        IReadOnlyList<CertificateRevocationList> revocationLists,
        DateTimeOffset serverCertificateNotAfter,
        DateTimeOffset? clientCertificateAuthorityNotAfter)
    {
        Generation = generation;
        this.serverContext = serverContext;
        this.clientPolicy = clientPolicy;
        this.revocationLists = revocationLists;
        ServerCertificateNotAfter = serverCertificateNotAfter;
        ClientCertificateAuthorityNotAfter = clientCertificateAuthorityNotAfter;
        ClientRevocationListNextUpdate = revocationLists.Count == 0
            ? null
            : revocationLists.Min(list => list.NextUpdate);
    }

    public long Generation { get; }

    public DateTimeOffset ServerCertificateNotAfter { get; }

    /// <summary>Earliest expiry among the trusted client CAs.</summary>
    public DateTimeOffset? ClientCertificateAuthorityNotAfter { get; }

    /// <summary>Earliest <c>nextUpdate</c> among the revocation lists; after it, their issuers' clients are refused.</summary>
    public DateTimeOffset? ClientRevocationListNextUpdate { get; }

    public static SyslogTlsMaterial Load(SyslogListenerOptions options, long generation)
    {
        SyslogTlsOptions tls = options.Tls!;
        try
        {
            X509Certificate2Collection chain = [];
            chain.ImportFromPem(Encoding.UTF8.GetString(ReadBounded(tls.CertificateFile)));
            using X509Certificate2 pem = X509Certificate2.CreateFromPem(
                Encoding.UTF8.GetString(ReadBounded(tls.CertificateFile)),
                Encoding.UTF8.GetString(ReadBounded(tls.PrivateKeyFile)));
            // Re-import so the key is usable by SslStream on every platform (PEM keys are ephemeral).
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
            X509Certificate2Collection intermediates = [.. chain.Skip(1)];
            X509ChainPolicy? clientPolicy = null;
            DateTimeOffset? authorityNotAfter = null;
            if (tls.ClientCertificateAuthorityFile is { } authorityFile)
            {
                X509Certificate2Collection authorities = [];
                authorities.ImportFromPem(Encoding.UTF8.GetString(ReadBounded(authorityFile)));
                if (authorities.Count == 0)
                {
                    throw new CryptographicException("No client certificate authority.");
                }

                // Client chains are built by SslStream with this policy, which adds the
                // intermediates the sender supplies; only the configured CAs are trusted.
                // Revocation is checked by Bower against the configured lists, offline.
                clientPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck
                };
                clientPolicy.CustomTrustStore.AddRange(authorities);
                clientPolicy.ApplicationPolicy.Add(ClientAuthentication);
                authorityNotAfter = authorities.Min(authority => new DateTimeOffset(authority.NotAfter.ToUniversalTime()));
            }

            IReadOnlyList<CertificateRevocationList> lists = tls.ClientCertificateRevocationListFile is { } listFile
                ? CertificateRevocationList.Load(ReadBounded(listFile))
                : [];
            return new SyslogTlsMaterial(
                generation,
                SslStreamCertificateContext.Create(server, intermediates, offline: true),
                clientPolicy,
                lists,
                new DateTimeOffset(server.NotAfter.ToUniversalTime()),
                authorityNotAfter);
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or ArgumentException
            or UnauthorizedAccessException or AsnContentException)
        {
            // Never echo key material, file contents or the underlying parser message.
            throw new InvalidOperationException($"Syslog listener {options.Id}: TLS certificate or key could not be loaded.");
        }
    }

    internal static byte[] ReadBounded(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > MaximumFileBytes)
        {
            throw new IOException("TLS file is too large.");
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
    /// currently trusted CA, the validity of every certificate and the revocation lists.
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
    /// End-entity revocation, as rustls does with <c>only_check_end_entity_revocation</c>,
    /// denied unknown status and enforced expiry: with lists configured, a client whose
    /// issuer has no list, whose list is not validly signed by that issuer or is past its
    /// <c>nextUpdate</c>, or that is listed, is refused.
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

        bool found = false;
        foreach (CertificateRevocationList list in revocationLists)
        {
            if (!list.Issuer.AsSpan().SequenceEqual(leaf.IssuerName.RawData))
            {
                continue;
            }

            found = true;
            if (!list.IsSignedBy(issuer) || list.NextUpdate < now || list.IsRevoked(leaf.SerialNumberBytes.Span))
            {
                return false;
            }
        }

        return found;
    }
}

/// <summary>One TLS connection's accepted client chain, kept to validate it again after a reload.</summary>
internal sealed class SyslogTlsSession
{
    public X509Certificate2? Leaf { get; private set; }

    public X509Certificate2Collection Intermediates { get; } = [];

    public long Generation { get; private set; }

    /// <summary>When the session must be validated again even without a reload: the first expiry in its chain or list.</summary>
    public DateTimeOffset RevalidateAt { get; private set; } = DateTimeOffset.MaxValue;

    public bool Revoked { get; set; }

    public void Accept(SyslogTlsMaterial material, X509Certificate2 leaf, X509Chain chain)
    {
        if (!ReferenceEquals(Leaf, leaf))
        {
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

/// <summary>
/// An X.509 v2 certificate revocation list (RFC 5280 section 5): issuer, validity, revoked
/// serial numbers and the signature, verified against the issuing CA at use. Delta lists
/// and lists or entries with critical extensions are refused, as are signature algorithms
/// other than RSA PKCS#1 v1.5 and ECDSA with SHA-256/384/512.
/// </summary>
internal sealed class CertificateRevocationList
{
    private const int MaximumLists = 64;

    private readonly HashSet<string> revoked;
    private readonly byte[] signedPart;
    private readonly byte[] signature;
    private readonly HashAlgorithmName hash;
    private readonly bool ecdsa;
    private readonly ConcurrentDictionary<string, bool> verified = new(StringComparer.Ordinal);

    private CertificateRevocationList(byte[] issuer, DateTimeOffset nextUpdate, HashSet<string> revoked,
        byte[] signedPart, byte[] signature, HashAlgorithmName hash, bool ecdsa)
    {
        Issuer = issuer;
        NextUpdate = nextUpdate;
        this.revoked = revoked;
        this.signedPart = signedPart;
        this.signature = signature;
        this.hash = hash;
        this.ecdsa = ecdsa;
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
            _ => throw new CryptographicException("Unsupported revocation list signature algorithm.")
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
        // RFC 5280 requires nextUpdate; rustls-webpki refuses a list without it.
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
                    RefuseCriticalExtensions(entry.ReadSequence());
                }

                entry.ThrowIfNotEmpty();
            }
        }

        if (tbs.HasData)
        {
            AsnReader extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            RefuseCriticalExtensions(extensions.ReadSequence());
            extensions.ThrowIfNotEmpty();
        }

        tbs.ThrowIfNotEmpty();
        return new CertificateRevocationList(issuer, nextUpdate, revoked, signedPart, signature, hash, ecdsa);
    }

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

    private static void RefuseCriticalExtensions(AsnReader extensions)
    {
        while (extensions.HasData)
        {
            AsnReader extension = extensions.ReadSequence();
            _ = extension.ReadObjectIdentifier();
            if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && extension.ReadBoolean())
            {
                throw new CryptographicException("Unsupported critical revocation list extension.");
            }

            _ = extension.ReadOctetString();
            extension.ThrowIfNotEmpty();
        }
    }

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

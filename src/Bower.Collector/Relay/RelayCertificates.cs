using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Bower.Collector.Relay;

/// <summary>PEM certificate loading and pinning shared by the relay and its downstream collectors.</summary>
public static class RelayCertificates
{
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Loads a certificate with its private key from PEM files. The message names the
    /// settings, never the paths' contents.
    /// </summary>
    public static X509Certificate2 Load(string certificateFile, string keyFile, string settingNames)
    {
        try
        {
            using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certificateFile, keyFile);
            // Round-trip through PKCS#12 so every platform TLS stack can use the private key.
            return X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or CryptographicException
            or ArgumentException)
        {
            throw new InvalidOperationException($"{settingNames} must name a readable PEM certificate and its private key.");
        }
    }

    /// <summary>
    /// Host for a socket connect or TLS target: the punycode name, or an IPv6 literal without
    /// the brackets that <see cref="Uri.IdnHost"/> keeps.
    /// </summary>
    public static string ConnectHost(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return url.HostNameType == UriHostNameType.IPv6 ? url.IdnHost.Trim('[', ']') : url.IdnHost;
    }

    /// <summary>Lowercase hex SHA-256 of the DER certificate (<c>openssl x509 -fingerprint -sha256</c>).</summary>
    public static string Pin(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Convert.ToHexStringLower(SHA256.HashData(certificate.GetRawCertData()));
    }

    /// <summary>
    /// A presented client certificate is usable when it is inside its validity period and,
    /// if it restricts its key usage, allows client authentication. The pin is the trust
    /// anchor, so self-signed certificates are fine.
    /// </summary>
    internal static bool IsUsableClientCertificate(X509Certificate2 certificate, DateTimeOffset now) =>
        now >= certificate.NotBefore.ToUniversalTime()
        && now <= certificate.NotAfter.ToUniversalTime()
        && AllowsUsage(certificate, ClientAuthentication);

    private static bool AllowsUsage(X509Certificate2 certificate, string usage)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension enhanced)
            {
                return enhanced.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == usage);
            }
        }

        return true;
    }
}

using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Bower.Collector;

/// <summary>
/// The management channel's HTTP handler. Without explicit settings the runtime's standard
/// proxy variables (HTTPS_PROXY, HTTP_PROXY, NO_PROXY) apply, as for every .NET HttpClient.
/// BOWER_MANAGEMENT_PROXY replaces them for this channel, with optional credentials read
/// from a file. BOWER_MANAGEMENT_CA_BUNDLE adds roots (for example a TLS-inspection proxy
/// CA) to the system roots: certificate and host name verification is never disabled.
/// Credentials are held in memory only and never logged.
/// </summary>
public static class ManagementHttp
{
    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

    public static SocketsHttpHandler CreateHandler(CollectorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        SocketsHttpHandler handler = new() { PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
        if (settings.ManagementProxy is not null)
        {
            WebProxy proxy = new(settings.ManagementProxy);
            if (settings.ManagementProxyUsername is not null)
            {
                proxy.Credentials = new NetworkCredential(
                    settings.ManagementProxyUsername,
                    ReadPassword(settings.ManagementProxyPasswordFile!));
            }

            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        if (settings.ManagementCaBundle is not null)
        {
            X509Certificate2Collection roots = ReadCaBundle(settings.ManagementCaBundle);
            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, chain, errors) => Validate(certificate, chain, errors, roots);
        }

        return handler;
    }

    /// <summary>
    /// Accepts what the platform accepts. Otherwise only a chain error may be retried, and
    /// only against the configured roots: a name mismatch or a missing certificate is final.
    /// </summary>
    internal static bool Validate(
        X509Certificate? certificate,
        X509Chain? presented,
        SslPolicyErrors errors,
        X509Certificate2Collection roots)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || certificate is null)
        {
            return false;
        }

        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthentication));
        if (presented is not null)
        {
            foreach (X509ChainElement element in presented.ChainElements)
            {
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }

        return chain.Build(leaf);
    }

    public static X509Certificate2Collection ReadCaBundle(string path)
    {
        X509Certificate2Collection roots = [];
        try
        {
            roots.ImportFromPemFile(path);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or CryptographicException)
        {
            throw new InvalidOperationException(
                "BOWER_MANAGEMENT_CA_BUNDLE must name a readable PEM file of CA certificates.");
        }

        return roots.Count > 0
            ? roots
            : throw new InvalidOperationException(
                "BOWER_MANAGEMENT_CA_BUNDLE must name a readable PEM file of CA certificates.");
    }

    private static string ReadPassword(string path)
    {
        try
        {
            // A trailing newline from `echo` or a secret mount is not part of the password.
            return File.ReadAllText(path).TrimEnd('\r', '\n');
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException("BOWER_MANAGEMENT_PROXY_PASSWORD_FILE must name a readable file.");
        }
    }
}

using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors.Crypto;

public sealed partial class CryptographicMaterialDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.CryptoMaterial;
    public override string Category => DetectorCategories.Crypto;
    protected override Regex Pattern => PemRegex();

    protected override string? SubKind(ReadOnlySpan<char> matched)
    {
        string s = matched.ToString();
        if (s.Contains("RSA PRIVATE", StringComparison.Ordinal))
        {
            return "rsa-private";
        }

        if (s.Contains("EC PRIVATE", StringComparison.Ordinal) || s.Contains("ECDSA", StringComparison.Ordinal))
        {
            return "ecdsa-private";
        }

        if (s.Contains("OPENSSH PRIVATE", StringComparison.Ordinal))
        {
            return "openssh-private";
        }

        if (s.Contains("PRIVATE KEY", StringComparison.Ordinal))
        {
            return "pkcs8-private";
        }

        if (s.Contains("CERTIFICATE", StringComparison.Ordinal))
        {
            return "x509-certificate";
        }

        if (s.Contains("PGP", StringComparison.Ordinal) || s.Contains("PGP PRIVATE", StringComparison.Ordinal))
        {
            return "pgp";
        }

        if (s.Contains("BEGIN SSH2", StringComparison.Ordinal))
        {
            return "ssh";
        }

        return "pem";
    }

    [GeneratedRegex(
        @"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----|-----BEGIN PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----[\s\S]+?-----END PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----|-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
        RegexOptions.CultureInvariant)]
    private static partial Regex PemRegex();
}

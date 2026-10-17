using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors.Crypto;

public sealed partial class CryptographicMaterialDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.CryptoMaterial;
    public override string Category => DetectorCategories.Crypto;
    protected override Regex Pattern => PemRegex();

    /// <summary>
    /// Labels the block by its exact <c>-----BEGIN &lt;label&gt;-----</c> header, so body text
    /// can never change the kind (every alternative of the pattern starts with a header).
    /// </summary>
    protected override string? SubKind(ReadOnlySpan<char> matched)
    {
        const string Begin = "-----BEGIN ";
        if (!matched.StartsWith(Begin, StringComparison.Ordinal))
        {
            return "pem";
        }

        ReadOnlySpan<char> rest = matched[Begin.Length..];
        int end = rest.IndexOf("-----", StringComparison.Ordinal);
        return (end < 0 ? rest : rest[..end]) switch
        {
            "RSA PRIVATE KEY" => "rsa-private",
            "EC PRIVATE KEY" => "ecdsa-private",
            "DSA PRIVATE KEY" => "dsa-private",
            "OPENSSH PRIVATE KEY" => "openssh-private",
            "ENCRYPTED PRIVATE KEY" => "encrypted-private",
            "PRIVATE KEY" => "pkcs8-private",
            "CERTIFICATE" => "x509-certificate",
            "PGP PRIVATE KEY BLOCK" => "pgp-private",
            "PGP PUBLIC KEY BLOCK" => "pgp-public",
            "PGP KEY BLOCK" => "pgp",
            _ => "pem"
        };
    }

    [GeneratedRegex(
        @"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----|-----BEGIN PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----[\s\S]+?-----END PGP (?:PRIVATE |PUBLIC )?KEY BLOCK-----|-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
        RegexOptions.CultureInvariant)]
    private static partial Regex PemRegex();
}

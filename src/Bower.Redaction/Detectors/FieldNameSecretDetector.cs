using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors;

/// <summary>
/// Removes whole properties whose names indicate secrets or unrestricted bodies.
/// Matches exact names, then secret-bearing name fragments (for example
/// <c>dbPassword</c>, <c>sessionToken</c>, <c>xApiKey</c>), minus an allow-list of
/// metadata names that describe a secret without containing it.
/// </summary>
public sealed class FieldNameSecretDetector : IFieldNameDetector
{
    private static readonly HashSet<string> SecretNames = new(
        [
            "password",
            "passwordhash",
            "pwd",
            "passwd",
            "accesstoken",
            "refreshtoken",
            "bearertoken",
            "apikeysecret",
            "apikey",
            "clientsecret",
            "privatekey",
            "connectionstring",
            "authorization",
            "authorizationheader",
            "cookie",
            "cookies",
            "credential",
            "credentials",
            "secret",
            "requestbody",
            "responsebody",
            "body",
            "headers",
            "payload",
            "filecontents"
        ],
        StringComparer.Ordinal);

    // Fragments that mark a value as secret wherever they appear in a normalised name.
    private static readonly string[] SecretFragments =
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "privatekey",
        "cookie",
        "credential",
        "connectionstring",
        "authorization",
        "signature"
    ];

    // Short markers that only count as a suffix, to avoid matching unrelated words.
    private static readonly string[] SecretSuffixes = ["pwd", "pass", "pin", "otp"];

    // Names that describe secret metadata rather than carrying the secret itself.
    private static readonly HashSet<string> SafeNames = new(
        [
            "tokentype",
            "tokenexpiry",
            "tokenexpiresat",
            "tokenexpiresin",
            "tokenissuer",
            "tokenaudience",
            "tokenvalid",
            "tokencount",
            "passwordpolicy",
            "passwordexpired",
            "passwordexpiresat",
            "passwordlastchanged",
            "passwordchanged",
            "passwordresetrequired",
            "secretname",
            "secretversion",
            "credentialtype",
            "credentialid",
            "signaturealgorithm",
            "signaturevalid",
            "cookieconsent",
            "bypass",
            "compass",
            "spin"
        ],
        StringComparer.Ordinal);

    public string Id => DetectorIds.FieldNameSecret;

    public string Category => DetectorCategories.FieldName;

    public bool MatchesFieldName(string normalizedFieldName)
    {
        if (string.IsNullOrEmpty(normalizedFieldName))
        {
            return false;
        }

        if (SecretNames.Contains(normalizedFieldName))
        {
            return true;
        }

        if (SafeNames.Contains(normalizedFieldName))
        {
            return false;
        }

        foreach (string fragment in SecretFragments)
        {
            if (normalizedFieldName.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        foreach (string suffix in SecretSuffixes)
        {
            if (normalizedFieldName.EndsWith(suffix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

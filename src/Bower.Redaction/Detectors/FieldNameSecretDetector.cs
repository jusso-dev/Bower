using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors;

/// <summary>Removes whole properties whose names indicate secrets or unrestricted bodies.</summary>
public sealed class FieldNameSecretDetector : IFieldNameDetector
{
    private static readonly HashSet<string> SecretNames = new(
        [
            "password",
            "passwordhash",
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

    public string Id => DetectorIds.FieldNameSecret;

    public string Category => DetectorCategories.FieldName;

    public bool MatchesFieldName(string normalizedFieldName) =>
        SecretNames.Contains(normalizedFieldName);
}

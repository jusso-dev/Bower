using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>A short-lived Google access token and when it expires. Never logged.</summary>
internal sealed record GoogleAccessToken(string Value, DateTimeOffset ExpiresAt)
{
    public override string ToString() => $"GoogleAccessToken {{ ExpiresAt = {ExpiresAt:O} }}";
}

/// <summary>One Application Default Credentials flow.</summary>
internal interface IGoogleCredential
{
    /// <summary>Short description for start-up errors (no secrets).</summary>
    string Kind { get; }

    Task<GoogleAccessToken> FetchAsync(CancellationToken cancellationToken);
}

/// <summary>Shared OAuth 2.0 helpers for the credential flows.</summary>
internal static class GoogleOAuth
{
    public const string CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform";
    public const string DefaultUniverseDomain = "googleapis.com";

    /// <summary>
    /// Parses a token endpoint response: a non-empty <c>access_token</c>, <c>token_type</c>
    /// Bearer and a positive <c>expires_in</c>.
    /// </summary>
    public static GoogleAccessToken ReadTokenResponse(byte[] body, string operation, DateTimeOffset now, string? expectedIssuedTokenType = null)
    {
        OAuthTokenResponse response = Deserialize(body, GoogleAuthJsonContext.Default.OAuthTokenResponse, operation);
        if (string.IsNullOrEmpty(response.AccessToken))
        {
            throw new InvalidOperationException($"{operation} returned no access token.");
        }

        if (!string.Equals(response.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{operation} returned an unsupported token type.");
        }

        if (expectedIssuedTokenType is not null
            && response.IssuedTokenType is not null
            && !string.Equals(response.IssuedTokenType, expectedIssuedTokenType, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{operation} issued an unexpected token type.");
        }

        if (response.ExpiresIn is not (> 0 and <= 7 * 24 * 3600))
        {
            throw new InvalidOperationException($"{operation} returned no valid expires_in.");
        }

        return new GoogleAccessToken(response.AccessToken, now.AddSeconds(response.ExpiresIn.Value));
    }

    public static T Deserialize<T>(byte[] body, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, string operation)
    {
        try
        {
            return JsonSerializer.Deserialize(body, type)
                ?? throw new InvalidOperationException($"{operation} returned an empty response.");
        }
        catch (JsonException)
        {
            // The parser message is safe, but the body may contain secrets; say nothing more.
            throw new InvalidOperationException($"{operation} returned malformed JSON.");
        }
    }

    public static HttpRequestMessage FormPost(Uri url, IEnumerable<KeyValuePair<string, string>> fields) =>
        new(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(fields) };

    public static void Bearer(HttpRequestMessage request, string token) =>
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

    /// <summary>
    /// A Google token or IAM endpoint: absolute HTTPS on a host in the credential's universe
    /// domain (<c>googleapis.com</c> unless the file sets <c>universe_domain</c>), so a
    /// tampered configuration cannot send subject tokens or keys to another host.
    /// </summary>
    public static Uri RequireGoogleEndpoint(string? value, string field, string universeDomain)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Uri.TryCreate(value, UriKind.Absolute, out Uri? url)
            || url.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(url.UserInfo)
            || !url.IsDefaultPort
            || !url.Host.EndsWith("." + universeDomain, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The Google credential file field {field} must be an HTTPS URL on {universeDomain}.");
        }

        return url;
    }

    public static string UniverseDomain(GoogleCredentialFile file)
    {
        string universe = string.IsNullOrWhiteSpace(file.UniverseDomain) ? DefaultUniverseDomain : file.UniverseDomain.Trim();
        // A bare DNS name: letters, digits, dots and hyphens.
        return universe.Contains('.', StringComparison.Ordinal)
            && universe.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-')
            && !universe.StartsWith('.')
            ? universe.ToLowerInvariant()
            : throw new InvalidOperationException("The Google credential file field universe_domain is not a domain name.");
    }

    public static DateTimeOffset ParseRfc3339(string? value, string operation) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : throw new InvalidOperationException($"{operation} returned no valid expireTime.");
}

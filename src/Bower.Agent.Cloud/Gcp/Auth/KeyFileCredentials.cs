using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>
/// Service account key file (lab only, <c>BOWER_GCP_ALLOW_KEY_FILE=true</c>): an RS256 JWT
/// assertion exchanged at the OAuth token endpoint (two-legged OAuth, RFC 7523 jwt-bearer).
/// The private key stays in memory and is never logged.
/// </summary>
internal sealed class ServiceAccountKeyCredential : IGoogleCredential, IDisposable
{
    private const string JwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private readonly GoogleAuthHttp http;
    private readonly TimeProvider time;
    private readonly string scope;
    private readonly string email;
    private readonly string? keyId;
    private readonly Uri tokenUri;
    private readonly RSA key;

    public ServiceAccountKeyCredential(GoogleCredentialFile file, IReadOnlyList<string> scopes, GoogleAuthHttp http, TimeProvider time)
    {
        this.http = http;
        this.time = time;
        scope = string.Join(' ', scopes);
        email = string.IsNullOrEmpty(file.ClientEmail)
            ? throw new InvalidOperationException("The service account key file has no client_email.")
            : file.ClientEmail;
        keyId = file.PrivateKeyId;
        tokenUri = GoogleOAuth.RequireGoogleEndpoint(
            file.TokenUri ?? "https://oauth2.googleapis.com/token",
            "token_uri",
            GoogleOAuth.UniverseDomain(file));
        if (string.IsNullOrEmpty(file.PrivateKey))
        {
            throw new InvalidOperationException("The service account key file has no private_key.");
        }

        key = RSA.Create();
        try
        {
            key.ImportFromPem(file.PrivateKey);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            key.Dispose();
            throw new InvalidOperationException("The service account key file private_key is not a PEM RSA key.");
        }
    }

    public string Kind => "service account key file";

    public async Task<GoogleAccessToken> FetchAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = time.GetUtcNow();
        string assertion = Assertion(now);
        using HttpRequestMessage request = GoogleOAuth.FormPost(
            tokenUri,
            [new("grant_type", JwtBearerGrant), new("assertion", assertion)]);
        HttpResult result = await http.SendAsync(
            request,
            "OAuth token request",
            GoogleAuthHttp.MaximumResponseBytes,
            cancellationToken);
        return GoogleOAuth.ReadTokenResponse(result.Body, "OAuth token request", time.GetUtcNow());
    }

    internal string Assertion(DateTimeOffset now)
    {
        long issued = now.ToUnixTimeSeconds();
        string header = Base64Url(JsonSerializer.SerializeToUtf8Bytes(
            new JwtHeader("RS256", "JWT", string.IsNullOrEmpty(keyId) ? null : keyId),
            GoogleAuthJsonContext.Default.JwtHeader));
        string claims = Base64Url(JsonSerializer.SerializeToUtf8Bytes(
            new JwtClaims(email, scope, tokenUri.AbsoluteUri, issued, issued + 3600),
            GoogleAuthJsonContext.Default.JwtClaims));
        string signingInput = header + "." + claims;
        byte[] signature = key.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return signingInput + "." + Base64Url(signature);
    }

    public void Dispose() => key.Dispose();

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// gcloud user credentials (<c>authorized_user</c>, lab only): a long-lived refresh token
/// exchanged at the OAuth token endpoint. Refused unless <c>BOWER_GCP_ALLOW_KEY_FILE=true</c>.
/// </summary>
internal sealed class AuthorizedUserCredential(GoogleCredentialFile file, GoogleAuthHttp http, TimeProvider time)
    : IGoogleCredential
{
    private readonly Uri tokenUri = GoogleOAuth.RequireGoogleEndpoint(
        file.TokenUri ?? "https://oauth2.googleapis.com/token",
        "token_uri",
        GoogleOAuth.UniverseDomain(file));

    private readonly string refreshToken = string.IsNullOrEmpty(file.RefreshToken) || string.IsNullOrEmpty(file.ClientId)
        ? throw new InvalidOperationException("The authorized_user credential needs client_id and refresh_token.")
        : file.RefreshToken;

    public string Kind => "gcloud user credentials";

    public async Task<GoogleAccessToken> FetchAsync(CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = GoogleOAuth.FormPost(
            tokenUri,
            [
                new("grant_type", "refresh_token"),
                new("client_id", file.ClientId!),
                new("client_secret", file.ClientSecret ?? string.Empty),
                new("refresh_token", refreshToken)
            ]);
        HttpResult result = await http.SendAsync(
            request,
            "OAuth refresh request",
            GoogleAuthHttp.MaximumResponseBytes,
            cancellationToken);
        return GoogleOAuth.ReadTokenResponse(result.Body, "OAuth refresh request", time.GetUtcNow());
    }
}

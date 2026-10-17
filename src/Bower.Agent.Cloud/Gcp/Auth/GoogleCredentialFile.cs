using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>
/// The fields Bower reads from an Application Default Credentials JSON file
/// (<c>external_account</c> per AIP-4117, and the lab-only <c>service_account</c> and
/// <c>authorized_user</c> types). Unknown fields are ignored, as Google's libraries do.
/// </summary>
internal sealed record GoogleCredentialFile
{
    /// <summary>Credential files are a few KiB; anything larger is not a credential file.</summary>
    public const int MaximumBytes = 64 * 1024;

    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("audience")]
    public string? Audience { get; init; }

    [JsonPropertyName("subject_token_type")]
    public string? SubjectTokenType { get; init; }

    [JsonPropertyName("token_url")]
    public string? TokenUrl { get; init; }

    [JsonPropertyName("service_account_impersonation_url")]
    public string? ServiceAccountImpersonationUrl { get; init; }

    [JsonPropertyName("service_account_impersonation")]
    public ImpersonationOptions? ServiceAccountImpersonation { get; init; }

    [JsonPropertyName("credential_source")]
    public CredentialSource? CredentialSource { get; init; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; init; }

    [JsonPropertyName("workforce_pool_user_project")]
    public string? WorkforcePoolUserProject { get; init; }

    [JsonPropertyName("universe_domain")]
    public string? UniverseDomain { get; init; }

    // service_account (lab only)
    [JsonPropertyName("client_email")]
    public string? ClientEmail { get; init; }

    [JsonPropertyName("private_key")]
    public string? PrivateKey { get; init; }

    [JsonPropertyName("private_key_id")]
    public string? PrivateKeyId { get; init; }

    [JsonPropertyName("token_uri")]
    public string? TokenUri { get; init; }

    // authorized_user (lab only)
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    /// <summary>Parses a credential file. Error messages never quote file contents.</summary>
    public static GoogleCredentialFile Parse(ReadOnlySpan<byte> json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, GoogleAuthJsonContext.Default.GoogleCredentialFile)
                ?? throw new InvalidOperationException("The Google credential file is empty.");
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("The Google credential file is not valid credential JSON.");
        }
    }
}

internal sealed record ImpersonationOptions
{
    [JsonPropertyName("token_lifetime_seconds")]
    public int? TokenLifetimeSeconds { get; init; }
}

internal sealed record CredentialSource
{
    [JsonPropertyName("file")]
    public string? File { get; init; }

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("headers")]
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    [JsonPropertyName("format")]
    public SubjectTokenFormat? Format { get; init; }

    [JsonPropertyName("environment_id")]
    public string? EnvironmentId { get; init; }

    [JsonPropertyName("region_url")]
    public string? RegionUrl { get; init; }

    [JsonPropertyName("regional_cred_verification_url")]
    public string? RegionalCredVerificationUrl { get; init; }

    [JsonPropertyName("imdsv2_session_token_url")]
    public string? Imdsv2SessionTokenUrl { get; init; }

    /// <summary>Executable-sourced credentials run a command from configuration; always refused.</summary>
    [JsonPropertyName("executable")]
    public JsonElement? Executable { get; init; }

    /// <summary>X.509 (mTLS) workload credentials; not supported.</summary>
    [JsonPropertyName("certificate")]
    public JsonElement? Certificate { get; init; }
}

internal sealed record SubjectTokenFormat
{
    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("subject_token_field_name")]
    public string? SubjectTokenFieldName { get; init; }
}

/// <summary>OAuth 2.0 / RFC 8693 token response (STS, OAuth token endpoint, metadata server).</summary>
internal sealed record OAuthTokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("issued_token_type")]
    public string? IssuedTokenType { get; init; }

    [JsonPropertyName("expires_in")]
    public long? ExpiresIn { get; init; }
}

/// <summary>IAM Credentials <c>generateAccessToken</c> request.</summary>
internal sealed record GenerateAccessTokenRequest(
    [property: JsonPropertyName("scope")] IReadOnlyList<string> Scope,
    [property: JsonPropertyName("lifetime")] string Lifetime);

/// <summary>IAM Credentials <c>generateAccessToken</c> response.</summary>
internal sealed record GenerateAccessTokenResponse
{
    [JsonPropertyName("accessToken")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("expireTime")]
    public string? ExpireTime { get; init; }
}

/// <summary>AWS instance metadata security credentials.</summary>
internal sealed record AwsMetadataCredentials
{
    [JsonPropertyName("AccessKeyId")]
    public string? AccessKeyId { get; init; }

    [JsonPropertyName("SecretAccessKey")]
    public string? SecretAccessKey { get; init; }

    [JsonPropertyName("Token")]
    public string? Token { get; init; }
}

/// <summary>
/// The serialized, signed GetCallerIdentity request sent to STS as the AWS subject token
/// (AIP-4117). The request has no body, so no <c>body</c> member is written, as in Google's
/// Python, Go and Node.js libraries.
/// </summary>
internal sealed record AwsSubjectToken(
    [property: JsonPropertyName("url")] string Url,
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("headers")] IReadOnlyList<AwsSubjectTokenHeader> Headers);

internal sealed record AwsSubjectTokenHeader(
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("value")] string Value);

/// <summary>Self-signed JWT header and claims for the lab-only service account key flow.</summary>
internal sealed record JwtHeader(
    [property: JsonPropertyName("alg")] string Algorithm,
    [property: JsonPropertyName("typ")] string Type,
    [property: JsonPropertyName("kid"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? KeyId);

internal sealed record JwtClaims(
    [property: JsonPropertyName("iss")] string Issuer,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("aud")] string Audience,
    [property: JsonPropertyName("iat")] long IssuedAt,
    [property: JsonPropertyName("exp")] long ExpiresAt);

/// <summary>STS <c>options</c> for workforce pools.</summary>
internal sealed record StsOptions([property: JsonPropertyName("userProject")] string UserProject);

/// <summary>Source-generated JSON for Google credential flows (Native AOT safe).</summary>
[JsonSourceGenerationOptions(MaxDepth = 16)]
[JsonSerializable(typeof(GoogleCredentialFile))]
[JsonSerializable(typeof(OAuthTokenResponse))]
[JsonSerializable(typeof(GenerateAccessTokenRequest))]
[JsonSerializable(typeof(GenerateAccessTokenResponse))]
[JsonSerializable(typeof(AwsMetadataCredentials))]
[JsonSerializable(typeof(AwsSubjectToken))]
[JsonSerializable(typeof(JwtHeader))]
[JsonSerializable(typeof(JwtClaims))]
[JsonSerializable(typeof(StsOptions))]
internal sealed partial class GoogleAuthJsonContext : JsonSerializerContext;

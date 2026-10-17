using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>
/// Workload Identity Federation (<c>external_account</c>, AIP-4117): read a subject token
/// from a file, a local URL or a SigV4-signed AWS GetCallerIdentity request, exchange it at
/// Google STS (RFC 8693) and optionally impersonate a service account through IAM Credentials
/// <c>generateAccessToken</c>. Executable-sourced and X.509 credential sources are refused.
/// </summary>
internal sealed partial class ExternalAccountCredential : IGoogleCredential
{
    public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
    public const string AwsTokenType = "urn:ietf:params:aws:token-type:aws4_request";

    private const int DefaultLifetimeSeconds = 3600;

    /// <summary>Subject token types Google STS accepts for file and URL sources.</summary>
    private static readonly HashSet<string> OidcSamlTokenTypes = new(StringComparer.Ordinal)
    {
        "urn:ietf:params:oauth:token-type:jwt",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
        AccessTokenType
    };

    private readonly GoogleAuthHttp http;
    private readonly Func<string, string?> environment;
    private readonly TimeProvider time;
    private readonly IReadOnlyList<string> scopes;
    private readonly string audience;
    private readonly string subjectTokenType;
    private readonly Uri tokenUrl;
    private readonly Uri? impersonationUrl;
    private readonly int lifetimeSeconds;
    private readonly string? clientId;
    private readonly string? clientSecret;
    private readonly string? workforceUserProject;
    private readonly Func<CancellationToken, Task<string>> subjectToken;

    public ExternalAccountCredential(
        GoogleCredentialFile file,
        IReadOnlyList<string> scopes,
        GoogleAuthHttp http,
        Func<string, string?> environment,
        TimeProvider time)
    {
        this.http = http;
        this.environment = environment;
        this.time = time;
        this.scopes = scopes;
        string universe = GoogleOAuth.UniverseDomain(file);

        audience = file.Audience ?? string.Empty;
        if (!AudiencePattern().IsMatch(audience))
        {
            throw new InvalidOperationException(
                "The external_account audience must be a workload or workforce identity pool provider "
                + "(//iam.googleapis.com/.../workloadIdentityPools/{pool}/providers/{provider}).");
        }

        subjectTokenType = file.SubjectTokenType ?? throw new InvalidOperationException(
            "The external_account credential has no subject_token_type.");
        tokenUrl = GoogleOAuth.RequireGoogleEndpoint(file.TokenUrl, "token_url", universe);
        if (!string.IsNullOrEmpty(file.ServiceAccountImpersonationUrl))
        {
            impersonationUrl = GoogleOAuth.RequireGoogleEndpoint(
                file.ServiceAccountImpersonationUrl,
                "service_account_impersonation_url",
                universe);
            if (!impersonationUrl.AbsolutePath.EndsWith(":generateAccessToken", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The service_account_impersonation_url must call IAM Credentials generateAccessToken.");
            }
        }

        lifetimeSeconds = file.ServiceAccountImpersonation?.TokenLifetimeSeconds ?? DefaultLifetimeSeconds;
        if (lifetimeSeconds is < 600 or > 43200)
        {
            throw new InvalidOperationException(
                "service_account_impersonation.token_lifetime_seconds must be between 600 and 43200.");
        }

        clientId = string.IsNullOrEmpty(file.ClientId) ? null : file.ClientId;
        clientSecret = file.ClientSecret;
        if (!string.IsNullOrEmpty(file.WorkforcePoolUserProject))
        {
            if (!audience.Contains("/workforcePools/", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "workforce_pool_user_project is only valid for a workforce identity pool audience.");
            }

            workforceUserProject = file.WorkforcePoolUserProject;
        }

        CredentialSource source = file.CredentialSource ?? throw new InvalidOperationException(
            "The external_account credential has no credential_source.");
        subjectToken = SelectSource(source);
    }

    public string Kind => "external_account (Workload Identity Federation)";

    public async Task<GoogleAccessToken> FetchAsync(CancellationToken cancellationToken)
    {
        string subject = await subjectToken(cancellationToken);
        if (string.IsNullOrEmpty(subject))
        {
            throw new InvalidOperationException("The external_account credential source returned an empty subject token.");
        }

        // With impersonation STS issues a cloud-platform token for the IAM call; the
        // requested scopes go to generateAccessToken (AIP-4117).
        GoogleAccessToken federated = await ExchangeAsync(
            subject,
            impersonationUrl is null ? string.Join(' ', scopes) : GoogleOAuth.CloudPlatformScope,
            cancellationToken);
        return impersonationUrl is null ? federated : await ImpersonateAsync(federated, cancellationToken);
    }

    private async Task<GoogleAccessToken> ExchangeAsync(string subject, string scope, CancellationToken cancellationToken)
    {
        List<KeyValuePair<string, string>> fields =
        [
            new("grant_type", TokenExchangeGrant),
            new("audience", audience),
            new("scope", scope),
            new("requested_token_type", AccessTokenType),
            new("subject_token", subject),
            new("subject_token_type", subjectTokenType)
        ];
        if (workforceUserProject is not null && clientId is null)
        {
            fields.Add(new(
                "options",
                JsonSerializer.Serialize(new StsOptions(workforceUserProject), GoogleAuthJsonContext.Default.StsOptions)));
        }

        using HttpRequestMessage request = GoogleOAuth.FormPost(tokenUrl, fields);
        if (clientId is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}")));
        }

        HttpResult result = await http.SendAsync(
            request,
            "Google STS token exchange",
            GoogleAuthHttp.MaximumResponseBytes,
            cancellationToken);
        return GoogleOAuth.ReadTokenResponse(result.Body, "Google STS token exchange", time.GetUtcNow(), AccessTokenType);
    }

    private async Task<GoogleAccessToken> ImpersonateAsync(GoogleAccessToken federated, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, impersonationUrl)
        {
            Content = JsonContent.Create(
                new GenerateAccessTokenRequest(scopes, lifetimeSeconds.ToString(CultureInfo.InvariantCulture) + "s"),
                GoogleAuthJsonContext.Default.GenerateAccessTokenRequest)
        };
        GoogleOAuth.Bearer(request, federated.Value);
        HttpResult result = await http.SendAsync(
            request,
            "IAM Credentials generateAccessToken",
            GoogleAuthHttp.MaximumResponseBytes,
            cancellationToken);
        GenerateAccessTokenResponse response = GoogleOAuth.Deserialize(
            result.Body,
            GoogleAuthJsonContext.Default.GenerateAccessTokenResponse,
            "IAM Credentials generateAccessToken");
        if (string.IsNullOrEmpty(response.AccessToken))
        {
            throw new InvalidOperationException("IAM Credentials generateAccessToken returned no access token.");
        }

        return new GoogleAccessToken(
            response.AccessToken,
            GoogleOAuth.ParseRfc3339(response.ExpireTime, "IAM Credentials generateAccessToken"));
    }

    private Func<CancellationToken, Task<string>> SelectSource(CredentialSource source)
    {
        if (source.Executable is not null)
        {
            // Configuration must never execute code (Bower invariant), whatever
            // GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES says.
            throw new InvalidOperationException(
                "Executable-sourced Workload Identity Federation credentials are not supported; "
                + "use a file, URL or AWS credential source.");
        }

        if (source.Certificate is not null)
        {
            throw new InvalidOperationException(
                "X.509 (certificate) Workload Identity Federation credentials are not supported.");
        }

        if (source.EnvironmentId is { } environmentId)
        {
            if (!environmentId.StartsWith("aws", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Unsupported credential_source.environment_id.");
            }

            if (environmentId != "aws1")
            {
                throw new InvalidOperationException(
                    $"credential_source.environment_id {environmentId} needs a newer Bower; only aws1 is supported.");
            }

            if (subjectTokenType != AwsTokenType)
            {
                throw new InvalidOperationException($"An AWS credential source needs subject_token_type {AwsTokenType}.");
            }

            AwsSubjectTokenSource aws = new(source, audience, http, environment, time);
            return aws.GetAsync;
        }

        if (!OidcSamlTokenTypes.Contains(subjectTokenType))
        {
            throw new InvalidOperationException("Unsupported subject_token_type for a file or URL credential source.");
        }

        (bool json, string? field) = Format(source.Format);
        if (!string.IsNullOrEmpty(source.File))
        {
            // AIP-4117: file takes precedence over url.
            string path = source.File;
            return async cancellationToken =>
                Extract(await ReadFileAsync(path, cancellationToken), json, field, "credential_source.file");
        }

        if (!string.IsNullOrEmpty(source.Url))
        {
            if (!Uri.TryCreate(source.Url, UriKind.Absolute, out Uri? url) || !string.IsNullOrEmpty(url.UserInfo))
            {
                throw new InvalidOperationException("credential_source.url must be an absolute URL.");
            }

            if (url.Scheme != Uri.UriSchemeHttps
                && !(url.Scheme == Uri.UriSchemeHttp && GoogleAuthHttp.IsMetadataOrLoopback(url)))
            {
                throw new InvalidOperationException(
                    "credential_source.url must use HTTPS unless it is a metadata server or loopback address.");
            }

            IReadOnlyDictionary<string, string> headers = source.Headers ?? new Dictionary<string, string>();
            return async cancellationToken =>
            {
                using HttpRequestMessage request = new(HttpMethod.Get, url);
                foreach ((string name, string value) in headers)
                {
                    if (!request.Headers.TryAddWithoutValidation(name, value)
                        || value.Contains('\r', StringComparison.Ordinal)
                        || value.Contains('\n', StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("credential_source.headers contains an invalid header.");
                    }
                }

                HttpResult result = await http.SendAsync(
                    request,
                    "Subject token request",
                    GoogleAuthHttp.MaximumSubjectTokenBytes,
                    cancellationToken);
                return Extract(result.Body, json, field, "credential_source.url");
            };
        }

        throw new InvalidOperationException(
            "credential_source must set file, url or environment_id (executable and certificate sources are not supported).");
    }

    private static (bool Json, string? Field) Format(SubjectTokenFormat? format)
    {
        string type = format?.Type ?? "text";
        if (string.Equals(type, "text", StringComparison.OrdinalIgnoreCase))
        {
            return (false, null);
        }

        if (!string.Equals(type, "json", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("credential_source.format.type must be text or json.");
        }

        return string.IsNullOrEmpty(format?.SubjectTokenFieldName)
            ? throw new InvalidOperationException("credential_source.format.subject_token_field_name is required for json.")
            : (true, format.SubjectTokenFieldName);
    }

    private static async Task<byte[]> ReadFileAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using FileStream stream = new(
                path,
                new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Options = FileOptions.Asynchronous });
            if (stream.CanSeek && stream.Length > GoogleAuthHttp.MaximumSubjectTokenBytes)
            {
                throw new InvalidOperationException(
                    $"credential_source.file exceeds {GoogleAuthHttp.MaximumSubjectTokenBytes} bytes.");
            }

            using StreamContent content = new(stream);
            return await GoogleAuthHttp.ReadBoundedAsync(
                content,
                GoogleAuthHttp.MaximumSubjectTokenBytes,
                "credential_source.file",
                cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Projected tokens rotate by symlink swap; a missing file is a retryable failure.
            throw new InvalidOperationException(
                $"credential_source.file could not be read ({exception.GetType().Name}).");
        }
    }

    private static string Extract(byte[] body, bool json, string? field, string origin)
    {
        if (!json)
        {
            return Encoding.UTF8.GetString(body).Trim();
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty(field!, out JsonElement value)
                && value.ValueKind == JsonValueKind.String
                    ? value.GetString()!
                    : throw new InvalidOperationException($"The {origin} JSON has no string field {field}.");
        }
        catch (JsonException)
        {
            throw new InvalidOperationException($"The {origin} response is not valid JSON.");
        }
    }

    /// <summary>
    /// //iam.{universe}/projects/{n}/locations/{l}/workloadIdentityPools/{p}/providers/{id} or
    /// //iam.{universe}/locations/{l}/workforcePools/{p}/providers/{id}.
    /// </summary>
    [GeneratedRegex(
        "^//iam\\.[a-z0-9.-]+/(projects/[^/]+/locations/[^/]+/workloadIdentityPools|locations/[^/]+/workforcePools)/[^/]+/providers/[^/]+$")]
    private static partial Regex AudiencePattern();
}

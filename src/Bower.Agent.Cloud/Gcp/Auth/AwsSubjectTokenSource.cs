using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>
/// AWS-sourced subject token (AIP-4117, <c>environment_id</c> aws1): a SigV4-signed
/// GetCallerIdentity request that Google STS replays to AWS to prove the workload's AWS
/// identity. The request is signed here but never sent to AWS. Credentials come from
/// <c>AWS_ACCESS_KEY_ID</c>/<c>AWS_SECRET_ACCESS_KEY</c>/<c>AWS_SESSION_TOKEN</c> or the EC2
/// instance metadata service (IMDSv2 when <c>imdsv2_session_token_url</c> is set).
/// </summary>
internal sealed partial class AwsSubjectTokenSource
{
    private const string ImdsTokenHeader = "X-aws-ec2-metadata-token";
    private const string ImdsTokenTtlHeader = "X-aws-ec2-metadata-token-ttl-seconds";

    private readonly string audience;
    private readonly GoogleAuthHttp http;
    private readonly Func<string, string?> environment;
    private readonly TimeProvider time;
    private readonly Uri? regionUrl;
    private readonly Uri? credentialsUrl;
    private readonly Uri? sessionTokenUrl;
    private readonly string verificationUrl;

    public AwsSubjectTokenSource(
        CredentialSource source,
        string audience,
        GoogleAuthHttp http,
        Func<string, string?> environment,
        TimeProvider time)
    {
        this.audience = audience;
        this.http = http;
        this.environment = environment;
        this.time = time;
        regionUrl = MetadataUrl(source.RegionUrl, "region_url");
        credentialsUrl = MetadataUrl(source.Url, "url");
        sessionTokenUrl = MetadataUrl(source.Imdsv2SessionTokenUrl, "imdsv2_session_token_url");
        verificationUrl = source.RegionalCredVerificationUrl
            ?? throw new InvalidOperationException("The AWS credential source has no regional_cred_verification_url.");
        if (!verificationUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("regional_cred_verification_url must be an HTTPS URL.");
        }
    }

    public async Task<string> GetAsync(CancellationToken cancellationToken)
    {
        string? region = FirstSet("AWS_REGION", "AWS_DEFAULT_REGION");
        AwsCredentials? credentials = EnvironmentCredentials();

        // IMDSv2 session token only when the metadata server is actually needed.
        string? session = null;
        if ((region is null || credentials is null) && sessionTokenUrl is not null)
        {
            session = await SessionTokenAsync(cancellationToken);
        }

        region ??= await RegionAsync(session, cancellationToken);
        credentials ??= await MetadataCredentialsAsync(session, cancellationToken);
        if (!RegionPattern().IsMatch(region))
        {
            throw new InvalidOperationException("The AWS region is not a valid region name.");
        }

        string url = verificationUrl.Replace("{region}", region, StringComparison.Ordinal);
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? target) || target.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("regional_cred_verification_url must be an HTTPS URL.");
        }

        AwsSignedRequest signed = AwsSignatureV4.Sign(
            "POST",
            target,
            [new("x-goog-cloud-target-resource", audience)],
            [],
            credentials,
            region,
            "sts",
            time.GetUtcNow());

        // Header keys as Google's libraries send them, sorted ordinally.
        List<AwsSubjectTokenHeader> headers = [new("Authorization", signed.Authorization)];
        headers.AddRange(signed.Headers.Select(item => new AwsSubjectTokenHeader(item.Key, item.Value)));
        headers.Sort((left, right) => string.CompareOrdinal(left.Key, right.Key));
        string json = JsonSerializer.Serialize(
            new AwsSubjectToken(url, "POST", headers),
            GoogleAuthJsonContext.Default.AwsSubjectToken);
        return Uri.EscapeDataString(json);
    }

    private AwsCredentials? EnvironmentCredentials()
    {
        string? key = environment("AWS_ACCESS_KEY_ID");
        string? secret = environment("AWS_SECRET_ACCESS_KEY");
        return string.IsNullOrEmpty(key) || string.IsNullOrEmpty(secret)
            ? null
            : new AwsCredentials(key, secret, NullIfEmpty(environment("AWS_SESSION_TOKEN")));
    }

    private async Task<string> SessionTokenAsync(CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Put, sessionTokenUrl);
        request.Headers.Add(ImdsTokenTtlHeader, "300");
        string token = await GetTextAsync(request, "AWS IMDSv2 session token request", cancellationToken);
        return token.Length == 0 ? throw new InvalidOperationException("AWS IMDSv2 returned an empty session token.") : token;
    }

    private async Task<string> RegionAsync(string? session, CancellationToken cancellationToken)
    {
        if (regionUrl is null)
        {
            throw new InvalidOperationException(
                "Set AWS_REGION or AWS_DEFAULT_REGION, or region_url in the credential configuration.");
        }

        using HttpRequestMessage request = Metadata(regionUrl, session);
        string zone = await GetTextAsync(request, "AWS region request", cancellationToken);
        // The endpoint returns the availability zone (us-east-1d); drop the zone letter.
        return zone.Length < 2 ? throw new InvalidOperationException("AWS returned no availability zone.") : zone[..^1];
    }

    private async Task<AwsCredentials> MetadataCredentialsAsync(string? session, CancellationToken cancellationToken)
    {
        if (credentialsUrl is null)
        {
            throw new InvalidOperationException(
                "No AWS credentials: set the AWS credential environment variables or url in the credential configuration.");
        }

        string role;
        using (HttpRequestMessage request = Metadata(credentialsUrl, session))
        {
            role = await GetTextAsync(request, "AWS role name request", cancellationToken);
        }

        if (!RoleNamePattern().IsMatch(role))
        {
            throw new InvalidOperationException("AWS instance metadata returned an invalid role name.");
        }

        Uri roleUrl = new(credentialsUrl.AbsoluteUri.TrimEnd('/') + "/" + role);
        using HttpRequestMessage credentialsRequest = Metadata(roleUrl, session);
        HttpResult result = await http.SendAsync(
            credentialsRequest,
            "AWS security credentials request",
            GoogleAuthHttp.MaximumResponseBytes,
            cancellationToken);
        AwsMetadataCredentials credentials = GoogleOAuth.Deserialize(
            result.Body,
            GoogleAuthJsonContext.Default.AwsMetadataCredentials,
            "AWS security credentials request");
        return string.IsNullOrEmpty(credentials.AccessKeyId) || string.IsNullOrEmpty(credentials.SecretAccessKey)
            ? throw new InvalidOperationException("AWS instance metadata returned incomplete security credentials.")
            : new AwsCredentials(credentials.AccessKeyId, credentials.SecretAccessKey, NullIfEmpty(credentials.Token));
    }

    private async Task<string> GetTextAsync(HttpRequestMessage request, string operation, CancellationToken cancellationToken)
    {
        HttpResult result = await http.SendAsync(request, operation, GoogleAuthHttp.MaximumResponseBytes, cancellationToken);
        return Encoding.UTF8.GetString(result.Body).Trim();
    }

    private static HttpRequestMessage Metadata(Uri url, string? session)
    {
        HttpRequestMessage request = new(HttpMethod.Get, url);
        if (session is not null)
        {
            request.Headers.Add(ImdsTokenHeader, session);
        }

        return request;
    }

    private string? FirstSet(params string[] names) =>
        names.Select(name => NullIfEmpty(environment(name))).FirstOrDefault(value => value is not null);

    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    /// <summary>AIP-4117: metadata URLs must be the AWS metadata server (169.254.169.254 or fd00:ec2::254).</summary>
    private static Uri? MetadataUrl(string? value, string field)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        return Uri.TryCreate(value, UriKind.Absolute, out Uri? url)
            && url.Scheme == Uri.UriSchemeHttp
            && string.IsNullOrEmpty(url.UserInfo)
            && url.DnsSafeHost is "169.254.169.254" or "fd00:ec2::254"
                ? url
                : throw new InvalidOperationException(
                    $"credential_source.{field} must be the AWS metadata server (169.254.169.254 or fd00:ec2::254).");
    }

    [GeneratedRegex("^[a-z]{2}(-[a-z]+)+-[0-9]+$")]
    private static partial Regex RegionPattern();

    [GeneratedRegex("^[A-Za-z0-9+=,.@_-]{1,128}$")]
    private static partial Regex RoleNamePattern();
}

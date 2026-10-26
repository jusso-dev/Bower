using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors.Secrets;

public sealed partial class AwsSecretDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Aws;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => AwsRegex();

    protected override string? SubKind(ReadOnlySpan<char> matched)
    {
        if (matched.StartsWith("AKIA", StringComparison.Ordinal) ||
            matched.StartsWith("ASIA", StringComparison.Ordinal))
        {
            return "access-key-id";
        }

        if (matched.Contains("ASIA", StringComparison.Ordinal) ||
            matched.Contains("session", StringComparison.OrdinalIgnoreCase))
        {
            return "session-token";
        }

        return "secret-access-key";
    }

    [GeneratedRegex(
        @"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|(?:aws)?_?secret_?(?:access)?_?key\s*[:=]\s*\S+|aws_session_token\s*[:=]\s*\S+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AwsRegex();
}

public sealed partial class AzureSecretDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Azure;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => AzureRegex();

    [GeneratedRegex(
        @"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}|sv=\d{4}-\d{2}-\d{2}[^;\s]*sig=[A-Za-z0-9%]+|SharedAccessSignature=[^\s;]+|AccountKey=[A-Za-z0-9+/=]{40,}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AzureRegex();
}

public sealed partial class EntraTokenDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Entra;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => EntraRegex();

    [GeneratedRegex(
        @"\b(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b|device_code\s*[:=]\s*[A-Za-z0-9\-_]{10,}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EntraRegex();
}

public sealed partial class GcpSecretDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Gcp;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => GcpRegex();

    [GeneratedRegex(
        @"""type""\s*:\s*""service_account""|""private_key""\s*:\s*""-----BEGIN|AIza[0-9A-Za-z\-_]{35}|ya29\.[0-9A-Za-z\-_]+",
        RegexOptions.CultureInvariant)]
    private static partial Regex GcpRegex();
}

public sealed partial class JwtDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Jwt;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => JwtRegex();
    protected override bool RequiresValidation => true;

    protected override bool Validate(ReadOnlySpan<char> matched)
    {
        // Three Base64URL segments separated by '.'.
        int first = matched.IndexOf('.');
        if (first <= 0)
        {
            return false;
        }

        int second = matched[(first + 1)..].IndexOf('.');
        if (second <= 0)
        {
            return false;
        }

        int secondAbs = first + 1 + second;
        if (secondAbs >= matched.Length - 1)
        {
            return false;
        }

        // Header should decode as JSON starting with '{' (Base64 of eyJ...).
        return matched.StartsWith("eyJ", StringComparison.Ordinal);
    }

    [GeneratedRegex(
        @"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex JwtRegex();
}

public sealed partial class OAuthTokenDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.OAuth;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => OAuthRegex();

    [GeneratedRegex(
        @"\b(?:access_token|refresh_token|id_token)\s*[:=]\s*[A-Za-z0-9\-._~+/]+=*",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OAuthRegex();
}

/// <summary>
/// Provider API key patterns. New providers are registered without changing the engine.
/// </summary>
public sealed partial class ApiKeyDetector : ISensitiveDetector
{
    public string Id => DetectorIds.ApiKey;
    public string Category => DetectorCategories.Secrets;

    // Source-generated (AOT-friendly, no Reflection.Emit at startup). No match timeout:
    // a wall-clock timeout makes the outcome depend on machine load (a valid value
    // quarantines when the thread is descheduled), unlike the Rust engine. Each pattern
    // is linear in the backtracking engine: it starts at a word boundary and every
    // unbounded single-class loop is followed by a boundary or a character the loop
    // cannot consume, so a failed attempt only rescans its own run. Input is bounded by
    // PrivacyEngine.MaximumPayloadBytes.
    private static readonly (string Provider, Regex Regex)[] Compiled =
    [
        ("OpenAI", OpenAIRegex()),
        ("Anthropic", AnthropicRegex()),
        ("GitHub", GitHubRegex()),
        ("GitLab", GitLabRegex()),
        ("Slack", SlackRegex()),
        ("Stripe", StripeRegex()),
        ("Twilio", TwilioRegex()),
        ("Cloudflare", CloudflareRegex()),
        ("Atlassian", AtlassianRegex()),
        ("Datadog", DatadogRegex()),
        ("PagerDuty", PagerDutyRegex()),
        ("Okta", OktaRegex()),
        ("MongoDB", MongoDBRegex()),
        ("Snowflake", SnowflakeRegex())
    ];

    public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        foreach ((string provider, Regex regex) in Compiled)
        {
            // High-FP patterns need context.
            if (provider is "PagerDuty" or "Datadog")
            {
                if (!text.Contains(provider, StringComparison.OrdinalIgnoreCase) &&
                    !text.Contains("api_key", StringComparison.OrdinalIgnoreCase) &&
                    !text.Contains("apikey", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
            }

            foreach (ValueMatch match in regex.EnumerateMatches(text))
            {
                matches.Add(new DetectionMatch(
                    Id,
                    Category,
                    match.Index,
                    match.Length,
                    Validated: false,
                    SubKind: provider));
            }
        }
    }

    [GeneratedRegex(@"\bsk-[A-Za-z0-9]{20,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex OpenAIRegex();

    [GeneratedRegex(@"\bsk-ant-[A-Za-z0-9\-_]{20,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex AnthropicRegex();

    [GeneratedRegex(@"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex GitHubRegex();

    [GeneratedRegex(@"\bglpat-[A-Za-z0-9\-_]{20,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex GitLabRegex();

    [GeneratedRegex(@"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex SlackRegex();

    [GeneratedRegex(@"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex StripeRegex();

    [GeneratedRegex(@"\bSK[0-9a-fA-F]{32}\b", RegexOptions.CultureInvariant)]
    private static partial Regex TwilioRegex();

    [GeneratedRegex(@"\b(?:cfx|v1\.0-)[A-Za-z0-9_\-]{20,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex CloudflareRegex();

    [GeneratedRegex(@"\bATATT3[A-Za-z0-9=_\-]{20,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex AtlassianRegex();

    [GeneratedRegex(@"\b(?:[a-f0-9]{32}|ddog_api_key)\b", RegexOptions.CultureInvariant)]
    private static partial Regex DatadogRegex();

    [GeneratedRegex(@"\b[a-f0-9]{32}\b", RegexOptions.CultureInvariant)]
    private static partial Regex PagerDutyRegex();

    [GeneratedRegex(@"\b00[A-Za-z0-9_\-]{40,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex OktaRegex();

    [GeneratedRegex(@"\bmongodb(?:\+srv)?:\/\/[^\s]+\b", RegexOptions.CultureInvariant)]
    private static partial Regex MongoDBRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9]{8,}-[A-Za-z0-9]{4,}\.[A-Za-z0-9]+\.snowflakecomputing\.com\b", RegexOptions.CultureInvariant)]
    private static partial Regex SnowflakeRegex();
}

public sealed partial class KubernetesSecretDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Kubernetes;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => K8sRegex();

    [GeneratedRegex(
        @"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|kubeconfig|kind:\s*Config[\s\S]{0,80}users:|Bearer\s+eyJ[A-Za-z0-9_-]+\.",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex K8sRegex();
}

public sealed partial class DockerCredentialDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Docker;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => DockerRegex();

    [GeneratedRegex(
        @"\b(?:docker\s+login|auths\s*\{|""auth""\s*:\s*""[A-Za-z0-9+/=]{20,}"")\b|registry[^\n]{0,40}password\s*[:=]\s*\S+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DockerRegex();
}

public sealed partial class DatabaseCredentialDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Database;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => DbRegex();

    [GeneratedRegex(
        @"(?:Server|Data Source|Host)=[^;]+;.*(?:Password|Pwd)=[^;]+|jdbc:[a-z0-9]+:\/\/[^\s]+|postgres(?:ql)?:\/\/[^\s]+|mysql:\/\/[^\s]+|mongodb(?:\+srv)?:\/\/[^\s]+|Driver=\{[^}]+\}.*Pwd=",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DbRegex();
}

public sealed partial class EnvironmentVariableSecretDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.EnvVar;
    public override string Category => DetectorCategories.Secrets;
    protected override Regex Pattern => EnvRegex();

    [GeneratedRegex(
        @"\b(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|AUTH_TOKEN)\s*=\s*\S+",
        RegexOptions.CultureInvariant)]
    private static partial Regex EnvRegex();
}

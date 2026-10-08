using System.Globalization;
using System.Text.RegularExpressions;

namespace Bower.Agent.Cloud;

public sealed record AwsQueueSettings
{
    public required Uri QueueUrl { get; init; }

    public required string Region { get; init; }

    public required string AccountId { get; init; }

    /// <summary>Buckets whose ObjectCreated notifications may be fetched. Empty disables S3 reads.</summary>
    public IReadOnlySet<string> AllowedBuckets { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    public long MaximumObjectBytes { get; init; } = 32L * 1024 * 1024;
}

public sealed record GcpSubscriptionSettings
{
    /// <summary>Full name: projects/{project}/subscriptions/{subscription}.</summary>
    public required string Subscription { get; init; }

    public Uri Endpoint { get; init; } = new("https://pubsub.googleapis.com/");

    public bool AllowServiceAccountKey { get; init; }
}

/// <summary>Cloud agent configuration from environment variables, validated before start.</summary>
public sealed partial record CloudAgentSettings
{
    public static readonly IReadOnlySet<string> AustralianAwsRegions =
        new HashSet<string>(["ap-southeast-2", "ap-southeast-4"], StringComparer.Ordinal);

    public required string AgentId { get; init; }

    public required Uri CollectorUrl { get; init; }

    public string? IngestToken { get; init; }

    public string Environment { get; init; } = "production";

    public AwsQueueSettings? Aws { get; init; }

    public GcpSubscriptionSettings? Gcp { get; init; }

    public int BatchSize { get; init; } = 10;

    /// <summary>How long a released message stays hidden before redelivery.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Visibility (SQS) or ack deadline (Pub/Sub) kept while a large message is forwarded.</summary>
    public TimeSpan Lease { get; init; } = TimeSpan.FromMinutes(5);

    public bool IncludeRawRecords { get; init; }

    public bool RequireAustralianRegion { get; init; }

    public string HeartbeatDirectory { get; init; } = "/tmp/bower-cloud";

    public string HeartbeatPath(string sourceName) => Path.Combine(HeartbeatDirectory, sourceName);

    public static CloudAgentSettings FromEnvironment(Func<string, string?>? read = null)
    {
        read ??= System.Environment.GetEnvironmentVariable;
        string? tokenFile = read("BOWER_INGEST_TOKEN_FILE");
        string? token = string.IsNullOrWhiteSpace(tokenFile)
            ? read("BOWER_INGEST_TOKEN")
            : File.ReadAllText(tokenFile).Trim();
        string collector = read("BOWER_COLLECTOR_URL") ?? "http://bower-collector:4319";

        AwsQueueSettings? aws = null;
        if (read("BOWER_AWS_SQS_QUEUE_URL") is { Length: > 0 } queue)
        {
            aws = ParseQueue(queue, read("BOWER_AWS_REGION"), read("BOWER_AWS_ACCOUNT_ID")) with
            {
                AllowedBuckets = new HashSet<string>(
                    (read("BOWER_AWS_S3_BUCKETS") ?? string.Empty)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                    StringComparer.Ordinal),
                MaximumObjectBytes = ReadInt(read, "BOWER_AWS_S3_MAX_OBJECT_MB", 32) * 1024L * 1024
            };
            if (!IsTrue(read("BOWER_AWS_ALLOW_STATIC_KEYS"))
                && !string.IsNullOrEmpty(read("AWS_ACCESS_KEY_ID"))
                && string.IsNullOrEmpty(read("AWS_SESSION_TOKEN")))
            {
                throw new InvalidOperationException(
                    "Long-lived AWS access keys are not accepted. Use an instance profile, ECS task role or IRSA, "
                    + "or set BOWER_AWS_ALLOW_STATIC_KEYS=true for a lab.");
            }
        }

        GcpSubscriptionSettings? gcp = null;
        if (read("BOWER_GCP_SUBSCRIPTION") is { Length: > 0 } subscription)
        {
            string endpoint = read("BOWER_GCP_PUBSUB_ENDPOINT") ?? "https://pubsub.googleapis.com/";
            gcp = new GcpSubscriptionSettings
            {
                Subscription = subscription,
                Endpoint = new Uri(endpoint.EndsWith('/') ? endpoint : endpoint + "/", UriKind.Absolute),
                AllowServiceAccountKey = IsTrue(read("BOWER_GCP_ALLOW_KEY_FILE"))
            };
        }

        CloudAgentSettings settings = new()
        {
            AgentId = read("BOWER_AGENT_ID") ?? System.Environment.MachineName,
            CollectorUrl = new Uri(collector.EndsWith('/') ? collector : collector + "/", UriKind.Absolute),
            IngestToken = string.IsNullOrWhiteSpace(token) ? null : token,
            Environment = read("BOWER_ENVIRONMENT") ?? "production",
            Aws = aws,
            Gcp = gcp,
            BatchSize = ReadInt(read, "BOWER_BATCH_SIZE", 10),
            RetryDelay = TimeSpan.FromSeconds(ReadInt(read, "BOWER_RETRY_SECONDS", 60)),
            IncludeRawRecords = IsTrue(read("BOWER_INCLUDE_RAW_RECORDS")),
            RequireAustralianRegion = IsTrue(read("BOWER_REQUIRE_AU_REGION")),
            HeartbeatDirectory = read("BOWER_CLOUD_HEARTBEAT_DIR") ?? "/tmp/bower-cloud"
        };
        settings.Validate();
        return settings;
    }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(AgentId);
        if (AgentId.Length > 128)
        {
            throw new InvalidOperationException("BOWER_AGENT_ID cannot exceed 128 characters.");
        }

        if (CollectorUrl.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException("BOWER_COLLECTOR_URL must be an HTTP(S) URL.");
        }

        // The ingest token is a bearer secret. Cleartext HTTP is allowed only for loopback
        // or a single-label host (a Compose or Kubernetes service on a private network).
        if (IngestToken is not null
            && CollectorUrl.Scheme == Uri.UriSchemeHttp
            && !CollectorUrl.IsLoopback
            && CollectorUrl.Host.Contains('.', StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "BOWER_COLLECTOR_URL must use HTTPS when it is not loopback or a single-label service name.");
        }

        if (Aws is null && Gcp is null)
        {
            throw new InvalidOperationException("Set BOWER_AWS_SQS_QUEUE_URL, BOWER_GCP_SUBSCRIPTION, or both.");
        }

        if (BatchSize is < 1 or > 10)
        {
            throw new InvalidOperationException("BOWER_BATCH_SIZE must be between 1 and 10.");
        }

        if (RetryDelay < TimeSpan.FromSeconds(10) || RetryDelay > TimeSpan.FromMinutes(10))
        {
            throw new InvalidOperationException("BOWER_RETRY_SECONDS must be between 10 and 600.");
        }

        if (Aws is not null)
        {
            if (Aws.MaximumObjectBytes is < 1024 * 1024 or > 512L * 1024 * 1024)
            {
                throw new InvalidOperationException("BOWER_AWS_S3_MAX_OBJECT_MB must be between 1 and 512.");
            }

            if (RequireAustralianRegion && !AustralianAwsRegions.Contains(Aws.Region))
            {
                throw new InvalidOperationException(
                    $"BOWER_REQUIRE_AU_REGION is set but the SQS queue is in {Aws.Region}; use ap-southeast-2 or ap-southeast-4.");
            }
        }

        if (Gcp is not null)
        {
            if (!SubscriptionPattern().IsMatch(Gcp.Subscription))
            {
                throw new InvalidOperationException(
                    "BOWER_GCP_SUBSCRIPTION must be projects/{project}/subscriptions/{subscription}.");
            }

            if (Gcp.Endpoint.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException("BOWER_GCP_PUBSUB_ENDPOINT must use HTTPS.");
            }
        }
    }

    internal static AwsQueueSettings ParseQueue(string queueUrl, string? region, string? accountId)
    {
        if (!Uri.TryCreate(queueUrl, UriKind.Absolute, out Uri? url) || url.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("BOWER_AWS_SQS_QUEUE_URL must be an HTTPS SQS queue URL.");
        }

        // https://sqs.{region}.amazonaws.com/{account}/{queue}
        string[] segments = url.AbsolutePath.Trim('/').Split('/');
        string[] host = url.Host.Split('.');
        string? urlRegion = host.Length >= 3 && host[0] == "sqs" ? host[1] : null;
        string? urlAccount = segments.Length == 2 ? segments[0] : null;
        string resolvedRegion = region ?? urlRegion
            ?? throw new InvalidOperationException("Set BOWER_AWS_REGION; it cannot be read from the queue URL.");
        string resolvedAccount = accountId ?? urlAccount
            ?? throw new InvalidOperationException("Set BOWER_AWS_ACCOUNT_ID; it cannot be read from the queue URL.");
        if (resolvedAccount.Length != 12 || !resolvedAccount.All(char.IsAsciiDigit))
        {
            throw new InvalidOperationException("The AWS account id must be 12 digits.");
        }

        return new AwsQueueSettings { QueueUrl = url, Region = resolvedRegion, AccountId = resolvedAccount };
    }

    private static bool IsTrue(string? value) => string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

    private static int ReadInt(Func<string, string?> read, string name, int fallback)
    {
        string? value = read(name);
        return string.IsNullOrWhiteSpace(value)
            ? fallback
            : int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
                ? parsed
                : throw new InvalidOperationException($"{name} must be an integer.");
    }

    [GeneratedRegex("^projects/[a-z][a-z0-9.:-]{4,61}[a-z0-9]/subscriptions/[A-Za-z][A-Za-z0-9._~+%-]{2,254}$")]
    private static partial Regex SubscriptionPattern();
}

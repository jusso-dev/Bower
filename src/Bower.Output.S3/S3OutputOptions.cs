using System.Globalization;
using System.Text.RegularExpressions;

namespace Bower.Output.S3;

/// <summary>
/// S3 output settings (BOWER_S3_*). Credentials are deliberately absent: the client uses
/// the AWS default chain only (web identity/IRSA, ECS and EC2 roles, environment), so no
/// key is ever configured, stored or hashed by Bower.
/// </summary>
public sealed partial record S3OutputOptions
{
    public const string SseS3 = "AES256";
    public const string SseKms = "aws:kms";
    public const int DefaultMaximumObjectBytes = 8 * 1024 * 1024;
    public const int MinimumObjectBytes = 1024 * 1024;
    public const int MaximumObjectBytesLimit = 64 * 1024 * 1024;
    public const int DefaultMaximumObjectEvents = 1000;
    public const int MaximumObjectEventsLimit = 100_000;

    /// <summary>Static key settings Bower refuses: the default chain is the only credential source.</summary>
    public static IReadOnlyList<string> RefusedCredentialSettings { get; } =
    [
        "BOWER_S3_ACCESS_KEY_ID", "BOWER_S3_SECRET_ACCESS_KEY", "BOWER_S3_SESSION_TOKEN",
        "BOWER_AWS_ACCESS_KEY_ID", "BOWER_AWS_SECRET_ACCESS_KEY", "BOWER_AWS_SESSION_TOKEN"
    ];

    public string Id { get; init; } = "s3";

    public required string Bucket { get; init; }

    public required string Region { get; init; }

    /// <summary>
    /// The collector id (BOWER_COLLECTOR_ID), used as the key segment after the prefix so
    /// collectors sharing a bucket never write the same key. It must be S3 and IAM safe:
    /// 1 to 128 letters, digits, dots, hyphens and underscores, starting with a letter or
    /// digit. It is validated, never rewritten, so two collectors cannot map to one segment.
    /// </summary>
    public required string CollectorId { get; init; }

    /// <summary>Key prefix without leading or trailing slash (BOWER_S3_PREFIX, default <c>bower</c>).</summary>
    public string Prefix { get; init; } = "bower";

    /// <summary>
    /// BOWER_S3_SSE: <c>AES256</c> (SSE-S3) or <c>aws:kms</c>, sent explicitly on every PUT.
    /// Null (the default) sends no encryption header, so the bucket's default encryption
    /// applies (a bucket KMS key included); S3 always encrypts, at least with SSE-S3.
    /// </summary>
    public string? ServerSideEncryption { get; init; }

    /// <summary>
    /// KMS key id, alias or ARN for <c>aws:kms</c>. Null with <c>aws:kms</c> means the AWS
    /// managed <c>aws/s3</c> key, not the bucket's default key; leave BOWER_S3_SSE unset to
    /// use the bucket default.
    /// </summary>
    public string? KmsKeyId { get; init; }

    /// <summary>Twelve-digit account id sent as <c>ExpectedBucketOwner</c> (BOWER_S3_EXPECTED_BUCKET_OWNER).</summary>
    public string? ExpectedBucketOwner { get; init; }

    /// <summary>Uncompressed NDJSON bytes per object, newlines included (BOWER_S3_MAX_OBJECT_BYTES).</summary>
    public int MaximumObjectBytes { get; init; } = DefaultMaximumObjectBytes;

    /// <summary>Events per object (BOWER_S3_MAX_OBJECT_EVENTS).</summary>
    public int MaximumObjectEvents { get; init; } = DefaultMaximumObjectEvents;

    /// <summary>Gzip objects (<c>.jsonl.gz</c>); on by default (BOWER_S3_GZIP).</summary>
    public bool Gzip { get; init; } = true;

    /// <summary>
    /// Reads BOWER_S3_* settings; null when none is set. Static key settings are refused
    /// whether or not the S3 output is selected. Messages never echo values.
    /// </summary>
    public static S3OutputOptions? FromEnvironment(Func<string, string?> read, string collectorId)
    {
        ArgumentNullException.ThrowIfNull(read);
        foreach (string name in RefusedCredentialSettings)
        {
            if (!string.IsNullOrEmpty(read(name)))
            {
                throw new InvalidOperationException(
                    $"{name} is not supported: the S3 output uses the AWS default credential chain only " +
                    "(IRSA/web identity, ECS or EC2 role, environment). Remove the setting.");
            }
        }

        string? bucket = Blank(read("BOWER_S3_BUCKET"));
        string? region = Blank(read("BOWER_S3_REGION"));
        string? prefix = Blank(read("BOWER_S3_PREFIX"));
        string? sse = Blank(read("BOWER_S3_SSE"));
        string? kms = Blank(read("BOWER_S3_KMS_KEY_ID"));
        string? owner = Blank(read("BOWER_S3_EXPECTED_BUCKET_OWNER"));
        string? bytes = Blank(read("BOWER_S3_MAX_OBJECT_BYTES"));
        string? events = Blank(read("BOWER_S3_MAX_OBJECT_EVENTS"));
        string? gzip = Blank(read("BOWER_S3_GZIP"));
        if (bucket is null && region is null && prefix is null && sse is null && kms is null && owner is null
            && bytes is null && events is null && gzip is null)
        {
            return null;
        }

        return new S3OutputOptions
        {
            Bucket = bucket ?? string.Empty,
            Region = region ?? string.Empty,
            CollectorId = collectorId,
            Prefix = prefix ?? "bower",
            ServerSideEncryption = sse is null ? null
                : string.Equals(sse, SseS3, StringComparison.OrdinalIgnoreCase) ? SseS3
                : string.Equals(sse, SseKms, StringComparison.OrdinalIgnoreCase) ? SseKms
                : sse,
            KmsKeyId = kms,
            ExpectedBucketOwner = owner,
            MaximumObjectBytes = ReadInt(bytes, "BOWER_S3_MAX_OBJECT_BYTES", DefaultMaximumObjectBytes),
            MaximumObjectEvents = ReadInt(events, "BOWER_S3_MAX_OBJECT_EVENTS", DefaultMaximumObjectEvents),
            Gzip = gzip is null || ReadBoolean(gzip, "BOWER_S3_GZIP")
        };
    }

    public void Validate()
    {
        if (!IsValidBucketName(Bucket))
        {
            throw new InvalidOperationException(
                "BOWER_S3_BUCKET must be an S3 bucket name: 3 to 63 lowercase letters, digits and hyphens, " +
                "starting and ending with a letter or digit, without dots or reserved prefixes and suffixes.");
        }

        if (!RegionPattern().IsMatch(Region))
        {
            throw new InvalidOperationException("BOWER_S3_REGION must be an AWS region such as ap-southeast-2.");
        }

        if (!IsValidPrefix(Prefix))
        {
            throw new InvalidOperationException(
                "BOWER_S3_PREFIX must be 1 to 512 characters of letters, digits and !-_.'()= in segments " +
                "separated by single slashes, without a leading or trailing slash or . and .. segments. " +
                "IAM wildcard and variable characters (* ? $ { }) are refused.");
        }

        if (!IsValidCollectorId(CollectorId))
        {
            throw new InvalidOperationException(
                "BOWER_COLLECTOR_ID must be 1 to 128 letters, digits, dots, hyphens and underscores, starting " +
                "with a letter or digit, for BOWER_OUTPUT=s3: it is a segment of every object key.");
        }

        if (ServerSideEncryption is not (null or SseS3 or SseKms))
        {
            throw new InvalidOperationException("BOWER_S3_SSE must be AES256 or aws:kms.");
        }

        if (KmsKeyId is not null)
        {
            if (ServerSideEncryption != SseKms)
            {
                throw new InvalidOperationException("BOWER_S3_KMS_KEY_ID requires BOWER_S3_SSE=aws:kms.");
            }

            if (KmsKeyId.Length > 2048 || KmsKeyId.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
            {
                throw new InvalidOperationException(
                    "BOWER_S3_KMS_KEY_ID must be a KMS key id, alias or ARN without whitespace.");
            }
        }

        if (ExpectedBucketOwner is not null && !AccountPattern().IsMatch(ExpectedBucketOwner))
        {
            throw new InvalidOperationException("BOWER_S3_EXPECTED_BUCKET_OWNER must be a 12-digit AWS account id.");
        }

        if (MaximumObjectBytes is < MinimumObjectBytes or > MaximumObjectBytesLimit)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"BOWER_S3_MAX_OBJECT_BYTES must be between {MinimumObjectBytes} and {MaximumObjectBytesLimit}."));
        }

        if (MaximumObjectEvents is < 1 or > MaximumObjectEventsLimit)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"BOWER_S3_MAX_OBJECT_EVENTS must be between 1 and {MaximumObjectEventsLimit}."));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
    }

    /// <summary>
    /// S3 general purpose bucket naming rules, without dots: dotted names break TLS for
    /// virtual-hosted requests, and an output bucket should be created without them.
    /// </summary>
    public static bool IsValidBucketName(string? value)
    {
        if (value is null || value.Length is < 3 or > 63 || !BucketPattern().IsMatch(value))
        {
            return false;
        }

        return !(value.StartsWith("xn--", StringComparison.Ordinal)
            || value.StartsWith("sthree-", StringComparison.Ordinal)
            || value.StartsWith("amzn-s3-demo-", StringComparison.Ordinal)
            || value.EndsWith("-s3alias", StringComparison.Ordinal)
            || value.EndsWith("--ol-s3", StringComparison.Ordinal)
            || value.EndsWith("--x-s3", StringComparison.Ordinal)
            || value.EndsWith("--table-s3", StringComparison.Ordinal));
    }

    public static bool IsValidCollectorId(string? value) =>
        value is { Length: >= 1 and <= 128 } && CollectorIdPattern().IsMatch(value);

    public static bool IsValidPrefix(string? value)
    {
        if (value is null || value.Length is < 1 or > 512 || !PrefixPattern().IsMatch(value))
        {
            return false;
        }

        return value.Split('/').All(segment => segment.Length > 0 && segment is not ("." or ".."));
    }

    /// <summary>Non-secret settings for the collector configuration hash.</summary>
    public string HashMaterial() => string.Join(',',
        Bucket, Region, Prefix, ServerSideEncryption ?? string.Empty, KmsKeyId ?? string.Empty, ExpectedBucketOwner ?? string.Empty,
        MaximumObjectBytes.ToString(CultureInfo.InvariantCulture),
        MaximumObjectEvents.ToString(CultureInfo.InvariantCulture),
        Gzip ? "gzip" : "plain");

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static int ReadInt(string? value, string name, int fallback)
    {
        if (value is null)
        {
            return fallback;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : throw new InvalidOperationException($"{name} must be an integer.");
    }

    private static bool ReadBoolean(string value, string name) =>
        string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ? true
        : string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) ? false
        : throw new InvalidOperationException($"{name} must be true or false.");

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex BucketPattern();

    [GeneratedRegex("^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$", RegexOptions.CultureInvariant)]
    private static partial Regex RegionPattern();

    [GeneratedRegex("^[0-9]{12}$", RegexOptions.CultureInvariant)]
    private static partial Regex AccountPattern();

    // No * ? $ { }: the prefix becomes an IAM resource ARN, where they are wildcards or variables.
    [GeneratedRegex("^[A-Za-z0-9!_.'()=/-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex PrefixPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex CollectorIdPattern();
}

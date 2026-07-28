namespace Bower.Source.Aws;

public enum AwsTelemetrySourceKind
{
    CloudTrail,
    GuardDuty,
    SecurityHub,
    CloudWatchLogs,
    VpcFlowLogs,
    Route53Resolver
}

public sealed record AwsSourceOptions
{
    public required string SourceId { get; init; }

    public required AwsTelemetrySourceKind Kind { get; init; }

    public string? AccountId { get; init; }

    public string? Region { get; init; }

    public string Environment { get; init; } = "production";

    public string ApplicationName { get; init; } = "aws-security";

    public int MaximumRecordBytes { get; init; } = 65_536;

    public int MaximumBatchEvents { get; init; } = 1_000;

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(SourceId);

        if (SourceId.Length > 128)
        {
            throw new ArgumentException("Source identifier cannot exceed 128 characters.");
        }

        if (MaximumRecordBytes is < 1_024 or > 1_048_576)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumRecordBytes),
                "Maximum record size must be between 1 KiB and 1 MiB.");
        }

        if (MaximumBatchEvents is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumBatchEvents),
                "Batch size must be between 1 and 10,000.");
        }

        if (AccountId is not null &&
            (AccountId.Length != 12 || !AccountId.All(char.IsDigit)))
        {
            throw new ArgumentException("AWS account id must be 12 digits when provided.");
        }
    }
}

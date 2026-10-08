namespace Bower.Agent.Cloud;

/// <summary>Start-up notes on where cloud security telemetry is stored before it reaches Bower.</summary>
public static partial class CloudResidency
{
    public static void Report(CloudAgentSettings settings, ILogger logger)
    {
        if (settings.Aws is { } aws && !CloudAgentSettings.AustralianAwsRegions.Contains(aws.Region))
        {
            LogAwsRegion(logger, aws.Region);
        }

        if (settings.Gcp is not null)
        {
            // The subscriber cannot read the topic's storage policy without extra permissions.
            LogGcpStorage(logger);
        }
    }

    [LoggerMessage(EventId = 4201, Level = LogLevel.Warning,
        Message = "SQS queue is in {Region}, outside Australia. Set BOWER_REQUIRE_AU_REGION=true to refuse this.")]
    private static partial void LogAwsRegion(ILogger logger, string region);

    [LoggerMessage(EventId = 4202, Level = LogLevel.Information,
        Message = "Pub/Sub data residency follows the topic's message storage policy; the Bower Terraform pins it to australia-southeast1/2.")]
    private static partial void LogGcpStorage(ILogger logger);
}

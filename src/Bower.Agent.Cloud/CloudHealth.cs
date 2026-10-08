using System.Globalization;

namespace Bower.Agent.Cloud;

/// <summary>Container health check: every configured source must have completed a pass recently.</summary>
public static class CloudHealth
{
    // Long-poll (20 s) plus the maximum back-off (5 min), with margin.
    private static readonly TimeSpan Allowed = TimeSpan.FromMinutes(12);

    public static int Check(CloudAgentSettings settings, TimeProvider? clock = null)
    {
        clock ??= TimeProvider.System;
        List<string> sources = [];
        if (settings.Aws is not null)
        {
            sources.Add("aws-sqs");
        }

        if (settings.Gcp is not null)
        {
            sources.Add("gcp-pubsub");
        }

        foreach (string source in sources)
        {
            try
            {
                string value = File.ReadAllText(settings.HeartbeatPath(source)).Trim();
                DateTimeOffset last = DateTimeOffset.Parse(value, CultureInfo.InvariantCulture);
                if (clock.GetUtcNow() - last > Allowed)
                {
                    return 1;
                }
            }
            catch (Exception exception) when (exception is IOException or FormatException or UnauthorizedAccessException)
            {
                return 1;
            }
        }

        return 0;
    }
}

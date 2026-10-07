using System.Globalization;

namespace Bower.Agent.Docker;

/// <summary>Container health check: the worker must have completed a pass recently.</summary>
public static class SidecarHealth
{
    public static int Check(SidecarSettings settings, TimeProvider? clock = null)
    {
        clock ??= TimeProvider.System;
        try
        {
            string value = File.ReadAllText(settings.HeartbeatPath).Trim();
            DateTimeOffset last = DateTimeOffset.Parse(value, CultureInfo.InvariantCulture);
            TimeSpan allowed = TimeSpan.FromTicks(Math.Max(settings.PollInterval.Ticks * 6, TimeSpan.FromMinutes(3).Ticks));
            return clock.GetUtcNow() - last <= allowed ? 0 : 1;
        }
        catch (Exception exception) when (exception is IOException or FormatException or UnauthorizedAccessException)
        {
            return 1;
        }
    }
}

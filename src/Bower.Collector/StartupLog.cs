namespace Bower.Collector;

/// <summary>Metadata-only startup lines: settings sources, never setting values.</summary>
internal static partial class StartupLog
{
    [LoggerMessage(EventId = 1290, Level = LogLevel.Information,
        Message = "Settings file {Path}: {State}, {Count} setting(s) applied.")]
    public static partial void SettingsFile(ILogger logger, SettingsFileState state, string path, int count);

    [LoggerMessage(EventId = 1291, Level = LogLevel.Information,
        Message = "Collector id {CollectorId} ({Source}).")]
    public static partial void CollectorId(ILogger logger, string collectorId, CollectorIdSource source);
}

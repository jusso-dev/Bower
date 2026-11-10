using Bower.Collector;

namespace Bower.UnitTests;

/// <summary>
/// 32-bit collector settings are parsed as 32-bit values. A 64-bit parse followed by a cast
/// dropped the high bits without an error, so a pasted value could wrap into range (#243).
/// </summary>
public sealed class CollectorSettingsIntegerTests
{
    [Theory]
    [InlineData("BOWER_INGEST_RATE_PER_SECOND")]
    [InlineData("BOWER_MAX_DELIVERY_ATTEMPTS")]
    [InlineData("BOWER_TAP_MAX_SESSIONS")]
    [InlineData("BOWER_TAP_MAX_EVENTS_PER_SECOND")]
    [InlineData("BOWER_TAP_MAX_DURATION_SECONDS")]
    [InlineData("BOWER_TAP_MAX_EVENTS")]
    [InlineData("BOWER_TAP_MAX_EVENT_BYTES")]
    [InlineData("BOWER_STORAGE_WARNING_FREE_PERCENT")]
    [InlineData("BOWER_STORAGE_CRITICAL_FREE_PERCENT")]
    [InlineData("BOWER_AMA_SYSLOG_MAX_BYTES")]
    public void Settings_RefuseA32BitValueThatWouldWrapIntoRange(string name)
    {
        // #243: 2^32 + 20 used to be narrowed to 20 and accepted.
        Dictionary<string, string> values = new(StringComparer.Ordinal) { ["BOWER_COLLECTOR_ID"] = "edge-01", [name] = "4294967316" };
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(key => values.GetValueOrDefault(key)));

        Assert.Contains($"{name} must be an integer", error.Message, StringComparison.Ordinal);
    }
}

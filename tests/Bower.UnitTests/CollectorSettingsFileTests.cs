using Bower.Collector;

namespace Bower.UnitTests;

public sealed class CollectorSettingsFileTests
{
    [Fact]
    public void Apply_OverridesServiceEnvironmentWithFileSettings()
    {
        using TemporaryDirectory directory = new();
        string path = Write(directory, """
            # Operator settings kept across MSI upgrades
            BOWER_OUTPUT=ama-spool
              BOWER_WINDOWS_EVENTLOG_CONFIG = "C:\ProgramData\Bower\windows eventlog.json"
            AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000

            BOWER_DELIVERY_LEASE_SECONDS=90
            BOWER_DELIVERY_TIMEOUT_SECONDS=60
            """);
        Dictionary<string, string> environment = new(StringComparer.Ordinal)
        {
            [CollectorSettingsFile.Variable] = path,
            ["BOWER_OUTPUT"] = "none",
            ["BOWER_QUEUE_PATH"] = "/state/queue.db"
        };

        IReadOnlyDictionary<string, string> applied = CollectorSettingsFile.Apply(
            name => environment.GetValueOrDefault(name), (name, value) => environment[name] = value);
        CollectorSettings settings = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));

        Assert.Equal(5, applied.Count);
        Assert.Equal("ama-spool", environment["BOWER_OUTPUT"]);
        Assert.Equal(@"C:\ProgramData\Bower\windows eventlog.json", environment["BOWER_WINDOWS_EVENTLOG_CONFIG"]);
        Assert.Equal("/state/queue.db", settings.QueuePath);
        Assert.Equal(TimeSpan.FromSeconds(90), settings.DeliveryLeaseDuration);
    }

    [Fact]
    public void Apply_MissingOrUnsetFileIsNotAnError()
    {
        using TemporaryDirectory directory = new();
        string missing = Path.Combine(directory.Path, "bower.env");

        Assert.Empty(CollectorSettingsFile.Apply(_ => null, (_, _) => throw new InvalidOperationException()));
        Assert.Empty(CollectorSettingsFile.Apply(
            name => name == CollectorSettingsFile.Variable ? missing : null, (_, _) => throw new InvalidOperationException()));
    }

    [Theory]
    [InlineData("PATH=/tmp", "line 1")]
    [InlineData("BOWER_OUTPUT", "line 1")]
    [InlineData("bower_output=none", "line 1")]
    [InlineData("BOWER_SETTINGS_FILE=/other", "line 1")]
    [InlineData("BOWER_OUTPUT=none\nBOWER_OUTPUT=azure-logs-ingestion", "repeats BOWER_OUTPUT")]
    public void Parse_RejectsUnsafeOrAmbiguousLinesWithoutEchoingValues(string content, string expected)
    {
        using TemporaryDirectory directory = new();
        string path = Write(directory, content + "\nBOWER_INGEST_TOKEN=secret-value-never-echoed");

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Parse(path));

        Assert.Contains(expected, failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-value", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("/tmp", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsOversizedAndWritableFiles()
    {
        using TemporaryDirectory directory = new();
        string large = Write(directory, "BOWER_OUTPUT=" + new string('x', (int)CollectorSettingsFile.MaximumBytes));
        Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Parse(large));
        if (!OperatingSystem.IsWindows())
        {
            string writable = Write(directory, "BOWER_OUTPUT=none", "writable.env");
            File.SetUnixFileMode(writable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Parse(writable));
        }
    }

    private static string Write(TemporaryDirectory directory, string content, string name = "bower.env")
    {
        string path = Path.Combine(directory.Path, name);
        File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        return path;
    }
}

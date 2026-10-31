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
            ; semicolon comments too
            BOWER_OUTPUT=ama-spool
              BOWER_WINDOWS_EVENTLOG_CONFIG = "C:\ProgramData\Bower\windows eventlog.json"
            BOWER_AMA_SPOOL_PATH='/var/spool/bower "lab"'
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

        SettingsFileResult result = CollectorSettingsFile.Apply(
            name => environment.GetValueOrDefault(name), (name, value) => environment[name] = value);
        CollectorSettings settings = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));

        Assert.Equal(new SettingsFileResult(SettingsFileState.Applied, path, 6), result);
        Assert.Equal("ama-spool", environment["BOWER_OUTPUT"]);
        // Matching single or double quotes are removed; no escapes, so Windows paths stay intact.
        Assert.Equal(@"C:\ProgramData\Bower\windows eventlog.json", environment["BOWER_WINDOWS_EVENTLOG_CONFIG"]);
        Assert.Equal("/var/spool/bower \"lab\"", environment["BOWER_AMA_SPOOL_PATH"]);
        Assert.Equal("/state/queue.db", settings.QueuePath);
        Assert.Equal(TimeSpan.FromSeconds(90), settings.DeliveryLeaseDuration);
    }

    [Fact]
    public void Apply_ReportsUnsetAndMissingFilesWithoutApplyingAnything()
    {
        using TemporaryDirectory directory = new();
        string missing = Path.Combine(directory.Path, "bower.env");

        Assert.Equal(SettingsFileState.NotConfigured,
            CollectorSettingsFile.Apply(_ => null, (_, _) => throw new InvalidOperationException()).State);
        SettingsFileResult result = CollectorSettingsFile.Apply(
            name => name == CollectorSettingsFile.Variable ? missing : null, (_, _) => throw new InvalidOperationException());
        Assert.Equal(new SettingsFileResult(SettingsFileState.NotPresent, missing, 0), result);
        Assert.Null(CollectorSettingsFile.Load(Path.Combine(directory.Path, "no-such-folder", "bower.env")));
    }

    [Fact]
    public void Load_FailsWhenAnEditorAddedTxt()
    {
        using TemporaryDirectory directory = new();
        Write(directory, "BOWER_OUTPUT=none", "bower.env.txt");

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(
            () => CollectorSettingsFile.Load(Path.Combine(directory.Path, "bower.env")));

        Assert.Contains("bower.env.txt", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_FailsWhenTheFileExistsButCannotBeRead()
    {
        if (OperatingSystem.IsWindows() || IsRoot())
        {
            return; // Root reads anything; Windows ACL denial is covered by the installer test.
        }
        using TemporaryDirectory directory = new();
        string unreadable = Write(directory, "BOWER_OUTPUT=none");
        File.SetUnixFileMode(unreadable, UnixFileMode.None);
        Assert.Contains("cannot be read", Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(unreadable)).Message,
            StringComparison.Ordinal);

        string folder = Path.Combine(directory.Path, "no-traverse");
        Directory.CreateDirectory(folder);
        string inside = Path.Combine(folder, "bower.env");
        File.WriteAllText(inside, "BOWER_OUTPUT=none");
        File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        try
        {
            Assert.Contains("cannot be read", Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(inside)).Message,
                StringComparison.Ordinal);
        }
        finally
        {
            File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Theory]
    [InlineData("PATH=/tmp", "line 1")]
    [InlineData("BOWER_OUTPUT", "line 1")]
    [InlineData("bower_output=none", "line 1")]
    [InlineData("BOWER_SETTINGS_FILE=/other", "line 1")]
    [InlineData("BOWER_OUTPUT=\"none", "unterminated quote")]
    [InlineData("BOWER_OUTPUT='none\"", "unterminated quote")]
    [InlineData("BOWER_OUTPUT='", "unterminated quote")]
    [InlineData("BOWER_OUTPUT=none\nBOWER_OUTPUT=azure-logs-ingestion", "repeats BOWER_OUTPUT")]
    public void Parse_RejectsUnsafeOrAmbiguousLinesWithoutEchoingValues(string content, string expected)
    {
        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(
            () => CollectorSettingsFile.Parse(content + "\nBOWER_INGEST_TOKEN=secret-value-never-echoed"));

        Assert.Contains(expected, failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-value", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("/tmp", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_RejectsOversizedFiles()
    {
        using TemporaryDirectory directory = new();
        string large = Write(directory, "BOWER_OUTPUT=" + new string('x', (int)CollectorSettingsFile.MaximumBytes));
        Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(large));
    }

    [Fact]
    public void Load_RejectsFilesOrFoldersOthersCanChangeAndSymbolicLinks()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // Windows ACL rules are exercised by the MSI install test.
        }
        using TemporaryDirectory directory = new();
        string writable = Write(directory, "BOWER_OUTPUT=none", "writable.env");
        File.SetUnixFileMode(writable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
        Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(writable));

        string trusted = Write(directory, "BOWER_OUTPUT=none", "trusted.env");
        Assert.NotNull(CollectorSettingsFile.Load(trusted));
        File.SetUnixFileMode(directory.Path, File.GetUnixFileMode(directory.Path) | UnixFileMode.GroupWrite);
        try
        {
            Assert.Contains("group- or world-writable", Assert.Throws<InvalidOperationException>(
                () => CollectorSettingsFile.Load(trusted)).Message, StringComparison.Ordinal);
        }
        finally
        {
            File.SetUnixFileMode(directory.Path, File.GetUnixFileMode(directory.Path) & ~UnixFileMode.GroupWrite);
        }

        string link = Path.Combine(directory.Path, "link.env");
        File.CreateSymbolicLink(link, trusted);
        Assert.Contains("symbolic link", Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(link)).Message,
            StringComparison.Ordinal);
    }

    private static bool IsRoot() => Environment.UserName == "root";

    private static string Write(TemporaryDirectory directory, string content, string name = "bower.env")
    {
        string path = Path.Combine(directory.Path, name);
        File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.SetUnixFileMode(directory.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        return path;
    }
}

public sealed class CollectorIdentityFileTests
{
    [Fact]
    public void FirstStartPersistsTheMachineNameAndLaterStartsReuseIt()
    {
        using TemporaryDirectory directory = new();
        string queue = Path.Combine(directory.Path, "state", "queue.db");

        Assert.Equal(("pod-abc", CollectorIdSource.Created), CollectorIdentityFile.Resolve(null, queue, () => "pod-abc"));
        // A recreated container or pod has a new hostname but keeps the persisted id.
        Assert.Equal(("pod-abc", CollectorIdSource.Persisted), CollectorIdentityFile.Resolve("  ", queue, () => "pod-xyz"));
        // An explicit id wins and never rewrites the file.
        Assert.Equal(("explicit", CollectorIdSource.Configured), CollectorIdentityFile.Resolve("explicit", queue, () => "pod-xyz"));
        Assert.Equal("pod-abc\n", File.ReadAllText(Path.Combine(directory.Path, "state", CollectorIdentityFile.FileName)));
    }

    [Fact]
    public void ApplyExportsThePersistedIdForSettings()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, string> environment = new(StringComparer.Ordinal)
        {
            ["BOWER_QUEUE_PATH"] = Path.Combine(directory.Path, "queue.db")
        };
        File.WriteAllText(Path.Combine(directory.Path, CollectorIdentityFile.FileName), "edge-syd-01\n");

        CollectorIdSource source = CollectorIdentityFile.Apply(name => environment.GetValueOrDefault(name), (name, value) => environment[name] = value);

        Assert.Equal(CollectorIdSource.Persisted, source);
        Assert.Equal("edge-syd-01", environment["BOWER_COLLECTOR_ID"]);
    }

    [Fact]
    public void InvalidPersistedOrMachineIdsFailClosed()
    {
        using TemporaryDirectory directory = new();
        string queue = Path.Combine(directory.Path, "queue.db");
        Assert.Throws<InvalidOperationException>(() => CollectorIdentityFile.Resolve(null, queue, () => "has space"));
        Assert.False(File.Exists(Path.Combine(directory.Path, CollectorIdentityFile.FileName)));
        File.WriteAllText(Path.Combine(directory.Path, CollectorIdentityFile.FileName), "bad\u0001id");
        Assert.Throws<InvalidOperationException>(() => CollectorIdentityFile.Resolve(null, queue, () => "ok"));
    }
}

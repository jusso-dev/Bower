using System.Reflection;
using System.Text.RegularExpressions;
using Bower.Collector;
using Bower.Contracts;

namespace Bower.UnitTests;

/// <summary>The release version from VERSION reaches every assembly and the collector.</summary>
public sealed partial class BowerVersionTests
{
    [Fact]
    public void Current_IsTheVersionFileCoreOrAPrereleaseOfIt()
    {
        string core = File.ReadAllText(Path.Combine(RepositoryRoot(), "VERSION")).Trim();

        Assert.Matches(Scheme(), BowerVersion.Current);
        Assert.Equal(core, BowerVersion.Current.Split('-')[0]);
    }

    [Fact]
    public void Current_IsTheVersionTheBuildWasStampedWith()
    {
        // CI builds with -p:BowerVersion=<tools/ci/version.py output> and sets this variable;
        // a local build is <VERSION>-dev.0.
        string? expected = Environment.GetEnvironmentVariable("BOWER_EXPECTED_VERSION");
        string core = File.ReadAllText(Path.Combine(RepositoryRoot(), "VERSION")).Trim();

        Assert.Equal(string.IsNullOrEmpty(expected) ? core + "-dev.0" : expected, BowerVersion.Current);
    }

    [Fact]
    public void EveryBowerAssemblyCarriesTheSameVersion()
    {
        Assembly[] assemblies =
        [
            typeof(BowerVersion).Assembly,
            typeof(CollectorSettings).Assembly,
            typeof(Bower.Core.CollectorIdentity).Assembly,
            typeof(Bower.Persistence.SqliteEventStore).Assembly
        ];
        string core = BowerVersion.Current.Split('-')[0];
        foreach (Assembly assembly in assemblies)
        {
            Assert.Equal(
                BowerVersion.Current,
                assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion);
            // Pinned: YAML error text (and the Rust parity vectors) carry the assembly identity.
            Assert.Equal(new Version(1, 0, 0, 0), assembly.GetName().Version);
            Assert.StartsWith(core + ".", assembly.GetCustomAttribute<AssemblyFileVersionAttribute>()!.Version, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void CollectorSettings_ReportTheBuildVersionAndNoEnvironmentOverridesIt()
    {
        Dictionary<string, string> environment = new()
        {
            ["BOWER_VERSION"] = "9.9.9",
            ["BOWER_COLLECTOR_ID"] = "collector-1"
        };

        CollectorSettings settings = CollectorSettings.FromEnvironment(name => environment.GetValueOrDefault(name));

        Assert.Equal(BowerVersion.Current, settings.Version);
        Assert.Equal(BowerVersion.Current, new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = "queue.db",
            PolicyDirectory = "policies",
            CollectorId = "collector-1"
        }.Version);
    }

    [Fact]
    public void VersionFile_MatchesTheRustWorkspaceVersion()
    {
        string root = RepositoryRoot();
        string core = File.ReadAllText(Path.Combine(root, "VERSION")).Trim();
        string cargo = File.ReadAllText(Path.Combine(root, "rust", "Cargo.toml"));

        Assert.Matches(Scheme(), core);
        Assert.Contains($"[workspace.package]\nversion = \"{core}\"", cargo.ReplaceLineEndings("\n"), StringComparison.Ordinal);
    }

    private static string RepositoryRoot()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "VERSION")) && File.Exists(Path.Combine(directory.FullName, "Bower.sln")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("Repository root not found.");
    }

    /// <summary>docs/operations/release-versioning.md: MAJOR.MINOR.PATCH[-dev.N|-rc.N].</summary>
    [GeneratedRegex(@"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-(dev|rc)\.(0|[1-9]\d*))?$")]
    private static partial Regex Scheme();
}

using System.Reflection;

namespace Bower.Contracts;

/// <summary>
/// The Bower release version of this build: <c>MAJOR.MINOR.PATCH</c> from the repository
/// <c>VERSION</c> file, with <c>-dev.N</c> or <c>-rc.N</c> for a pre-release build
/// (docs/operations/release-versioning.md). Directory.Build.props stamps it into every
/// assembly as the informational version and validates its form; collector status,
/// heartbeats, enrolment, every event's <c>collector.version</c> and the CLI report it.
/// </summary>
public static class BowerVersion
{
    public static string Current { get; } = Read(typeof(BowerVersion).Assembly);

    /// <summary>The informational version without build metadata (anything after <c>+</c>).</summary>
    private static string Read(Assembly assembly)
    {
        string? informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(informational) ? "0.0.0-dev.0" : informational.Split('+')[0];
    }
}

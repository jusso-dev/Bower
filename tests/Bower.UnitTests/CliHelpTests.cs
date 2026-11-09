using System.Diagnostics;
using Bower.Cli.Commands;

namespace Bower.UnitTests;

/// <summary>
/// docs/reference/cli.md is generated from <see cref="CliHelp.Text"/> (what `bower --help`
/// prints). This fails when the help changes without regenerating the page.
/// </summary>
public sealed class CliHelpTests
{
    [Fact]
    public void CliReference_EmbedsTheExactHelpText()
    {
        string page = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "reference", "cli.md")).ReplaceLineEndings("\n");

        Assert.Contains("```text\n" + CliHelp.Text.ReplaceLineEndings("\n") + "\n```", page, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryCommandInTheHelpHasAGuideRow()
    {
        string page = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "reference", "cli.md"));
        IEnumerable<string> commands = CliHelp.Text.Split('\n')
            .Select(line => line.TrimStart())
            .Where(line => line.StartsWith("bower ", StringComparison.Ordinal))
            .Select(line => line.Split(' ', 3)[1])
            .Distinct(StringComparer.Ordinal);

        Assert.All(commands, command => Assert.Contains($"| `bower {command}` |", page, StringComparison.Ordinal));
    }

    [Fact]
    public void Help_StartsAndEndsWithTheStableLines()
    {
        Assert.StartsWith("Bower security telemetry\n\nCommands:\n  bower validate", CliHelp.Text.ReplaceLineEndings("\n"), StringComparison.Ordinal);
        Assert.EndsWith("  bower version | bower --version", CliHelp.Text.ReplaceLineEndings("\n"), StringComparison.Ordinal);
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

        throw new UnreachableException("Repository root not found.");
    }
}

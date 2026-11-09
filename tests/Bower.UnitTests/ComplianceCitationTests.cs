using System.Text.Json;
using System.Text.RegularExpressions;

namespace Bower.UnitTests;

/// <summary>
/// Every OWASP ASVS and ASD ISM identifier Bower content cites must be in the verified
/// lists under docs/security/verified/, which tools/compliance/verify_sources.py builds
/// from the official sources (ASVS v5.0.0_release, ISM September 2026 OSCAL).
/// </summary>
public sealed partial class ComplianceCitationTests
{
    private static readonly string[] ScannedRoots =
        ["docs", "packs", "policies", "rules", "deploy", "examples", "schemas", "src", "tools", "powershell", "ui", "rust/crates", "README.md", "PRODUCT.md", "SECURITY.md"];

    private static readonly string[] ScannedExtensions =
        [".md", ".yaml", ".yml", ".json", ".jsonl", ".kql", ".bicep", ".cs", ".rs", ".py", ".ts", ".tsx", ".js", ".go", ".java", ".rb", ".php", ".ps1", ".psm1", ".toml"];

    private static readonly HashSet<string> SkippedDirectories =
        new(["bin", "obj", "node_modules", "target", ".venv", "site", "dist", "vendor", ".next"], StringComparer.Ordinal);

    [Fact]
    public void VerifiedLists_RecordTheirOfficialSources()
    {
        using JsonDocument asvs = JsonDocument.Parse(File.ReadAllText(VerifiedPath("asvs-5.0.0-logging.json")));
        JsonElement asvsSource = asvs.RootElement.GetProperty("source");
        Assert.Equal("5.0.0", asvs.RootElement.GetProperty("version").GetString());
        Assert.Equal("v5.0.0_release", asvsSource.GetProperty("tag").GetString());
        Assert.Equal("5cf9b032440be53ce345ab3c130fda46ba1ce7a2", asvsSource.GetProperty("commit").GetString());
        Assert.StartsWith("https://github.com/OWASP/ASVS/releases/download/v5.0.0_release/", asvsSource.GetProperty("asset").GetString(), StringComparison.Ordinal);
        Assert.Matches("^[0-9a-f]{64}$", asvsSource.GetProperty("assetSha256").GetString());

        using JsonDocument ism = JsonDocument.Parse(File.ReadAllText(VerifiedPath("ism-2026-09-logging.json")));
        JsonElement ismSource = ism.RootElement.GetProperty("source");
        Assert.Equal("September 2026", ism.RootElement.GetProperty("release").GetString());
        Assert.StartsWith("https://www.cyber.gov.au/ism/oscal/", ismSource.GetProperty("catalogue").GetString(), StringComparison.Ordinal);
        Assert.Matches("^[0-9a-f]{64}$", ismSource.GetProperty("catalogueSha256").GetString());

        foreach (JsonElement item in asvs.RootElement.GetProperty("requirements").EnumerateArray())
        {
            Assert.Matches(AsvsId(), item.GetProperty("id").GetString());
            Assert.InRange(item.GetProperty("level").GetInt32(), 1, 3);
            Assert.StartsWith("Verify that", item.GetProperty("text").GetString(), StringComparison.Ordinal);
        }

        foreach (JsonElement item in ism.RootElement.GetProperty("controls").EnumerateArray())
        {
            Assert.Matches("^ISM-[0-9]{4}$", item.GetProperty("id").GetString());
            Assert.False(string.IsNullOrWhiteSpace(item.GetProperty("text").GetString()));
        }
    }

    [Fact]
    public void VerifiedAsvsList_CoversAllOfV16()
    {
        HashSet<string> asvs = VerifiedIds("asvs-5.0.0-logging.json", "requirements");
        string[] v16 =
        [
            "V16.1.1", "V16.2.1", "V16.2.2", "V16.2.3", "V16.2.4", "V16.2.5", "V16.3.1", "V16.3.2", "V16.3.3",
            "V16.3.4", "V16.4.1", "V16.4.2", "V16.4.3", "V16.5.1", "V16.5.2", "V16.5.3", "V16.5.4"
        ];
        Assert.All(v16, id => Assert.Contains(id, asvs));
        Assert.Equal(17, asvs.Count(id => id.StartsWith("V16.", StringComparison.Ordinal)));
    }

    [Fact]
    public void EveryCitedAsvsAndIsmIdentifier_IsVerified()
    {
        string root = RepositoryRoot();
        HashSet<string> asvs = VerifiedIds("asvs-5.0.0-logging.json", "requirements");
        HashSet<string> ism = VerifiedIds("ism-2026-09-logging.json", "controls");
        List<string> unverified = [];
        int citations = 0;

        foreach (string file in ScannedFiles(root))
        {
            string text = File.ReadAllText(file);
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            foreach (Match match in AsvsCitation().Matches(text))
            {
                citations++;
                if (!asvs.Contains(match.Value))
                {
                    unverified.Add($"{relative}: {match.Value}");
                }
            }

            foreach (Match match in IsmCitation().Matches(text))
            {
                // "ISM-1986, 1906" shorthand: every number in the run is a citation.
                foreach (Match number in Regex.Matches(match.Value, "[0-9]{4}"))
                {
                    citations++;
                    if (!ism.Contains($"ISM-{number.Value}"))
                    {
                        unverified.Add($"{relative}: ISM-{number.Value}");
                    }
                }
            }
        }

        Assert.True(citations > 0, "No citations found: the scan roots are wrong.");
        Assert.True(unverified.Count == 0, "Unverified ASVS or ISM identifiers:\n" + string.Join('\n', unverified));
    }

    [Theory]
    [InlineData("See V16.3.1 and V99.1.1.", "V99.1.1")]
    [InlineData("ISM-1405, ISM-0001", "ISM-0001")]
    [InlineData("ISM-1986, 1906, 0002", "ISM-0002")]
    public void CitationScan_FindsUnverifiedIdentifiers(string text, string expected)
    {
        HashSet<string> asvs = VerifiedIds("asvs-5.0.0-logging.json", "requirements");
        HashSet<string> ism = VerifiedIds("ism-2026-09-logging.json", "controls");
        List<string> found = [.. AsvsCitation().Matches(text).Select(match => match.Value).Where(id => !asvs.Contains(id))];
        found.AddRange(IsmCitation().Matches(text)
            .SelectMany(match => Regex.Matches(match.Value, "[0-9]{4}"))
            .Select(number => $"ISM-{number.Value}")
            .Where(id => !ism.Contains(id)));

        Assert.Equal([expected], found);
    }

    private static IEnumerable<string> ScannedFiles(string root)
    {
        string verified = Path.GetFullPath(Path.Combine(root, "docs", "security", "verified"));
        foreach (string entry in ScannedRoots)
        {
            string path = Path.Combine(root, entry);
            if (File.Exists(path))
            {
                yield return path;
                continue;
            }

            if (!Directory.Exists(path))
            {
                continue;
            }

            Stack<string> pending = new([path]);
            while (pending.Count > 0)
            {
                string directory = pending.Pop();
                if (Path.GetFullPath(directory).StartsWith(verified, StringComparison.Ordinal))
                {
                    continue;
                }

                foreach (string child in Directory.EnumerateDirectories(directory))
                {
                    if (!SkippedDirectories.Contains(Path.GetFileName(child)))
                    {
                        pending.Push(child);
                    }
                }

                foreach (string file in Directory.EnumerateFiles(directory))
                {
                    if (ScannedExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)
                        && !file.EndsWith("packages.lock.json", StringComparison.Ordinal)
                        && !file.EndsWith("package-lock.json", StringComparison.Ordinal))
                    {
                        yield return file;
                    }
                }
            }
        }
    }

    private static HashSet<string> VerifiedIds(string file, string array)
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(VerifiedPath(file)));
        return document.RootElement.GetProperty(array).EnumerateArray()
            .Select(item => item.GetProperty("id").GetString()!)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static string VerifiedPath(string file) => Path.Combine(RepositoryRoot(), "docs", "security", "verified", file);

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

    [GeneratedRegex(@"^V[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$")]
    private static partial Regex AsvsId();

    // ASVS 5.0 style chapter.section.requirement with the V prefix, as the standard writes it.
    [GeneratedRegex(@"(?<![A-Za-z0-9.])V[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}(?![0-9.]*[0-9])")]
    private static partial Regex AsvsCitation();

    [GeneratedRegex(@"\bISM-[0-9]{4}(?:,\s*(?:ISM-)?[0-9]{4}\b)*")]
    private static partial Regex IsmCitation();
}

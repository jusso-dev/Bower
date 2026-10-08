using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Dcr;
using Bower.Evidence;

namespace Bower.Cli.Commands;

internal static class DcrCommands
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>bower dcr generate [--out FILE] [--rule-name NAME] [--retention-days N] [--total-retention-days N] [--plan Analytics|Basic]</summary>
    public static int Generate(string[] args)
    {
        JsonObject template = DcrTemplateGenerator.Generate(new DcrTemplateOptions
        {
            RuleName = CliOptions.Get(args, "--rule-name") ?? "bower-dcr",
            Plan = CliOptions.Get(args, "--plan") ?? "Analytics",
            RetentionInDays = CliOptions.Int(args, "--retention-days", 90),
            TotalRetentionInDays = CliOptions.Int(args, "--total-retention-days", 365)
        });
        string json = template.ToJsonString(Indented);
        if (CliOptions.Get(args, "--out") is { } path)
        {
            File.WriteAllText(path, json);
            Console.WriteLine($"Wrote {path}. Deploy with: az deployment group create -g <rg> -f {path} -p workspaceName=<workspace>");
        }
        else
        {
            Console.WriteLine(json);
        }

        return 0;
    }

    /// <summary>
    /// bower dcr diff (--rule FILE | --dcr-resource-id ID) [--table FILE | --workspace-resource-id ID] [--credential MODE]
    /// Exit code 1 when any error-level drift is found.
    /// </summary>
    public static async Task<int> DiffAsync(string[] args)
    {
        SentinelSchema schema = SentinelSchema.Default;
        List<DcrFinding> findings = [.. DcrDrift.LintSchema(schema)];
        ArmReader? arm = null;
        if (CliOptions.Has(args, "--dcr-resource-id") || CliOptions.Has(args, "--workspace-resource-id"))
        {
            arm = new ArmReader(new HttpClient(), VerifierCredential.Create(CliOptions.Get(args, "--credential")));
        }

        string? ruleJson = CliOptions.Get(args, "--rule") is { } ruleFile
            ? File.ReadAllText(ruleFile)
            : CliOptions.Get(args, "--dcr-resource-id") is { } ruleId
                ? (await arm!.GetAsync(ruleId, DcrTemplateGenerator.ApiVersion, CancellationToken.None))?.ToJsonString()
                    ?? throw new InvalidOperationException("DCR not found or not readable with this credential.")
                : null;
        if (ruleJson is null)
        {
            throw new ArgumentException("Provide --rule FILE or --dcr-resource-id ID.");
        }

        findings.AddRange(DcrDrift.CompareRule(ruleJson, schema));

        string? tableJson = CliOptions.Get(args, "--table") is { } tableFile
            ? File.ReadAllText(tableFile)
            : CliOptions.Get(args, "--workspace-resource-id") is { } workspaceId
                ? (await arm!.GetAsync($"{workspaceId}/tables/{schema.TableName}", DcrTemplateGenerator.ApiVersion, CancellationToken.None))?.ToJsonString()
                : null;
        if (tableJson is not null)
        {
            findings.AddRange(DcrDrift.CompareTable(tableJson, schema));
        }

        foreach (DcrFinding finding in findings)
        {
            Console.WriteLine($"{finding.Level.ToString().ToUpperInvariant(),-7} {finding.Code,-26} {finding.Detail}");
        }

        if (findings.Count == 0)
        {
            Console.WriteLine("OK      no drift          Deployed DCR matches Bower's schema.");
        }

        return findings.Any(finding => finding.Level == FindingLevel.Error) ? 1 : 0;
    }
}

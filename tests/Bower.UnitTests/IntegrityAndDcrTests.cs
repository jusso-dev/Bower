using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Dcr;
using Bower.Integrity;

namespace Bower.UnitTests;

public sealed partial class IntegrityAndDcrTests
{
    [Fact]
    public void Signer_VerifiesWithTrustedKeyAndRejectsTamperingAndOtherKeys()
    {
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        (_, string otherPublic, _) = DetachedSigner.GenerateKeyPair();
        byte[] content = Encoding.UTF8.GetBytes("bower evidence");

        DetachedSignature signature = DetachedSigner.Sign(content, privatePem);

        Assert.Equal(keyId, signature.KeyId);
        Assert.True(DetachedSigner.Verify(content, signature, [publicPem]));
        Assert.False(DetachedSigner.Verify(Encoding.UTF8.GetBytes("bower evidencE"), signature, [publicPem]));
        Assert.False(DetachedSigner.Verify(content, signature, [otherPublic]));
        Assert.False(DetachedSigner.Verify(content, signature with { Algorithm = "RS256" }, [publicPem]));
        Assert.False(DetachedSigner.Verify(content, signature with { Value = "not base64!" }, [publicPem]));
    }

    [Fact]
    public void Signer_RejectsNonP256Keys()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        Assert.Throws<CryptographicException>(() => DetachedSigner.Sign([1, 2, 3], p384.ExportPkcs8PrivateKeyPem()));
    }

    [Fact]
    public void CanonicalJson_IsIndependentOfPropertyOrder()
    {
        JsonNode a = JsonNode.Parse("""{"b":1,"a":{"d":[1,{"z":2,"y":1}],"c":"x"}}""")!;
        JsonNode b = JsonNode.Parse("""{ "a": { "c": "x", "d": [1, {"y": 1, "z": 2}] }, "b": 1 }""")!;

        Assert.Equal(CanonicalJson.Text(a), CanonicalJson.Text(b));
        Assert.Equal("""{"a":{"c":"x","d":[1,{"y":1,"z":2}]},"b":1}""", CanonicalJson.Text(a));
    }

    [Fact]
    public void Generator_ProducesDirectRuleAndTableMatchingSchema()
    {
        JsonObject template = DcrTemplateGenerator.Generate(new DcrTemplateOptions());
        JsonObject rule = Resource(template, "Microsoft.Insights/dataCollectionRules");
        JsonObject table = Resource(template, "Microsoft.OperationalInsights/workspaces/tables");

        Assert.Equal("Direct", rule["kind"]!.GetValue<string>());
        Assert.Empty(DcrDrift.CompareRule(rule.ToJsonString(), SentinelSchema.Default));
        Assert.Empty(DcrDrift.CompareTable(table.ToJsonString(), SentinelSchema.Default));
        Assert.Equal(365, table["properties"]!["totalRetentionInDays"]!.GetValue<int>());
    }

    [Fact]
    public void Drift_FlagsMissingColumnsWrongOutputAndShortRetention()
    {
        JsonObject template = DcrTemplateGenerator.Generate(new DcrTemplateOptions { TotalRetentionInDays = 90, RetentionInDays = 30 });
        JsonObject rule = Resource(template, "Microsoft.Insights/dataCollectionRules");
        JsonObject table = Resource(template, "Microsoft.OperationalInsights/workspaces/tables");
        ((JsonArray)rule["properties"]!["streamDeclarations"]!["Custom-BowerSecurity"]!["columns"]!).RemoveAt(1);
        rule["properties"]!["dataFlows"]![0]!["outputStream"] = "Custom-Other_CL";
        ((JsonArray)table["properties"]!["schema"]!["columns"]!).RemoveAt(1);

        string[] ruleCodes = DcrDrift.CompareRule(rule.ToJsonString(), SentinelSchema.Default).Select(f => f.Code).ToArray();
        string[] tableCodes = DcrDrift.CompareTable(table.ToJsonString(), SentinelSchema.Default).Select(f => f.Code).ToArray();

        Assert.Contains("stream-column-missing", ruleCodes);
        Assert.Contains("output-stream", ruleCodes);
        Assert.Contains("table-column-missing", tableCodes);
        Assert.Contains("retention-short", tableCodes);
    }

    [Fact]
    public void Lint_FlagsTransformTraps()
    {
        string tooLong = "source | " + new string('x', DcrDrift.MaximumTransformLength);
        string regex = "source | parse kind=regex RawData with @'(\\d+)' Id:int";

        Assert.Contains(DcrDrift.LintTransform(tooLong), f => f.Code == "transform-too-long");
        Assert.Contains(DcrDrift.LintTransform(regex), f => f.Code == "parse-regex-full-match");
    }

    [Fact]
    public void Lint_RejectsReservedAndInvalidColumnNames()
    {
        SentinelSchema schema = SentinelSchema.Default with
        {
            TableColumns = [.. SentinelSchema.Default.TableColumns, new TableColumn("TenantId", "string", "x"), new TableColumn("1bad", "string", "x")]
        };

        Assert.Equal(2, DcrDrift.LintSchema(schema).Count(f => f.Code == "column-name"));
    }

    [Fact]
    public void Preflight_CatchesWhatAzureWouldSilentlyTruncateOrCoerce()
    {
        JsonObject record = new()
        {
            ["eventId"] = "e1",
            ["timeGenerated"] = "not a date",
            ["eventType"] = new JsonObject(),
            ["actor"] = new JsonObject { ["username"] = new string('x', 70_000) }
        };

        string[] codes = IngestionPreflight.Check(record, SentinelSchema.Default).Select(issue => issue.Code).ToArray();

        Assert.Contains("field-too-large", codes);
        Assert.Contains("type-mismatch", codes);
        Assert.Empty(IngestionPreflight.Check(new JsonObject { ["timeGenerated"] = "2026-10-08T00:00:00Z" }, SentinelSchema.Default));
    }

    [Fact]
    public void Bicep_MatchesTheSchemaModel()
    {
        string bicep = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "main.bicep"));
        SentinelSchema schema = SentinelSchema.Default;

        string[] tableColumns = BicepColumns(bicep, "schema: {", "]");
        string[] streamColumns = BicepColumns(bicep, "'Custom-BowerSecurity': {", "]");
        string transform = Regex.Match(bicep, "transformKql: '''(?<kql>.*?)'''", RegexOptions.Singleline).Groups["kql"].Value;

        Assert.Equal(schema.TableColumns.Select(c => $"{c.Name}:{c.Type}".ToLowerInvariant()), tableColumns);
        Assert.Equal(schema.StreamColumns.Select(c => $"{c.Name}:{c.Type}".ToLowerInvariant()), streamColumns);
        Assert.Equal(Normalise(schema.TransformKql()), Normalise(transform));
    }

    private static string[] BicepColumns(string bicep, string startMarker, string endMarker)
    {
        int start = bicep.IndexOf(startMarker, StringComparison.Ordinal);
        int end = bicep.IndexOf(endMarker, start, StringComparison.Ordinal);
        return ColumnPattern().Matches(bicep[start..end])
            .Select(match => $"{match.Groups["name"].Value}:{match.Groups["type"].Value}".ToLowerInvariant())
            .ToArray();
    }

    private static string Normalise(string kql) => Regex.Replace(kql, @"\s+", " ").Trim();

    private static JsonObject Resource(JsonObject template, string type) =>
        ((JsonArray)template["resources"]!).OfType<JsonObject>().Single(item => item["type"]!.GetValue<string>() == type);

    [GeneratedRegex(@"name: '(?<name>[^']+)', type: '(?<type>[^']+)'")]
    private static partial Regex ColumnPattern();
}

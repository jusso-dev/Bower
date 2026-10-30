using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
    public void Investigation_context_is_declared_and_projected_before_pack_all()
    {
        SentinelSchema schema = SentinelSchema.Default;
        foreach (string field in new[] { "target", "change", "attributes", "eventOutcomeReason", "timeObserved" })
        {
            Assert.Contains(schema.StreamColumns, column => column.Name == field);
            Assert.Contains(schema.TableColumns, column => column.Expression.Contains(field, StringComparison.Ordinal));
        }
        Assert.Equal("target", schema.TableColumns.Single(column => column.Name == "Target").Expression);
        Assert.Equal("change", schema.TableColumns.Single(column => column.Name == "Change").Expression);
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

    [Theory]
    [InlineData("""{"eventId":"e1","timeGenerated":"not a date","eventType":{},"actor":{"username":"x"}}""")]
    [InlineData("""{"eventId":"e1","timeGenerated":null,"eventResult":3,"labels":"text","valueScore":"9"}""")]
    [InlineData("""{"eventId":"e1","timeGenerated":"2026-10-08T00:00:00Z","eventSeverity":"high","valueScore":7,"o":{"x":1,"x":2}}""")]
    [InlineData("""{"eventId":"e1","timeGenerated":"2026-10-08T00:00:00Z","eventCategory":"\u00e9\u003c","attributes":[1,{"a":null}]}""")]
    [InlineData("""{"eventId":"e1"}""")]
    public void Preflight_OverUploadBytesMatchesTheJsonObjectCheck(string json)
    {
        JsonObject record = JsonNode.Parse(json)!.AsObject();
        byte[] uploaded = Encoding.UTF8.GetBytes(JsonNode.Parse(json)!.ToJsonString());
        IReadOnlyList<PreflightIssue> legacy = LegacyPreflight(record, SentinelSchema.Default);

        Assert.Equal(legacy, IngestionPreflight.Check(uploaded, SentinelSchema.Default));
        Assert.Equal(legacy, IngestionPreflight.Check(record, SentinelSchema.Default));
    }

    /// <summary>The JsonObject implementation the byte reader replaced (the oracle).</summary>
    private static List<PreflightIssue> LegacyPreflight(JsonObject record, SentinelSchema schema)
    {
        List<PreflightIssue> issues = [];
        int recordBytes = Encoding.UTF8.GetByteCount(record.ToJsonString());
        if (recordBytes > IngestionPreflight.MaximumRecordBytes)
        {
            issues.Add(new("record-too-large", "$", $"Record is {recordBytes} bytes; the API limit is {IngestionPreflight.MaximumRecordBytes}."));
        }

        foreach (StreamColumn column in schema.StreamColumns)
        {
            JsonNode? value = record[column.Name];
            if (value is null)
            {
                continue;
            }

            int bytes = Encoding.UTF8.GetByteCount(value.ToJsonString());
            if (bytes > IngestionPreflight.MaximumFieldBytes)
            {
                issues.Add(new("field-too-large", column.Name,
                    $"Field is {bytes} bytes; Azure silently truncates values above {IngestionPreflight.MaximumFieldBytes}."));
            }

            JsonValueKind kind = value.GetValueKind();
            bool typeOk = column.Type switch
            {
                "string" => kind == JsonValueKind.String,
                "datetime" => kind == JsonValueKind.String && DateTimeOffset.TryParse(
                    value.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out _),
                "int" or "long" or "real" => kind == JsonValueKind.Number,
                "boolean" => kind is JsonValueKind.True or JsonValueKind.False,
                "dynamic" => kind is JsonValueKind.Object or JsonValueKind.Array,
                _ => true
            };
            if (!typeOk)
            {
                issues.Add(new("type-mismatch", column.Name,
                    $"Expected {column.Type}, got {kind}; Azure would store an empty or stringified value."));
            }
        }

        if (record["timeGenerated"] is null)
        {
            issues.Add(new("time-generated-missing", "timeGenerated", "Rows without timeGenerated cannot be placed in time."));
        }

        return issues;
    }

    [Fact]
    public void Preflight_MeasuresSizesOnTheUploadedBytes()
    {
        string username = new('<', 11_000);
        byte[] uploaded = Encoding.UTF8.GetBytes(
            new JsonObject
            {
                ["timeGenerated"] = "2026-10-08T00:00:00Z",
                ["actor"] = new JsonObject { ["username"] = username }
            }.ToJsonString());

        // 11 000 '<' escape to 66 000 bytes (<), above the 64 KiB field limit.
        PreflightIssue issue = Assert.Single(IngestionPreflight.Check(uploaded, SentinelSchema.Default));
        Assert.Equal("field-too-large", issue.Code);
        Assert.Equal("actor", issue.Field);
    }

    [Theory]
    [InlineData("""{"eventId":"e1","timeGenerated":"2026-10-08T00:00:00Z","eventId":"e2"}""")]
    [InlineData("""[{"eventId":"e1"}]""")]
    [InlineData("""{"eventId":"e1"} {}""")]
    [InlineData("""{"eventId":""")]
    public void Preflight_RejectsBytesThatAreNotOneJsonObject(string json)
    {
        Assert.ThrowsAny<JsonException>(() => IngestionPreflight.Check(Encoding.UTF8.GetBytes(json), SentinelSchema.Default));
    }

    [Fact]
    public void Preflight_RequiresDynamicColumnsToBeObjectsOrArrays()
    {
        JsonObject record = new()
        {
            ["timeGenerated"] = "2026-10-08T00:00:00Z",
            ["labels"] = "team=red",
            ["application"] = new JsonObject { ["name"] = "a" },
            ["privacy"] = new JsonArray()
        };

        PreflightIssue issue = Assert.Single(IngestionPreflight.Check(record, SentinelSchema.Default));

        Assert.Equal(("type-mismatch", "labels"), (issue.Code, issue.Field));
        Assert.Equal("Expected dynamic, got String; Azure would store an empty or stringified value.", issue.Detail);
    }

    [Fact]
    public void ArmApiVersions_ArePinnedPerResourceProviderInTemplateAndBicep()
    {
        JsonObject template = DcrTemplateGenerator.Generate(new DcrTemplateOptions());
        JsonArray resources = template["resources"]!.AsArray();
        string ApiVersion(string type) =>
            resources.Single(resource => resource!["type"]!.GetValue<string>() == type)!["apiVersion"]!.GetValue<string>();
        string bicep = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "main.bicep"));

        Assert.Equal(AzureApiVersions.LogAnalytics, ApiVersion("Microsoft.OperationalInsights/workspaces/tables"));
        Assert.Equal(AzureApiVersions.DataCollectionRules, ApiVersion("Microsoft.Insights/dataCollectionRules"));
        Assert.Contains(
            $"'{AzureApiVersions.DataCollectionRules}').endpoints.logsIngestion",
            template["outputs"]!["logsIngestionEndpoint"]!["value"]!.GetValue<string>(),
            StringComparison.Ordinal);
        Assert.Contains($"'Microsoft.OperationalInsights/workspaces@{AzureApiVersions.LogAnalytics}'", bicep, StringComparison.Ordinal);
        Assert.Contains($"'Microsoft.OperationalInsights/workspaces/tables@{AzureApiVersions.LogAnalytics}'", bicep, StringComparison.Ordinal);
        Assert.Contains($"'Microsoft.Insights/dataCollectionRules@{AzureApiVersions.DataCollectionRules}'", bicep, StringComparison.Ordinal);
    }

    [Fact]
    public void Bicep_MatchesTheSchemaModel()
    {
        string bicep = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "main.bicep"));
        SentinelSchema schema = SentinelSchema.Default;

        string[] tableColumns = BicepColumns(bicep, "schema: {", "]");
        string[] streamColumns = BicepColumns(bicep, "'Custom-BowerSecurity': {", "]");
        string transform = Regex.Match(bicep, "transformKql: '''(?<kql>.*?)'''", RegexOptions.Singleline).Groups["kql"].Value;

        // The resource providers use different, case-sensitive timestamp type names:
        // Log Analytics tables use dateTime, while DCR streams require datetime.
        JsonObject generated = DcrTemplateGenerator.Generate(new DcrTemplateOptions());
        JsonArray generatedColumns = Resource(generated, "Microsoft.OperationalInsights/workspaces/tables")
            ["properties"]!["schema"]!["columns"]!.AsArray();
        Assert.Equal(generatedColumns.Select(column => $"{column!["name"]!.GetValue<string>()}:{column["type"]!.GetValue<string>()}"), tableColumns);
        Assert.Equal(schema.StreamColumns.Select(c => $"{c.Name}:{c.Type}"), streamColumns);
        Assert.Equal(Normalise(schema.TransformKql()), Normalise(transform));
    }

    private static string[] BicepColumns(string bicep, string startMarker, string endMarker)
    {
        int start = bicep.IndexOf(startMarker, StringComparison.Ordinal);
        int end = bicep.IndexOf(endMarker, start, StringComparison.Ordinal);
        return ColumnPattern().Matches(bicep[start..end])
            .Select(match => $"{match.Groups["name"].Value}:{match.Groups["type"].Value}")
            .ToArray();
    }

    private static string Normalise(string kql) => Regex.Replace(kql, @"\s+", " ").Trim();

    private static JsonObject Resource(JsonObject template, string type) =>
        ((JsonArray)template["resources"]!).OfType<JsonObject>().Single(item => item["type"]!.GetValue<string>() == type);

    [GeneratedRegex(@"name: '(?<name>[^']+)', type: '(?<type>[^']+)'")]
    private static partial Regex ColumnPattern();
}

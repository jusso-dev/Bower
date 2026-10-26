using Bower.Pipeline;

namespace Bower.UnitTests;

public sealed class PipelineValidatorTests
{
    [Fact]
    public void Template_SentinelApp_IsValid()
    {
        TelemetryPipeline pipeline = PipelineValidator.CreateTemplate("sentinel-app");
        PipelineValidationResult result = PipelineValidator.Validate(pipeline);

        Assert.True(result.IsValid, string.Join("; ", result.Issues.Select(issue => issue.Message)));
        Assert.Equal(4, result.TopologicalOrder.Count);
        Assert.Equal("source", result.TopologicalOrder[0]);
    }

    [Fact]
    public void Validate_RejectsCycleAndSecrets()
    {
        TelemetryPipeline pipeline = new(
            "bad",
            "Bad",
            "1.0.0",
            "cycle",
            [
                new PipelineNode("a", PipelineNodeKind.Source, "http-collector"),
                new PipelineNode(
                    "b",
                    PipelineNodeKind.Output,
                    "http",
                    new Dictionary<string, string> { ["apiKey"] = "super-secret" })
            ],
            [
                new PipelineEdge("a", "b"),
                new PipelineEdge("b", "a")
            ]);

        PipelineValidationResult result = PipelineValidator.Validate(pipeline);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code == "cycle");
        Assert.Contains(result.Issues, issue => issue.Code == "secret-in-config");
    }

    [Fact]
    public void Yaml_RoundTripsTemplate()
    {
        TelemetryPipeline original = PipelineValidator.CreateTemplate("aws-security");
        string yaml = PipelineDocument.ToYaml(original);
        TelemetryPipeline parsed = PipelineDocument.ParseYaml(yaml);

        Assert.Equal(original.Id, parsed.Id);
        Assert.Equal(original.Nodes.Count, parsed.Nodes.Count);
        Assert.Equal(original.Edges.Count, parsed.Edges.Count);
        Assert.True(PipelineValidator.Validate(parsed).IsValid);
    }

    [Fact]
    public void Validate_FlagsNodesWithNoEdgesAndExplainsUnknownOutputTypes()
    {
        TelemetryPipeline pipeline = new(
            "orphan",
            "Orphan",
            "1.0.0",
            string.Empty,
            [
                new PipelineNode("s", PipelineNodeKind.Source, "http-collector"),
                new PipelineNode("lonely", PipelineNodeKind.Enrich, "geo"),
                new PipelineNode("o", PipelineNodeKind.Output, "azure-monitor")
            ],
            [new PipelineEdge("s", "o")]);

        PipelineValidationResult result = PipelineValidator.Validate(pipeline);

        Assert.False(result.IsValid);
        PipelineValidationIssue disconnected = Assert.Single(result.Issues, issue => issue.Code == "node-disconnected");
        Assert.Equal("lonely", disconnected.NodeId);
        Assert.Equal("Node 'lonely' has no edges; connect it to the pipeline or remove it.", disconnected.Message);
        PipelineValidationIssue output = Assert.Single(result.Issues, issue => issue.Code == "output-type");
        Assert.Equal(
            "Unknown output type 'azure-monitor'. Supported: azure-logs-ingestion, ama-spool, http, kafka, syslog, security-lake, opensearch.",
            output.Message);
        Assert.True(PipelineValidator.Validate(PipelineValidator.CreateTemplate("aws-security")).IsValid);
    }

    [Fact]
    public void Estimate_RefusesCyclesAndMeasuresLongestPathInAnyEdgeOrder()
    {
        TelemetryPipeline cycle = new(
            "c",
            "C",
            "1",
            string.Empty,
            [
                new PipelineNode("a", PipelineNodeKind.Source, "http-collector"),
                new PipelineNode("b", PipelineNodeKind.Output, "http")
            ],
            [new PipelineEdge("a", "b"), new PipelineEdge("b", "a")]);
        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => PipelineValidator.Estimate(cycle));
        Assert.Equal("Pipeline graph contains a cycle; no estimate.", exception.Message);
        Assert.Null(PipelineValidator.TryEstimate(cycle));

        TelemetryPipeline duplicate = cycle with { Edges = [], Nodes = [cycle.Nodes[0], cycle.Nodes[0]] };
        Assert.Throws<ArgumentException>(() => PipelineValidator.Estimate(duplicate));
        Assert.Null(PipelineValidator.TryEstimate(duplicate));

        // Edges listed back to front: a single pass would report depth 1.
        TelemetryPipeline chain = new(
            "chain",
            "Chain",
            "1",
            string.Empty,
            [
                new PipelineNode("a", PipelineNodeKind.Source, "http-collector"),
                new PipelineNode("b", PipelineNodeKind.Redact, "privacy"),
                new PipelineNode("c", PipelineNodeKind.Filter, "policy-engine"),
                new PipelineNode("d", PipelineNodeKind.Output, "http")
            ],
            [new PipelineEdge("c", "d"), new PipelineEdge("b", "c"), new PipelineEdge("a", "b"), new PipelineEdge("a", "zzz")]);
        Assert.Equal(new PipelinePerformanceEstimate(4, 4, 1, 1, 3), PipelineValidator.Estimate(chain));
    }

    private const string SupportedKinds = "Source, Filter, Redact, Normalise, Detect, Enrich, Output";

    /// <summary>
    /// <c>rust/crates/bower-pipeline/tests/fixtures/node-kinds.txt</c>, shared with the Rust
    /// port: one <c>kind text|parsed kind name or error</c> per line.
    /// </summary>
    [Fact]
    public void NodeKindVectors_AcceptDeclaredNamesAndOrdinalsOnly()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "pipeline-vectors", "node-kinds.txt"));
        Assert.NotEmpty(lines);
        foreach (string line in lines)
        {
            int separator = line.LastIndexOf('|');
            string text = line[..separator];
            string expected = line[(separator + 1)..];
            string yaml = ConnectedGraph(text);

            if (expected == "error")
            {
                InvalidDataException exception = Assert.Throws<InvalidDataException>(() => PipelineDocument.ParseYaml(yaml));
                Assert.Equal($"Node 'm' has unknown kind '{text}'. Supported: {SupportedKinds}.", exception.Message);
                continue;
            }

            PipelineNodeKind kind = PipelineDocument.ParseYaml(yaml).Nodes[1].Kind;
            Assert.True(Enum.IsDefined(kind), line);
            Assert.Equal(expected, kind.ToString());
        }
    }

    [Theory]
    [InlineData("999", 0)]
    [InlineData("999", 1)]
    [InlineData("999", 2)]
    [InlineData("-1", 0)]
    [InlineData("-1", 1)]
    [InlineData("-1", 2)]
    public void ParseYaml_RejectsUndefinedNumericKindInAnyGraphPosition(string kind, int position)
    {
        string[] kinds = ["Source", "Filter", "Output"];
        kinds[position] = kind;
        string yaml =
            $"id: p\nname: P\nversion: 1.0.0\ndescription: d\nnodes:\n" +
            $"- id: s\n  kind: {kinds[0]}\n  type: http-collector\n" +
            $"- id: m\n  kind: {kinds[1]}\n  type: policy-engine\n" +
            $"- id: o\n  kind: {kinds[2]}\n  type: http\n" +
            "edges:\n- from: s\n  to: m\n- from: m\n  to: o\n";

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() => PipelineDocument.ParseYaml(yaml));
        string node = new[] { "s", "m", "o" }[position];
        Assert.Equal($"Node '{node}' has unknown kind '{kind}'. Supported: {SupportedKinds}.", exception.Message);
    }

    [Theory]
    [InlineData(999)]
    [InlineData(-1)]
    [InlineData(7)]
    public void Validate_RejectsUndefinedKindOnDirectlyConstructedModel(int value)
    {
        TelemetryPipeline pipeline = Connected((PipelineNodeKind)value, "policy-engine");

        PipelineValidationResult result = PipelineValidator.Validate(pipeline);

        Assert.False(result.IsValid);
        PipelineValidationIssue issue = Assert.Single(result.Issues);
        Assert.Equal("node-kind", issue.Code);
        Assert.Equal("m", issue.NodeId);
        Assert.Equal($"Node 'm' has undefined kind '{value}'. Supported: {SupportedKinds}.", issue.Message);
    }

    [Theory]
    [InlineData(PipelineNodeKind.Source, "http-collector")]
    [InlineData(PipelineNodeKind.Filter, "policy-engine")]
    [InlineData(PipelineNodeKind.Redact, "json-redactor")]
    [InlineData(PipelineNodeKind.Normalise, "ocsf")]
    [InlineData(PipelineNodeKind.Detect, "sigma")]
    [InlineData(PipelineNodeKind.Enrich, "geo")]
    [InlineData(PipelineNodeKind.Output, "http")]
    public void Validate_AcceptsEveryDeclaredKind(PipelineNodeKind kind, string type)
    {
        TelemetryPipeline pipeline = Connected(kind, type);

        PipelineValidationResult result = PipelineValidator.Validate(pipeline);
        Assert.True(result.IsValid, string.Join("; ", result.Issues.Select(issue => issue.Message)));
        Assert.Equal(kind, PipelineDocument.ParseYaml(PipelineDocument.ToYaml(pipeline)).Nodes[1].Kind);
    }

    private static TelemetryPipeline Connected(PipelineNodeKind middle, string type) => new(
        "p",
        "P",
        "1.0.0",
        string.Empty,
        [
            new PipelineNode("s", PipelineNodeKind.Source, "http-collector"),
            new PipelineNode("m", middle, type),
            new PipelineNode("o", PipelineNodeKind.Output, "http")
        ],
        [new PipelineEdge("s", "m"), new PipelineEdge("m", "o")]);

    private static string ConnectedGraph(string middleKind) =>
        "id: p\nname: P\nversion: 1.0.0\ndescription: d\nnodes:\n" +
        "- id: s\n  kind: Source\n  type: http-collector\n" +
        $"- id: m\n  kind: '{middleKind}'\n  type: policy-engine\n" +
        "- id: o\n  kind: Output\n  type: http\n" +
        "edges:\n- from: s\n  to: m\n- from: m\n  to: o\n";
}

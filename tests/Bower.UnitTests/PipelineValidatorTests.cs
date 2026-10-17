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
}

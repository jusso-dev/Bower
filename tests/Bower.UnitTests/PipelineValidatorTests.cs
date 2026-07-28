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
}

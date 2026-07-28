namespace Bower.Pipeline;

public enum PipelineNodeKind
{
    Source,
    Filter,
    Redact,
    Normalise,
    Detect,
    Enrich,
    Output
}

public sealed record PipelineNode(
    string Id,
    PipelineNodeKind Kind,
    string Type,
    IReadOnlyDictionary<string, string>? Config = null);

public sealed record PipelineEdge(string From, string To);

public sealed record TelemetryPipeline(
    string Id,
    string Name,
    string Version,
    string Description,
    IReadOnlyList<PipelineNode> Nodes,
    IReadOnlyList<PipelineEdge> Edges,
    IReadOnlyList<string>? Tags = null);

public sealed record PipelineValidationIssue(
    string Code,
    string Message,
    string? NodeId = null);

public sealed record PipelineValidationResult(
    bool IsValid,
    IReadOnlyList<PipelineValidationIssue> Issues,
    IReadOnlyList<string> TopologicalOrder,
    int EstimatedStageCount);

public sealed record PipelinePerformanceEstimate(
    int NodeCount,
    int EdgeCount,
    int SourceCount,
    int OutputCount,
    int MaxDepth);

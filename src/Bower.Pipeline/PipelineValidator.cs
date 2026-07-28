namespace Bower.Pipeline;

public static class PipelineValidator
{
    private static readonly HashSet<string> AllowedSourceTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "http-collector", "sqlserver", "aws-cloudtrail", "aws-guardduty", "aws-securityhub",
        "aws-cloudwatch", "file-tail", "ama-companion", "ec2-host"
    };

    private static readonly HashSet<string> AllowedOutputTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "azure-logs-ingestion", "ama-spool", "http", "kafka", "syslog", "security-lake", "opensearch"
    };

    private static readonly HashSet<string> SecretKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "secret", "token", "apikey", "connectionstring", "privatekey"
    };

    public static PipelineValidationResult Validate(TelemetryPipeline pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        List<PipelineValidationIssue> issues = [];

        if (string.IsNullOrWhiteSpace(pipeline.Id) || pipeline.Id.Length > 128)
        {
            issues.Add(new PipelineValidationIssue("pipeline-id", "Pipeline id is required and must be <= 128 chars."));
        }

        if (string.IsNullOrWhiteSpace(pipeline.Name))
        {
            issues.Add(new PipelineValidationIssue("pipeline-name", "Pipeline name is required."));
        }

        if (string.IsNullOrWhiteSpace(pipeline.Version))
        {
            issues.Add(new PipelineValidationIssue("pipeline-version", "Pipeline version is required."));
        }

        if (pipeline.Nodes.Count == 0)
        {
            issues.Add(new PipelineValidationIssue("nodes-empty", "Pipeline must contain at least one node."));
        }

        if (pipeline.Nodes.Count > 64)
        {
            issues.Add(new PipelineValidationIssue("nodes-too-many", "Pipeline cannot exceed 64 nodes."));
        }

        Dictionary<string, PipelineNode> nodes = new(StringComparer.Ordinal);
        foreach (PipelineNode node in pipeline.Nodes)
        {
            if (string.IsNullOrWhiteSpace(node.Id) || !nodes.TryAdd(node.Id, node))
            {
                issues.Add(new PipelineValidationIssue("node-id", "Node ids must be unique and non-empty.", node.Id));
                continue;
            }

            ValidateNode(node, issues);
        }

        foreach (PipelineEdge edge in pipeline.Edges)
        {
            if (!nodes.ContainsKey(edge.From) || !nodes.ContainsKey(edge.To))
            {
                issues.Add(
                    new PipelineValidationIssue(
                        "edge-unknown-node",
                        $"Edge '{edge.From}' -> '{edge.To}' references unknown node."));
            }

            if (string.Equals(edge.From, edge.To, StringComparison.Ordinal))
            {
                issues.Add(new PipelineValidationIssue("edge-self", "Self-edges are not allowed.", edge.From));
            }
        }

        List<string> order = [];
        if (nodes.Count == pipeline.Nodes.Count &&
            pipeline.Edges.All(edge => nodes.ContainsKey(edge.From) && nodes.ContainsKey(edge.To)))
        {
            if (!TryTopologicalSort(pipeline, out order, out string? cycleNode))
            {
                issues.Add(new PipelineValidationIssue("cycle", "Pipeline graph contains a cycle.", cycleNode));
            }
        }

        bool hasSource = pipeline.Nodes.Any(node => node.Kind == PipelineNodeKind.Source);
        bool hasOutput = pipeline.Nodes.Any(node => node.Kind == PipelineNodeKind.Output);
        if (!hasSource)
        {
            issues.Add(new PipelineValidationIssue("missing-source", "Pipeline needs at least one source node."));
        }

        if (!hasOutput)
        {
            issues.Add(new PipelineValidationIssue("missing-output", "Pipeline needs at least one output node."));
        }

        return new PipelineValidationResult(issues.Count == 0, issues, order, order.Count);
    }

    public static PipelinePerformanceEstimate Estimate(TelemetryPipeline pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        Dictionary<string, int> depth = pipeline.Nodes.ToDictionary(node => node.Id, _ => 0, StringComparer.Ordinal);
        foreach (PipelineEdge edge in pipeline.Edges)
        {
            if (depth.TryGetValue(edge.From, out int fromDepth) &&
                depth.TryGetValue(edge.To, out int toDepth))
            {
                depth[edge.To] = Math.Max(toDepth, fromDepth + 1);
            }
        }

        return new PipelinePerformanceEstimate(
            pipeline.Nodes.Count,
            pipeline.Edges.Count,
            pipeline.Nodes.Count(node => node.Kind == PipelineNodeKind.Source),
            pipeline.Nodes.Count(node => node.Kind == PipelineNodeKind.Output),
            depth.Count == 0 ? 0 : depth.Values.Max());
    }

    public static TelemetryPipeline CreateTemplate(string templateId)
    {
        return templateId.ToLowerInvariant() switch
        {
            "sentinel-app" => new TelemetryPipeline(
                "template-sentinel-app",
                "Application to Sentinel",
                "1.0.0",
                "HTTP collector → redact → policy filter → Azure Logs Ingestion",
                [
                    new PipelineNode("source", PipelineNodeKind.Source, "http-collector"),
                    new PipelineNode("redact", PipelineNodeKind.Redact, "json-redactor"),
                    new PipelineNode("filter", PipelineNodeKind.Filter, "policy-engine"),
                    new PipelineNode("out", PipelineNodeKind.Output, "azure-logs-ingestion")
                ],
                [
                    new PipelineEdge("source", "redact"),
                    new PipelineEdge("redact", "filter"),
                    new PipelineEdge("filter", "out")
                ],
                ["template", "sentinel"]),
            "aws-security" => new TelemetryPipeline(
                "template-aws-security",
                "AWS Security to multi-destination",
                "1.0.0",
                "AWS sources → normalise → detect → dual output",
                [
                    new PipelineNode("cloudtrail", PipelineNodeKind.Source, "aws-cloudtrail"),
                    new PipelineNode("guardduty", PipelineNodeKind.Source, "aws-guardduty"),
                    new PipelineNode("normalise", PipelineNodeKind.Normalise, "ocsf"),
                    new PipelineNode("detect", PipelineNodeKind.Detect, "sigma"),
                    new PipelineNode("sentinel", PipelineNodeKind.Output, "azure-logs-ingestion"),
                    new PipelineNode("lake", PipelineNodeKind.Output, "security-lake")
                ],
                [
                    new PipelineEdge("cloudtrail", "normalise"),
                    new PipelineEdge("guardduty", "normalise"),
                    new PipelineEdge("normalise", "detect"),
                    new PipelineEdge("detect", "sentinel"),
                    new PipelineEdge("detect", "lake")
                ],
                ["template", "aws"]),
            _ => throw new ArgumentException($"Unknown pipeline template '{templateId}'.")
        };
    }

    private static void ValidateNode(PipelineNode node, List<PipelineValidationIssue> issues)
    {
        if (string.IsNullOrWhiteSpace(node.Type))
        {
            issues.Add(new PipelineValidationIssue("node-type", "Node type is required.", node.Id));
        }

        if (node.Kind == PipelineNodeKind.Source &&
            !AllowedSourceTypes.Contains(node.Type))
        {
            issues.Add(new PipelineValidationIssue("source-type", $"Unknown source type '{node.Type}'.", node.Id));
        }

        if (node.Kind == PipelineNodeKind.Output &&
            !AllowedOutputTypes.Contains(node.Type))
        {
            issues.Add(new PipelineValidationIssue("output-type", $"Unknown output type '{node.Type}'.", node.Id));
        }

        if (node.Config is null)
        {
            return;
        }

        foreach ((string key, string value) in node.Config)
        {
            string normalized = string.Concat(key.Where(char.IsLetterOrDigit));
            if (SecretKeys.Contains(normalized))
            {
                issues.Add(
                    new PipelineValidationIssue(
                        "secret-in-config",
                        $"Node config key '{key}' looks like a secret and is not allowed.",
                        node.Id));
            }

            if (value.Length > 4_096)
            {
                issues.Add(
                    new PipelineValidationIssue(
                        "config-too-large",
                        $"Config value for '{key}' exceeds 4 KiB.",
                        node.Id));
            }
        }
    }

    private static bool TryTopologicalSort(
        TelemetryPipeline pipeline,
        out List<string> order,
        out string? cycleNode)
    {
        Dictionary<string, List<string>> adjacency = pipeline.Nodes.ToDictionary(
            node => node.Id,
            _ => new List<string>(),
            StringComparer.Ordinal);
        Dictionary<string, int> indegree = pipeline.Nodes.ToDictionary(
            node => node.Id,
            _ => 0,
            StringComparer.Ordinal);

        foreach (PipelineEdge edge in pipeline.Edges)
        {
            adjacency[edge.From].Add(edge.To);
            indegree[edge.To]++;
        }

        Queue<string> queue = new(indegree.Where(pair => pair.Value == 0).Select(pair => pair.Key));
        order = [];
        while (queue.Count > 0)
        {
            string current = queue.Dequeue();
            order.Add(current);
            foreach (string next in adjacency[current])
            {
                indegree[next]--;
                if (indegree[next] == 0)
                {
                    queue.Enqueue(next);
                }
            }
        }

        if (order.Count != pipeline.Nodes.Count)
        {
            cycleNode = indegree.First(pair => pair.Value > 0).Key;
            return false;
        }

        cycleNode = null;
        return true;
    }
}

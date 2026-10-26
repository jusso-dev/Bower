namespace Bower.Pipeline;

public static class PipelineValidator
{
    private static readonly string[] SourceTypes =
    [
        "http-collector", "sqlserver", "aws-cloudtrail", "aws-guardduty", "aws-securityhub",
        "aws-cloudwatch", "file-tail", "ama-companion", "ec2-host"
    ];

    // Azure Monitor / Sentinel delivery is the "azure-logs-ingestion" output (Logs
    // Ingestion API). There is no separate "azure-monitor" output type.
    private static readonly string[] OutputTypes =
    [
        "azure-logs-ingestion", "ama-spool", "http", "kafka", "syslog", "security-lake", "opensearch"
    ];

    private static readonly HashSet<string> AllowedSourceTypes = new(SourceTypes, StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> AllowedOutputTypes = new(OutputTypes, StringComparer.OrdinalIgnoreCase);

    private static readonly string SupportedSourceTypes = string.Join(", ", SourceTypes);

    private static readonly string SupportedOutputTypes = string.Join(", ", OutputTypes);

    internal static readonly string SupportedKinds = string.Join(", ", Enum.GetNames<PipelineNodeKind>());

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

        // A node with no edges is never reached and never delivers: flag it instead of
        // silently ignoring it. Duplicate and empty ids are reported above.
        HashSet<string> connected = new(StringComparer.Ordinal);
        foreach (PipelineEdge edge in pipeline.Edges)
        {
            connected.Add(edge.From);
            connected.Add(edge.To);
        }

        HashSet<string> reported = new(StringComparer.Ordinal);
        foreach (PipelineNode node in pipeline.Nodes)
        {
            if (!string.IsNullOrWhiteSpace(node.Id)
                && !connected.Contains(node.Id)
                && reported.Add(node.Id))
            {
                issues.Add(
                    new PipelineValidationIssue(
                        "node-disconnected",
                        $"Node '{node.Id}' has no edges; connect it to the pipeline or remove it.",
                        node.Id));
            }
        }

        List<string> order = [];
        if (nodes.Count == pipeline.Nodes.Count &&
            pipeline.Edges.All(edge => nodes.ContainsKey(edge.From) && nodes.ContainsKey(edge.To)))
        {
            if (!TryTopologicalSort(pipeline.Nodes, pipeline.Edges, out order, out string? cycleNode))
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

    /// <summary>
    /// Counts and the longest path through the graph. Edges that reference unknown nodes
    /// are ignored. Throws <see cref="ArgumentException"/> for duplicate node ids and
    /// <see cref="InvalidOperationException"/> for a cyclic graph, which has no depth.
    /// </summary>
    public static PipelinePerformanceEstimate Estimate(TelemetryPipeline pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        Dictionary<string, int> depth = new(StringComparer.Ordinal);
        foreach (PipelineNode node in pipeline.Nodes)
        {
            if (!depth.TryAdd(node.Id, 0))
            {
                throw new ArgumentException($"Duplicate node id '{node.Id}'; no estimate.");
            }
        }

        List<PipelineEdge> edges = [.. pipeline.Edges.Where(edge => depth.ContainsKey(edge.From) && depth.ContainsKey(edge.To))];
        if (!TryTopologicalSort(pipeline.Nodes, edges, out List<string> order, out _))
        {
            throw new InvalidOperationException("Pipeline graph contains a cycle; no estimate.");
        }

        // Longest path: relax each node's outgoing edges in topological order.
        ILookup<string, string> outgoing = edges.ToLookup(edge => edge.From, edge => edge.To, StringComparer.Ordinal);
        foreach (string current in order)
        {
            foreach (string next in outgoing[current])
            {
                depth[next] = Math.Max(depth[next], depth[current] + 1);
            }
        }

        return new PipelinePerformanceEstimate(
            pipeline.Nodes.Count,
            pipeline.Edges.Count,
            pipeline.Nodes.Count(node => node.Kind == PipelineNodeKind.Source),
            pipeline.Nodes.Count(node => node.Kind == PipelineNodeKind.Output),
            depth.Count == 0 ? 0 : depth.Values.Max());
    }

    /// <summary><see cref="Estimate"/>, or null when node ids are duplicated or the graph has a cycle.</summary>
    public static PipelinePerformanceEstimate? TryEstimate(TelemetryPipeline pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        try
        {
            return Estimate(pipeline);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
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
        // A model built in code can carry any integer cast to the enum; only declared kinds run.
        if (!Enum.IsDefined(node.Kind))
        {
            issues.Add(
                new PipelineValidationIssue(
                    "node-kind",
                    $"Node '{node.Id}' has undefined kind '{(int)node.Kind}'. Supported: {SupportedKinds}.",
                    node.Id));
        }

        if (string.IsNullOrWhiteSpace(node.Type))
        {
            issues.Add(new PipelineValidationIssue("node-type", "Node type is required.", node.Id));
        }

        if (node.Kind == PipelineNodeKind.Source &&
            !AllowedSourceTypes.Contains(node.Type))
        {
            issues.Add(new PipelineValidationIssue("source-type", $"Unknown source type '{node.Type}'. Supported: {SupportedSourceTypes}.", node.Id));
        }

        if (node.Kind == PipelineNodeKind.Output &&
            !AllowedOutputTypes.Contains(node.Type))
        {
            issues.Add(new PipelineValidationIssue("output-type", $"Unknown output type '{node.Type}'. Supported: {SupportedOutputTypes}.", node.Id));
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
        IReadOnlyList<PipelineNode> nodes,
        IReadOnlyList<PipelineEdge> edges,
        out List<string> order,
        out string? cycleNode)
    {
        Dictionary<string, List<string>> adjacency = nodes.ToDictionary(
            node => node.Id,
            _ => new List<string>(),
            StringComparer.Ordinal);
        Dictionary<string, int> indegree = nodes.ToDictionary(
            node => node.Id,
            _ => 0,
            StringComparer.Ordinal);

        foreach (PipelineEdge edge in edges)
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

        if (order.Count != nodes.Count)
        {
            cycleNode = indegree.First(pair => pair.Value > 0).Key;
            return false;
        }

        cycleNode = null;
        return true;
    }
}

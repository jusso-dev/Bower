using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Bower.Pipeline;

public static class PipelineDocument
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly ISerializer Serializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .Build();

    public static TelemetryPipeline ParseYaml(string yaml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yaml);
        if (Encoding.UTF8.GetByteCount(yaml) > 512 * 1024)
        {
            throw new InvalidDataException("Pipeline document exceeds 512 KiB.");
        }

        PipelineDto dto = Deserializer.Deserialize<PipelineDto>(yaml)
            ?? throw new InvalidDataException("Pipeline document was empty.");
        return dto.ToModel();
    }

    public static string ToYaml(TelemetryPipeline pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        return Serializer.Serialize(PipelineDto.FromModel(pipeline));
    }

    private sealed class PipelineDto
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public string? Version { get; set; }
        public string? Description { get; set; }
        public List<NodeDto>? Nodes { get; set; }
        public List<EdgeDto>? Edges { get; set; }
        public List<string>? Tags { get; set; }

        public TelemetryPipeline ToModel()
        {
            return new TelemetryPipeline(
                Id ?? string.Empty,
                Name ?? string.Empty,
                Version ?? string.Empty,
                Description ?? string.Empty,
                (Nodes ?? []).Select(node => node.ToModel()).ToArray(),
                (Edges ?? []).Select(edge => edge.ToModel()).ToArray(),
                Tags);
        }

        public static PipelineDto FromModel(TelemetryPipeline pipeline)
        {
            return new PipelineDto
            {
                Id = pipeline.Id,
                Name = pipeline.Name,
                Version = pipeline.Version,
                Description = pipeline.Description,
                Nodes = pipeline.Nodes.Select(NodeDto.FromModel).ToList(),
                Edges = pipeline.Edges.Select(EdgeDto.FromModel).ToList(),
                Tags = pipeline.Tags?.ToList()
            };
        }
    }

    private sealed class NodeDto
    {
        public string? Id { get; set; }
        public string? Kind { get; set; }
        public string? Type { get; set; }
        public Dictionary<string, string>? Config { get; set; }

        public PipelineNode ToModel()
        {
            if (!Enum.TryParse(Kind, ignoreCase: true, out PipelineNodeKind kind))
            {
                throw new InvalidDataException($"Unknown node kind '{Kind}'.");
            }

            return new PipelineNode(Id ?? string.Empty, kind, Type ?? string.Empty, Config);
        }

        public static NodeDto FromModel(PipelineNode node)
        {
            return new NodeDto
            {
                Id = node.Id,
                Kind = node.Kind.ToString(),
                Type = node.Type,
                Config = node.Config is null ? null : new Dictionary<string, string>(node.Config)
            };
        }
    }

    private sealed class EdgeDto
    {
        public string? From { get; set; }
        public string? To { get; set; }

        public PipelineEdge ToModel() => new(From ?? string.Empty, To ?? string.Empty);

        public static EdgeDto FromModel(PipelineEdge edge) => new() { From = edge.From, To = edge.To };
    }
}

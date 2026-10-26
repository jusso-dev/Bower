using System.ComponentModel;
using System.Globalization;
using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Bower.Pipeline;

public static class PipelineDocument
{
    // Static (source-generated) YamlDotNet context: reflection-free for Native AOT.
    private static readonly IDeserializer Deserializer = new StaticDeserializerBuilder(new PipelineYamlContext())
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly ISerializer Serializer = new StaticSerializerBuilder(new PipelineYamlContext())
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

    internal sealed class PipelineDto
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

    internal sealed class NodeDto
    {
        public string? Id { get; set; }
        public string? Kind { get; set; }
        public string? Type { get; set; }
        public Dictionary<string, string>? Config { get; set; }

        public PipelineNode ToModel()
        {
            if (!TryParseKind(Kind, out PipelineNodeKind kind))
            {
                throw new InvalidDataException(
                    $"Node '{Id}' has unknown kind '{Kind}'. Supported: {PipelineValidator.SupportedKinds}.");
            }

            return new PipelineNode(Id ?? string.Empty, kind, Type ?? string.Empty, Config);
        }

        // A declared name (any case, surrounding whitespace ignored) or a declared ordinal
        // written as ASCII digits. Enum.TryParse alone also accepts undefined numbers
        // ("999", "-1"), signs and comma-joined names, which the Rust port rejects.
        private static bool TryParseKind(string? text, out PipelineNodeKind kind)
        {
            string trimmed = text?.Trim() ?? string.Empty;
            foreach (PipelineNodeKind candidate in Enum.GetValues<PipelineNodeKind>())
            {
                if (string.Equals(candidate.ToString(), trimmed, StringComparison.OrdinalIgnoreCase))
                {
                    kind = candidate;
                    return true;
                }
            }

            kind = default;
            if (!int.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out int ordinal)
                || !Enum.IsDefined((PipelineNodeKind)ordinal))
            {
                return false;
            }

            kind = (PipelineNodeKind)ordinal;
            return true;
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

    internal sealed class EdgeDto
    {
        public string? From { get; set; }
        public string? To { get; set; }

        public PipelineEdge ToModel() => new(From ?? string.Empty, To ?? string.Empty);

        public static EdgeDto FromModel(PipelineEdge edge) => new() { From = edge.From, To = edge.To };
    }
}

/// <summary>YamlDotNet static context for pipeline documents. Infrastructure only.</summary>
[EditorBrowsable(EditorBrowsableState.Never)]
[YamlStaticContext]
[YamlSerializable(typeof(PipelineDocument.PipelineDto))]
[YamlSerializable(typeof(PipelineDocument.NodeDto))]
[YamlSerializable(typeof(PipelineDocument.EdgeDto))]
public partial class PipelineYamlContext : StaticContext;

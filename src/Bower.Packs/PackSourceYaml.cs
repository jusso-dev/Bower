using System.ComponentModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Model = Bower.Packs;

namespace Bower.Packs.Yaml;

/// <summary>
/// Reflection-free YAML binding for <see cref="Model.PackSource"/> (Native AOT safe).
/// YamlDotNet's static context needs settable properties, so YAML binds to the mutable
/// mirrors below and is copied into the immutable model. Semantics match the former
/// reflection deserializer: camelCase keys, unknown keys fail, missing keys keep the model
/// defaults and explicit nulls stay null.
/// </summary>
internal static class PackSourceYamlReader
{
    private static readonly IDeserializer Deserializer = new StaticDeserializerBuilder(new PackSourceYamlContext())
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    public static Model.PackSource? Read(string yaml) =>
        Deserializer.Deserialize<PackSource?>(yaml)?.ToModel();
}

/// <summary>YamlDotNet static context for pack.yaml. Infrastructure only.</summary>
[EditorBrowsable(EditorBrowsableState.Never)]
[YamlStaticContext]
[YamlSerializable(typeof(PackSource))]
[YamlSerializable(typeof(PackSourceMetadata))]
public partial class PackSourceYamlContext : StaticContext;

internal sealed class PackSource
{
    public string? ApiVersion { get; set; }

    public string? Kind { get; set; }

    public PackSourceMetadata? Metadata { get; set; }

    public List<string> Policies { get; set; } = [];

    public string? PrivacyProfile { get; set; }

    public List<string> Parsers { get; set; } = [];

    public List<string> Detections { get; set; } = [];

    public List<string> Samples { get; set; } = [];

    public bool Dcr { get; set; }

    public Model.PackSource ToModel() => new()
    {
        ApiVersion = ApiVersion!,
        Kind = Kind!,
        Metadata = Metadata?.ToModel()!,
        Policies = Policies,
        PrivacyProfile = PrivacyProfile,
        Parsers = Parsers,
        Detections = Detections,
        Samples = Samples,
        Dcr = Dcr
    };
}

internal sealed class PackSourceMetadata
{
    public string? Id { get; set; }

    public string? Version { get; set; }

    public string? Name { get; set; }

    public string? Description { get; set; }

    public string? Owner { get; set; }

    public Model.PackSourceMetadata ToModel() => new()
    {
        Id = Id!,
        Version = Version!,
        Name = Name!,
        Description = Description,
        Owner = Owner!
    };
}

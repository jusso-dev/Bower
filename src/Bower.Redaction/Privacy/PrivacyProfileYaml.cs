using System.ComponentModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Model = Bower.Redaction.Privacy;

namespace Bower.Redaction.Privacy.Yaml;

/// <summary>
/// Reflection-free YAML binding for <see cref="Model.PrivacyProfileDocument"/> (Native AOT
/// safe). YamlDotNet's static context needs settable properties, so YAML binds to the
/// mutable mirrors below and is copied into the immutable model. Semantics match the former
/// reflection deserializer: camelCase keys, unknown keys fail, missing keys keep the model
/// defaults and explicit nulls stay null.
/// </summary>
internal static class PrivacyProfileYamlReader
{
    private static readonly IDeserializer Deserializer = new StaticDeserializerBuilder(new PrivacyProfileYamlContext())
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    public static Model.PrivacyProfileDocument? Read(string yaml) =>
        Deserializer.Deserialize<PrivacyProfileDocument?>(yaml)?.ToModel();
}

/// <summary>YamlDotNet static context for privacy profiles. Infrastructure only.</summary>
[EditorBrowsable(EditorBrowsableState.Never)]
[YamlStaticContext]
[YamlSerializable(typeof(PrivacyProfileDocument))]
[YamlSerializable(typeof(PrivacyProfileMetadata))]
[YamlSerializable(typeof(PrivacyFieldRuleDocument))]
[YamlSerializable(typeof(PrivacyCustomDetectorDocument))]
[YamlSerializable(typeof(PrivacyCustomDetectorTestsDocument))]
public partial class PrivacyProfileYamlContext : StaticContext;

internal sealed class PrivacyProfileDocument
{
    public string? ApiVersion { get; set; }

    public string? Kind { get; set; }

    public PrivacyProfileMetadata? Metadata { get; set; }

    public string? DefaultAction { get; set; }

    public Dictionary<string, string> Detectors { get; set; } = [];

    public List<string> Disabled { get; set; } = [];

    public List<string> EnableOptIn { get; set; } = [];

    public List<PrivacyFieldRuleDocument> Fields { get; set; } = [];

    public int? MaximumFieldLength { get; set; }

    public bool? EmitMetadata { get; set; }

    public List<PrivacyCustomDetectorDocument> CustomDetectors { get; set; } = [];

    public List<string> SecretFieldNames { get; set; } = [];

    public Model.PrivacyProfileDocument ToModel() => new()
    {
        ApiVersion = ApiVersion!,
        Kind = Kind!,
        Metadata = Metadata?.ToModel()!,
        DefaultAction = DefaultAction,
        Detectors = Detectors,
        Disabled = Disabled,
        EnableOptIn = EnableOptIn,
        Fields = Fields?.Select(field => field?.ToModel()!).ToList()!,
        MaximumFieldLength = MaximumFieldLength,
        EmitMetadata = EmitMetadata,
        CustomDetectors = CustomDetectors?.Select(detector => detector?.ToModel()!).ToList()!,
        SecretFieldNames = SecretFieldNames
    };
}

internal sealed class PrivacyProfileMetadata
{
    public string? Id { get; set; }

    public string? Version { get; set; }

    public string? Description { get; set; }

    public Model.PrivacyProfileMetadata ToModel() => new()
    {
        Id = Id!,
        Version = Version!,
        Description = Description
    };
}

internal sealed class PrivacyFieldRuleDocument
{
    public string? Path { get; set; }

    public string? Action { get; set; }

    public int? MaxLength { get; set; }

    public Model.PrivacyFieldRuleDocument ToModel() => new()
    {
        Path = Path!,
        Action = Action!,
        MaxLength = MaxLength
    };
}

internal sealed class PrivacyCustomDetectorDocument
{
    public string? Id { get; set; }

    public string? Description { get; set; }

    public string? Pattern { get; set; }

    public bool? IgnoreCase { get; set; }

    public bool? WholeWord { get; set; }

    public string? Action { get; set; }

    public PrivacyCustomDetectorTestsDocument? Tests { get; set; }

    public Model.PrivacyCustomDetectorDocument ToModel() => new()
    {
        Id = Id!,
        Description = Description,
        Pattern = Pattern!,
        IgnoreCase = IgnoreCase,
        WholeWord = WholeWord,
        Action = Action!,
        Tests = Tests?.ToModel()!
    };
}

internal sealed class PrivacyCustomDetectorTestsDocument
{
    public List<string>? Match { get; set; } = [];

    public List<string>? NoMatch { get; set; } = [];

    public Model.PrivacyCustomDetectorTestsDocument ToModel() => new()
    {
        Match = Match!,
        NoMatch = NoMatch!
    };
}

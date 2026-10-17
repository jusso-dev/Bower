using System.ComponentModel;
using System.Globalization;
using System.Text.Json.Serialization;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Model = Bower.PolicyEngine;

namespace Bower.PolicyEngine.Yaml;

/// <summary>
/// Reflection-free YAML binding for <see cref="Model.TelemetryPolicy"/> (Native AOT safe).
/// YamlDotNet's static context needs settable properties, so YAML binds to the mutable
/// mirrors below and is copied into the immutable model. Semantics match the former
/// reflection deserializer: camelCase keys, unknown keys fail, missing keys keep the model
/// defaults and explicit nulls stay null.
/// </summary>
internal static class PolicyYamlReader
{
    private static readonly IDeserializer Deserializer = new StaticDeserializerBuilder(new PolicyYamlContext())
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .WithTypeConverter(new DateOnlyYamlConverter())
        .Build();

    public static Model.TelemetryPolicy? Read(string yaml) =>
        Deserializer.Deserialize<TelemetryPolicy?>(yaml)?.ToModel();
}

/// <summary>Parses YAML scalars into <see cref="DateOnly"/>, as the reflection type converter did.</summary>
internal sealed class DateOnlyYamlConverter : IYamlTypeConverter
{
    public bool Accepts(Type type) => type == typeof(DateOnly) || type == typeof(DateOnly?);

    public object? ReadYaml(IParser parser, Type type, ObjectDeserializer rootDeserializer)
    {
        Scalar scalar = parser.Consume<Scalar>();
        if (type == typeof(DateOnly?) && scalar.IsPlainNull())
        {
            return null;
        }

        return DateOnly.Parse(scalar.Value, CultureInfo.InvariantCulture);
    }

    public void WriteYaml(IEmitter emitter, object? value, Type type, ObjectSerializer serializer) =>
        throw new NotSupportedException("Policies are never written as YAML.");
}

internal static class ScalarExtensions
{
    // The YAML 1.2 core schema null forms, as YamlDotNet's null node deserializer treats them.
    public static bool IsPlainNull(this Scalar scalar) =>
        scalar.Style == ScalarStyle.Plain
        && scalar.Value is "" or "~" or "null" or "Null" or "NULL";
}

/// <summary>YamlDotNet static context for policy documents. Infrastructure only.</summary>
[EditorBrowsable(EditorBrowsableState.Never)]
[YamlStaticContext]
[YamlSerializable(typeof(TelemetryPolicy))]
[YamlSerializable(typeof(PolicyMetadata))]
[YamlSerializable(typeof(PolicyMatch))]
[YamlSerializable(typeof(PolicyRequirements))]
[YamlSerializable(typeof(PolicyAction))]
[YamlSerializable(typeof(PolicyRouting))]
public partial class PolicyYamlContext : StaticContext;

internal sealed class TelemetryPolicy
{
    public string? ApiVersion { get; set; }

    public string? Kind { get; set; }

    public PolicyMetadata? Metadata { get; set; }

    public PolicyMatch? Match { get; set; }

    public PolicyRequirements? Requirements { get; set; }

    public PolicyAction? Decision { get; set; }

    public PolicyRouting? Routing { get; set; }

    public Model.TelemetryPolicy ToModel() => new()
    {
        ApiVersion = ApiVersion!,
        Kind = Kind!,
        Metadata = Metadata?.ToModel()!,
        Match = Match?.ToModel()!,
        Requirements = Requirements?.ToModel()!,
        Decision = Decision?.ToModel()!,
        Routing = Routing?.ToModel()
    };
}

internal sealed class PolicyMetadata
{
    public string? Id { get; set; }

    public string? Name { get; set; }

    public string? Version { get; set; }

    public string? Owner { get; set; }

    public DateOnly? ReviewDate { get; set; }

    public Model.PolicyMetadata ToModel() => new()
    {
        Id = Id!,
        Name = Name!,
        Version = Version!,
        Owner = Owner!,
        ReviewDate = ReviewDate
    };
}

internal sealed class PolicyMatch
{
    public List<string> EventCategories { get; set; } = [];

    public List<string> EventTypes { get; set; } = [];

    public Model.PolicyMatch ToModel() => new()
    {
        EventCategories = EventCategories,
        EventTypes = EventTypes
    };
}

internal sealed class PolicyRequirements
{
    public List<string> RequiredFields { get; set; } = [];

    public List<string> AtLeastOne { get; set; } = [];

    public List<string> RecommendedFields { get; set; } = [];

    public Model.PolicyRequirements ToModel() => new()
    {
        RequiredFields = RequiredFields,
        AtLeastOne = AtLeastOne,
        RecommendedFields = RecommendedFields
    };
}

internal sealed class PolicyAction
{
    public string? Action { get; set; }

    public int MinimumValueScore { get; set; }

    public bool NeverSample { get; set; }

    public Model.PolicyAction ToModel() => new()
    {
        Action = Action!,
        MinimumValueScore = MinimumValueScore,
        NeverSample = NeverSample
    };
}

internal sealed class PolicyRouting
{
    public string? Profile { get; set; }

    public string? Destination { get; set; }

    public Model.PolicyRouting ToModel() => new()
    {
        Profile = Profile,
        Destination = Destination
    };
}

/// <summary>
/// Policy hash input: <see cref="System.Text.Json.JsonSerializer"/> default options (the
/// former reflection call), source generated so the canonical bytes are unchanged.
/// </summary>
[JsonSerializable(typeof(Model.TelemetryPolicy))]
internal sealed partial class PolicyHashJsonContext : JsonSerializerContext;

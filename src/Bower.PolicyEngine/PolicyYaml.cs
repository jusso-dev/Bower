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
        .WithTypeConverter(new StrictScalarYamlConverter())
        .WithNodeTypeResolver(new CoreScalarTagNodeTypeResolver(), where => where.OnTop())
        .Build();

    public static Model.TelemetryPolicy? Read(string yaml)
    {
        try
        {
            return Deserializer.Deserialize<TelemetryPolicy?>(yaml)?.ToModel();
        }
        catch (InvalidCastException exception)
        {
            // A scalar document deserializes to its text and the root cast fails outside
            // YamlDotNet's own wrapping. Report it at the scalar like any other node.
            Parser parser = new(new StringReader(yaml));
            while (parser.MoveNext() && parser.Current is not Scalar)
            {
            }

            Mark start = parser.Current?.Start ?? Mark.Empty;
            throw new YamlException(start, start, "Exception during deserialization", exception);
        }
    }
}

/// <summary>
/// Core-schema tags on scalars (<c>!!str 5</c>, <c>!!int 5</c>) do not change the target
/// type: the property type and its converter decide, as for untagged text. Without this the
/// tag picks the CLR type and the property assignment fails with a cast error.
/// </summary>
internal sealed class CoreScalarTagNodeTypeResolver : INodeTypeResolver
{
    public bool Resolve(NodeEvent? nodeEvent, ref Type currentType) =>
        nodeEvent is Scalar scalar
        && !scalar.Tag.IsEmpty
        && scalar.Tag.Value.StartsWith("tag:yaml.org,2002:", StringComparison.Ordinal);
}

/// <summary>
/// Canonical scalars for the policy value types, so a policy means the same on every
/// parser, culture and machine. YamlDotNet's defaults follow YAML 1.1 (<c>yes</c>/<c>on</c>/<c>y</c>
/// booleans, <c>070</c> read as octal 56, hex, binary, base-60 and <c>_</c>-separated integers)
/// and <see cref="DateOnly.Parse(string)"/> accepts locale-shaped dates. Only the YAML 1.2
/// JSON-schema forms are accepted: <c>true</c>/<c>false</c>, decimal integers without a leading
/// zero or <c>+</c>, and ISO 8601 <c>yyyy-MM-dd</c> dates. A plain null keeps the CLR default,
/// as before. Anything else, including a mapping or sequence, fails the load at its line.
/// </summary>
internal sealed class StrictScalarYamlConverter : IYamlTypeConverter
{
    internal const string IntegerMessage = "Expected a decimal integer such as 70.";
    internal const string BooleanMessage = "Expected true or false.";
    internal const string DateMessage = "Expected an ISO 8601 date (yyyy-MM-dd).";

    public bool Accepts(Type type) =>
        type == typeof(int) || type == typeof(bool) || type == typeof(DateOnly?);

    public object? ReadYaml(IParser parser, Type type, ObjectDeserializer rootDeserializer)
    {
        string message = type == typeof(int) ? IntegerMessage
            : type == typeof(bool) ? BooleanMessage
            : DateMessage;
        ParsingEvent current = parser.Current ?? throw new YamlException(message);
        if (current is not Scalar)
        {
            throw new YamlException(current.Start, current.End, message);
        }

        Scalar scalar = parser.Consume<Scalar>();
        if (scalar.IsPlainNull())
        {
            return type == typeof(int) ? 0 : type == typeof(bool) ? false : null;
        }

        object? value = type == typeof(int) ? ParseInteger(scalar.Value)
            : type == typeof(bool) ? ParseBoolean(scalar.Value)
            : ParseDate(scalar.Value);
        return value ?? throw new YamlException(scalar.Start, scalar.End, message);
    }

    public void WriteYaml(IEmitter emitter, object? value, Type type, ObjectSerializer serializer) =>
        throw new NotSupportedException("Policies are never written as YAML.");

    /// <summary><c>-?(0|[1-9][0-9]*)</c> within <see cref="int"/> range.</summary>
    internal static object? ParseInteger(string text)
    {
        ReadOnlySpan<char> digits = text.StartsWith('-') ? text.AsSpan(1) : text.AsSpan();
        bool canonical = !digits.IsEmpty
            && (digits[0] != '0' || digits.Length == 1)
            && !digits.ContainsAnyExceptInRange('0', '9');
        return canonical
            && int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int value)
            ? value
            : null;
    }

    internal static object? ParseBoolean(string text) => text switch
    {
        "true" => true,
        "false" => false,
        _ => null
    };

    /// <summary>Exactly <c>yyyy-MM-dd</c>: four-digit year, two-digit month and day.</summary>
    internal static object? ParseDate(string text) =>
        text.Length == 10
        && text[4] == '-'
        && text[7] == '-'
        && !text.AsSpan(0, 4).ContainsAnyExceptInRange('0', '9')
        && !text.AsSpan(5, 2).ContainsAnyExceptInRange('0', '9')
        && !text.AsSpan(8, 2).ContainsAnyExceptInRange('0', '9')
        && DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date)
            ? date
            : null;
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
    private List<string>? eventActions;
    private List<string>? eventResults;
    private List<string>? eventSeverities;

    public List<string>? EventActions { get => eventActions; set => eventActions = value ?? throw new InvalidDataException("Null match predicates are not permitted."); }
    public List<string>? EventResults { get => eventResults; set => eventResults = value ?? throw new InvalidDataException("Null match predicates are not permitted."); }
    public List<string>? EventSeverities { get => eventSeverities; set => eventSeverities = value ?? throw new InvalidDataException("Null match predicates are not permitted."); }
    public List<string> EventCategories { get; set; } = [];

    public List<string> EventTypes { get; set; } = [];

    public Model.PolicyMatch ToModel() => new()
    {
        EventCategories = EventCategories,
        EventTypes = EventTypes,
        EventActions = EventActions,
        EventResults = EventResults,
        EventSeverities = EventSeverities
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

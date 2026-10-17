using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Bower.Contracts;

/// <summary>
/// Bower wire JSON: Web defaults (camelCase, case-sensitive here), nulls omitted, camelCase
/// string enums and a maximum depth of 32. Metadata is source generated, so serialization
/// is reflection-free and safe under trimming and Native AOT.
/// </summary>
public static class BowerJson
{
    /// <summary>Options for the contract types in <see cref="BowerJsonContext"/>.</summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions(BowerJsonContext.Default);

    /// <summary>Envelope metadata bound to <see cref="Options"/>.</summary>
    public static JsonTypeInfo<SecurityEventEnvelope> Envelope { get; } =
        (JsonTypeInfo<SecurityEventEnvelope>)Options.GetTypeInfo(typeof(SecurityEventEnvelope));

    /// <summary>
    /// Creates read-only options with Bower wire semantics over a source-generated resolver,
    /// for assemblies that serialize their own types the same way as the envelope.
    /// </summary>
    public static JsonSerializerOptions CreateOptions(
        IJsonTypeInfoResolver resolver,
        params JsonConverter[] converters)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(converters);

        JsonSerializerOptions options = new(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = false,
            WriteIndented = false,
            MaxDepth = 32,
            TypeInfoResolver = resolver
        };
        // The generic converters are the AOT-safe equivalent of
        // JsonStringEnumConverter(JsonNamingPolicy.CamelCase) for each contract enum.
        options.Converters.Add(CamelCase<EventResult>());
        options.Converters.Add(CamelCase<EventSeverity>());
        options.Converters.Add(CamelCase<ActorType>());
        options.Converters.Add(CamelCase<DecisionAction>());
        foreach (JsonConverter converter in converters)
        {
            options.Converters.Add(converter);
        }

        options.MakeReadOnly();
        return options;
    }

    /// <summary>A camelCase string converter for one enum type (AOT safe).</summary>
    public static JsonConverter CamelCase<TEnum>()
        where TEnum : struct, Enum =>
        new JsonStringEnumConverter<TEnum>(JsonNamingPolicy.CamelCase);
}

/// <summary>Source-generated metadata for the Bower event contracts.</summary>
[JsonSerializable(typeof(SecurityEventEnvelope))]
[JsonSerializable(typeof(JsonElement))]
public sealed partial class BowerJsonContext : JsonSerializerContext;

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Contracts;

/// <summary>
/// <see cref="JsonStringEnumConverter{TEnum}"/> that only accepts declared members.
/// Member names (any case) and the integer ordinals of declared members keep working, but
/// an undefined value such as <c>7</c>, a numeric string or a comma-joined list of names
/// is invalid JSON instead of an enum value that would be fingerprinted and queued.
/// Writing an undefined value throws for the same reason. Reflection-free and safe under
/// Native AOT.
/// </summary>
public sealed class DefinedEnumConverter<TEnum> : JsonConverterFactory
    where TEnum : struct, Enum
{
    private readonly JsonStringEnumConverter<TEnum> inner;

    /// <summary>Enum member names as declared (the <c>[JsonConverter]</c> attribute form).</summary>
    public DefinedEnumConverter()
        : this(null)
    {
    }

    public DefinedEnumConverter(JsonNamingPolicy? namingPolicy)
    {
        inner = new JsonStringEnumConverter<TEnum>(namingPolicy);
    }

    public override bool CanConvert(Type typeToConvert) => typeToConvert == typeof(TEnum);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        new Strict((JsonConverter<TEnum>)inner.CreateConverter(typeToConvert, options)!);

    private sealed class Strict(JsonConverter<TEnum> converter) : JsonConverter<TEnum>
    {
        public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? name = reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
            return Defined(converter.Read(ref reader, typeToConvert, options), name);
        }

        public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options) =>
            converter.Write(writer, Defined(value, null), options);

        public override TEnum ReadAsPropertyName(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            string? name = reader.GetString();
            return Defined(converter.ReadAsPropertyName(ref reader, typeToConvert, options), name);
        }

        public override void WriteAsPropertyName(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options) =>
            converter.WriteAsPropertyName(writer, Defined(value, null), options);

        /// <summary>
        /// The value must be declared, and text must be that member's name (any case): the
        /// numeric strings ("2") and comma-joined names ("success, failure" reads as
        /// Denied) that JsonStringEnumConverter also accepts are rejected.
        /// </summary>
        private static TEnum Defined(TEnum value, string? name) =>
            Enum.IsDefined(value)
            && (name is null || string.Equals(name, Enum.GetName(value), StringComparison.OrdinalIgnoreCase))
                ? value
                : throw new JsonException($"The value is not a defined {typeof(TEnum).Name} member.");
    }
}

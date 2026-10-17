using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Bower.Contracts;

namespace Bower.UnitTests;

/// <summary>Contract enums accept declared members only (default deny).</summary>
public sealed class ContractEnumTests
{
    [Theory]
    [InlineData("\"failure\"", EventResult.Failure)]
    [InlineData("\"FAILURE\"", EventResult.Failure)]
    [InlineData("2", EventResult.Failure)]
    [InlineData("0", EventResult.Unknown)]
    [InlineData("3", EventResult.Denied)]
    public void DeclaredNamesAndOrdinalsStillRead(string json, EventResult expected)
    {
        Assert.Equal(expected, JsonSerializer.Deserialize(json, TypeInfo<EventResult>()));
    }

    [Theory]
    [InlineData("4")]
    [InlineData("7")]
    [InlineData("-1")]
    [InlineData("\"7\"")]
    [InlineData("\"2\"")]
    [InlineData("\"success, failure\"")]
    [InlineData("\"bogus\"")]
    [InlineData("1.5")]
    public void UndefinedEventResultIsInvalidJson(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize(json, TypeInfo<EventResult>()));
    }

    [Fact]
    public void EveryContractEnumRejectsUndefinedValues()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize("5", TypeInfo<EventSeverity>()));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize("5", TypeInfo<ActorType>()));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize("7", TypeInfo<DecisionAction>()));
        Assert.Equal(EventSeverity.Critical, JsonSerializer.Deserialize("4", TypeInfo<EventSeverity>()));
        Assert.Equal(ActorType.Unknown, JsonSerializer.Deserialize("4", TypeInfo<ActorType>()));
        Assert.Equal(DecisionAction.DeadLetter, JsonSerializer.Deserialize("6", TypeInfo<DecisionAction>()));
    }

    [Fact]
    public void WireFormatOfDeclaredValuesIsUnchanged()
    {
        Assert.Equal("\"redactAndAccept\"", JsonSerializer.Serialize(DecisionAction.RedactAndAccept, TypeInfo<DecisionAction>()));
        Assert.Equal("\"failure\"", JsonSerializer.Serialize(EventResult.Failure, TypeInfo<EventResult>()));
        Assert.Equal("\"informational\"", JsonSerializer.Serialize(EventSeverity.Informational, TypeInfo<EventSeverity>()));
        Assert.Equal("\"system\"", JsonSerializer.Serialize(ActorType.System, TypeInfo<ActorType>()));
    }

    [Fact]
    public void UndefinedValuesAreNeverWritten()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize((EventResult)7, TypeInfo<EventResult>()));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(TestEvents.Now) with { EventSeverity = (EventSeverity)9 },
            BowerJson.Envelope));
    }

    [Fact]
    public void TypeAttributeConverterIsAlsoStrict()
    {
        // Options without the Bower converters fall back to the [JsonConverter] attribute:
        // member names as declared, still default deny.
        JsonSerializerOptions options = new() { TypeInfoResolver = BowerJsonContext.Default };
        Assert.Equal("\"Failure\"", JsonSerializer.Serialize(EventResult.Failure, options));
        Assert.Equal(EventResult.Denied, JsonSerializer.Deserialize<EventResult>("\"denied\"", options));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<EventResult>("7", options));
    }

    [Fact]
    public void EnvelopeWithUndefinedOrdinalIsInvalidJson()
    {
        string json = """{"schemaVersion":"1.0.0","eventId":"e6","timeGenerated":"2026-07-26T02:14:19Z","eventCategory":"c","eventType":"t","eventAction":"a","eventResult":7,"application":{"name":"App","environment":"prod"}}""";

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize(json, BowerJson.Envelope));
    }

    private static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)BowerJson.Options.GetTypeInfo(typeof(T));
}

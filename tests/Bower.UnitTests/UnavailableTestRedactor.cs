using Bower.Abstractions;

namespace Bower.UnitTests;

internal sealed class UnavailableTestRedactor(string mode) : IEventRedactor
{
    public const string SecretMarker = "redactor-private-marker";

    public RedactionResult Redact(string json) => mode switch
    {
        "throw" => throw new InvalidOperationException(SecretMarker),
        "failure" => new RedactionResult(false, null, [], [], SecretMarker),
        "missing" => new RedactionResult(true, null, [], [], SecretMarker),
        "damaged" => new RedactionResult(true, "{\"eventId\":\"synthetic-id\"}", [], [], null),
        _ => throw new ArgumentException("Unknown mode.")
    };
}

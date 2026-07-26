using System.Text.Json;
using Bower.Redaction;

namespace Bower.UnitTests;

public sealed class RedactionTests
{
    [Fact]
    public void Redact_RemovesDangerousFieldsAndMasksEmail()
    {
        const string json =
            """
            {
              "actor": {
                "email": "alice@example.test",
                "password": "do-not-store"
              },
              "http": {
                "request": {
                  "headers": {
                    "Authorization": "Bearer secret"
                  }
                }
              }
            }
            """;

        JsonEventRedactor redactor = new();
        Bower.Abstractions.RedactionResult result = redactor.Redact(json);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.RedactedJson);
        Assert.Contains("$.actor.password", result.RemovedPaths);
        Assert.Contains("$.http.request.headers", result.RemovedPaths);
        Assert.Contains("$.actor.email", result.MaskedPaths);
        using JsonDocument document = JsonDocument.Parse(result.RedactedJson);
        Assert.Equal(
            "a***@example.test",
            document.RootElement.GetProperty("actor").GetProperty("email").GetString());
        Assert.False(document.RootElement.GetProperty("actor").TryGetProperty("password", out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("[]")]
    [InlineData("{ invalid")]
    public void Redact_RejectsUnsafeDocument(string json)
    {
        JsonEventRedactor redactor = new();

        Bower.Abstractions.RedactionResult result = redactor.Redact(json);

        Assert.False(result.Succeeded);
        Assert.Null(result.RedactedJson);
    }
}

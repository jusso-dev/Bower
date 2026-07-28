using Bower.Redaction;

namespace Bower.UnitTests;

public sealed class SensitiveDataDetectorTests
{
    [Fact]
    public void ScanAndRedact_DetectsAwsKeyJwtAndEmail()
    {
        const string json =
            """
            {
              "awsKey": "AKIAIOSFODNN7EXAMPLE",
              "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
              "owner": "alice@example.test",
              "password": "do-not-store"
            }
            """;

        SensitiveDataDetector detector = new();
        SensitiveScanResult result = detector.ScanAndRedact(json);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Findings, item => item.Kind == SensitiveFindingKind.AwsAccessKey);
        Assert.Contains(result.Findings, item => item.Kind == SensitiveFindingKind.Jwt);
        Assert.Contains(result.Findings, item => item.Kind == SensitiveFindingKind.Email);
        Assert.Contains(result.Findings, item => item.Kind == SensitiveFindingKind.GenericSecret);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", result.RedactedJson);
        Assert.DoesNotContain("do-not-store", result.RedactedJson);
        Assert.Contains("a***@example.test", result.RedactedJson);
    }

    [Fact]
    public void ScanAndRedact_DetectsValidCreditCard()
    {
        // Visa test number that passes Luhn
        const string json = """{ "pan": "4111111111111111" }""";
        SensitiveDataDetector detector = new();
        SensitiveScanResult result = detector.ScanAndRedact(json);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Findings, item => item.Kind == SensitiveFindingKind.CreditCard);
        Assert.Contains("****-****-****-1111", result.RedactedJson);
    }
}

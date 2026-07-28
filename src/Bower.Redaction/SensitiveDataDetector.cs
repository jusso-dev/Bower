using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Abstractions;

namespace Bower.Redaction;

public enum SensitiveFindingKind
{
    AwsAccessKey,
    AwsSecretKey,
    PrivateKeyBlock,
    Jwt,
    CreditCard,
    Email,
    IpAddress,
    BearerToken,
    ConnectionString,
    GenericSecret
}

public sealed record SensitiveFinding(
    SensitiveFindingKind Kind,
    string Path,
    string Preview,
    string Action);

public sealed record SensitiveScanResult(
    bool Succeeded,
    string? RedactedJson,
    IReadOnlyList<SensitiveFinding> Findings,
    string? FailureCode);

public sealed partial class SensitiveDataDetector
{
    public const int MaximumPayloadBytes = 1_048_576;

    // Instance API mirrors JsonEventRedactor for DI wiring.
    private readonly int maximumPayloadBytes = MaximumPayloadBytes;

    public SensitiveScanResult ScanAndRedact(string json, bool maskInPlace = true)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new SensitiveScanResult(false, null, [], "empty-payload");
        }

        if (Encoding.UTF8.GetByteCount(json) > maximumPayloadBytes)
        {
            return new SensitiveScanResult(false, null, [], "payload-too-large");
        }

        try
        {
            JsonNode? root = JsonNode.Parse(
                json,
                documentOptions: new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
            if (root is not JsonObject rootObject)
            {
                return new SensitiveScanResult(false, null, [], "root-must-be-object");
            }

            List<SensitiveFinding> findings = [];
            Walk(rootObject, "$", findings, maskInPlace);
            return new SensitiveScanResult(true, rootObject.ToJsonString(), findings, null);
        }
        catch (JsonException)
        {
            return new SensitiveScanResult(false, null, [], "invalid-json");
        }
    }

    public RedactionResult ToRedactionResult(string json)
    {
        SensitiveScanResult scan = ScanAndRedact(json, maskInPlace: true);
        if (!scan.Succeeded || scan.RedactedJson is null)
        {
            return new RedactionResult(false, null, [], [], scan.FailureCode);
        }

        List<string> removed = scan.Findings
            .Where(item => item.Action == "removed")
            .Select(item => item.Path)
            .ToList();
        List<string> masked = scan.Findings
            .Where(item => item.Action == "masked")
            .Select(item => item.Path)
            .ToList();
        return new RedactionResult(true, scan.RedactedJson, removed, masked, null);
    }

    private static void Walk(
        JsonObject value,
        string parentPath,
        List<SensitiveFinding> findings,
        bool maskInPlace)
    {
        foreach ((string propertyName, JsonNode? child) in value.ToArray())
        {
            string path = $"{parentPath}.{propertyName}";
            string normalized = Normalize(propertyName);

            if (IsSecretName(normalized))
            {
                findings.Add(
                    new SensitiveFinding(
                        SensitiveFindingKind.GenericSecret,
                        path,
                        Preview(child?.ToString()),
                        "removed"));
                if (maskInPlace)
                {
                    value.Remove(propertyName);
                }

                continue;
            }

            if (child is JsonValue jsonValue && jsonValue.TryGetValue(out string? text) && text is not null)
            {
                foreach (SensitiveFinding finding in DetectInText(path, text))
                {
                    findings.Add(finding);
                    if (maskInPlace && finding.Action == "masked")
                    {
                        value[propertyName] = MaskValue(text, finding.Kind);
                    }
                }

                continue;
            }

            if (child is JsonObject childObject)
            {
                Walk(childObject, path, findings, maskInPlace);
            }
            else if (child is JsonArray array)
            {
                for (int index = 0; index < array.Count; index++)
                {
                    if (array[index] is JsonObject nested)
                    {
                        Walk(nested, $"{path}[{index}]", findings, maskInPlace);
                    }
                    else if (array[index] is JsonValue arrayValue &&
                             arrayValue.TryGetValue(out string? arrayText) &&
                             arrayText is not null)
                    {
                        foreach (SensitiveFinding finding in DetectInText($"{path}[{index}]", arrayText))
                        {
                            findings.Add(finding);
                            if (maskInPlace && finding.Action == "masked")
                            {
                                array[index] = MaskValue(arrayText, finding.Kind);
                            }
                        }
                    }
                }
            }
        }
    }

    private static IEnumerable<SensitiveFinding> DetectInText(string path, string text)
    {
        if (AwsAccessKeyRegex().IsMatch(text))
        {
            yield return new SensitiveFinding(
                SensitiveFindingKind.AwsAccessKey,
                path,
                Preview(text),
                "masked");
        }

        if (AwsSecretKeyRegex().IsMatch(text) || text.Contains("aws_secret_access_key", StringComparison.OrdinalIgnoreCase))
        {
            yield return new SensitiveFinding(
                SensitiveFindingKind.AwsSecretKey,
                path,
                Preview(text),
                "masked");
        }

        if (text.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal) ||
            text.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal))
        {
            yield return new SensitiveFinding(
                SensitiveFindingKind.PrivateKeyBlock,
                path,
                Preview(text),
                "masked");
        }

        if (JwtRegex().IsMatch(text))
        {
            yield return new SensitiveFinding(SensitiveFindingKind.Jwt, path, Preview(text), "masked");
        }

        if (text.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            yield return new SensitiveFinding(
                SensitiveFindingKind.BearerToken,
                path,
                Preview(text),
                "masked");
        }

        if (CreditCardRegex().IsMatch(text) && LooksLikeCreditCard(text))
        {
            yield return new SensitiveFinding(
                SensitiveFindingKind.CreditCard,
                path,
                Preview(text),
                "masked");
        }

        if (EmailRegex().IsMatch(text))
        {
            yield return new SensitiveFinding(SensitiveFindingKind.Email, path, Preview(text), "masked");
        }

        if (text.Contains("Connection String", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Password=", StringComparison.OrdinalIgnoreCase) &&
            text.Contains(';', StringComparison.Ordinal))
        {
            yield return new SensitiveFinding(
                SensitiveFindingKind.ConnectionString,
                path,
                Preview(text),
                "masked");
        }
    }

    private static bool IsSecretName(string normalized)
    {
        return normalized is "password" or "passwordhash" or "accesstoken" or "refreshtoken"
            or "bearertoken" or "apikeysecret" or "clientsecret" or "privatekey"
            or "connectionstring" or "authorization" or "cookie" or "cookies"
            or "credential" or "credentials" or "secret" or "apikey";
    }

    private static string MaskValue(string value, SensitiveFindingKind kind)
    {
        return kind switch
        {
            SensitiveFindingKind.Email => MaskEmail(value),
            SensitiveFindingKind.CreditCard => "****-****-****-" + DigitsOnly(value)[^4..],
            SensitiveFindingKind.AwsAccessKey => value.Length > 8 ? value[..4] + "********" + value[^2..] : "***",
            _ => "***REDACTED***"
        };
    }

    private static string MaskEmail(string value)
    {
        Match match = EmailRegex().Match(value);
        if (!match.Success)
        {
            return "***";
        }

        string email = match.Value;
        int at = email.IndexOf('@', StringComparison.Ordinal);
        return at <= 0 ? "***" : $"{email[0]}***{email[at..]}";
    }

    private static bool LooksLikeCreditCard(string value)
    {
        string digits = DigitsOnly(value);
        if (digits.Length is < 13 or > 19)
        {
            return false;
        }

        // Luhn
        int sum = 0;
        bool alt = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int n = digits[i] - '0';
            if (alt)
            {
                n *= 2;
                if (n > 9)
                {
                    n -= 9;
                }
            }

            sum += n;
            alt = !alt;
        }

        return sum % 10 == 0;
    }

    private static string DigitsOnly(string value) => string.Concat(value.Where(char.IsDigit));

    private static string Normalize(string value) =>
        string.Concat(value.Where(char.IsLetterOrDigit)).ToLowerInvariant();

    private static string Preview(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Length <= 12 ? "***" : value[..4] + "…";
    }

    [GeneratedRegex(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.CultureInvariant)]
    private static partial Regex AwsAccessKeyRegex();

    [GeneratedRegex(@"\b(?:aws)?_?secret_?(?:access)?_?key\b\s*[:=]\s*\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AwsSecretKeyRegex();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", RegexOptions.CultureInvariant)]
    private static partial Regex JwtRegex();

    [GeneratedRegex(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.CultureInvariant)]
    private static partial Regex CreditCardRegex();

    [GeneratedRegex(@"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EmailRegex();
}

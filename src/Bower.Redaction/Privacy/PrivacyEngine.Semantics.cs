using System.Text.Json.Nodes;

namespace Bower.Redaction.Privacy;

public sealed partial class PrivacyEngine
{
    // Only reviewed event/field pairs may carry before/after values. A secret need
    // not look like a token: ordinary password text must never reach persistence.
    private static void SanitizeChange(JsonObject root, List<AppliedFinding> findings)
    {
        if (root["change"] is not JsonObject change)
        {
            return;
        }

        bool allowed = root["eventType"] is JsonValue type
            && type.TryGetValue<string>(out string? eventType)
            && eventType == "role_membership_changed"
            && change["field"] is JsonValue field
            && field.TryGetValue<string>(out string? fieldName)
            && fieldName == "role";
        if (allowed)
        {
            return;
        }

        foreach (string name in new[] { "previousValue", "newValue" })
        {
            if (change.Remove(name))
            {
                findings.Add(new AppliedFinding(
                    DetectorIds.FieldNameSecret, DetectorCategories.FieldName, $"$.change.{name}",
                    PrivacyAction.Remove, Validated: true, SubKind: null));
            }
        }
    }

    // Deliberately discard all query/fragment values, not just familiar token keys.
    // Lexical handling preserves path spelling and is identical in both runtimes.
    private static string SafeUrl(string text, string path)
    {
        string name = NormalizeFieldName(path[(path.LastIndexOf('.') + 1)..]);
        bool absolute = text.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        if (!absolute && name is not ("path" or "url" or "uri" or "href" or "endpoint"
            or "requesturl" or "requesturi" or "redirecturl" or "redirecturi"))
        {
            return text;
        }

        if (text.Any(character => char.IsControl(character) || character == '\\'))
        {
            return "[redacted]";
        }

        int end = text.Length;
        foreach (string delimiter in new[] { "?", "#", "%3f", "%23" })
        {
            int index = text.IndexOf(delimiter, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                end = Math.Min(end, index);
            }
        }

        string safe = text[..end];
        int start = absolute ? safe.IndexOf("://", StringComparison.Ordinal) + 3
            : safe.StartsWith("//", StringComparison.Ordinal) ? 2 : -1;
        if (start >= 0)
        {
            int slash = safe.IndexOf('/', start);
            int authorityEnd = slash < 0 ? safe.Length : slash;
            string authority = safe[start..authorityEnd];
            // Encoded authority delimiters are ambiguous; retain no authority data.
            if (authority.Contains('%', StringComparison.Ordinal))
            {
                return "[redacted]";
            }

            int at = authority.LastIndexOf('@');
            authority = authority[(at + 1)..];
            // A truncated malformed URL must not turn a password into a host/port.
            if (authority.Length == 0 || authority.Any(char.IsWhiteSpace))
            {
                return "[redacted]";
            }

            int portStart;
            if (authority.StartsWith('['))
            {
                int close = authority.IndexOf(']');
                if (close < 0 || !System.Net.IPAddress.TryParse(authority[1..close], out _))
                {
                    return "[redacted]";
                }

                portStart = close + 1;
            }
            else
            {
                portStart = authority.IndexOf(':');
                if (portStart < 0)
                {
                    portStart = authority.Length;
                }
            }

            if (portStart < authority.Length && (authority[portStart] != ':'
                || portStart == 0 || portStart + 1 == authority.Length
                || !authority[(portStart + 1)..].All(char.IsAsciiDigit)))
            {
                return "[redacted]";
            }

            safe = safe[..start] + authority + safe[authorityEnd..];
        }
        else if (safe.Contains(':', StringComparison.Ordinal) || safe.Contains('@', StringComparison.Ordinal))
        {
            return "[redacted]";
        }

        return safe;
    }
}

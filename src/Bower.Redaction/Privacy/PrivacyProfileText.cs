using System.Globalization;

namespace Bower.Redaction.Privacy;

/// <summary>
/// Characters a privacy profile may not contain, checked identically by the C# and Rust
/// loaders so both accept and reject exactly the same documents: C0 controls other than
/// tab, line feed and carriage return; DEL and C1 controls (including NEL); the line and
/// paragraph separators; UTF-16 surrogates on their own; and YAML escapes of surrogates
/// (<c>\uD83D</c>, <c>\U0000D83D</c>), which the two YAML parsers decode differently.
/// Raw text is checked before parsing and every parsed string afterwards (escapes such as
/// <c>\x0C</c> or <c>\L</c> produce the characters only when parsed). This also keeps the
/// profile hash unambiguous: only CR, LF and CRLF remain as line endings.
/// </summary>
internal static class PrivacyProfileText
{
    public static void RequireSupportedRawText(string yaml)
    {
        for (int index = 0; index < yaml.Length; index++)
        {
            char current = yaml[index];
            if (char.IsHighSurrogate(current) && index + 1 < yaml.Length && char.IsLowSurrogate(yaml[index + 1]))
            {
                index++;
                continue;
            }

            if (IsUnsupported(current))
            {
                throw Unsupported(current);
            }

            if (current == '\\' && SurrogateEscape(yaml, index + 1) is { } escaped)
            {
                throw Unsupported(escaped);
            }
        }
    }

    public static void RequireSupportedValue(string? value)
    {
        if (value is null)
        {
            return;
        }

        for (int index = 0; index < value.Length; index++)
        {
            char current = value[index];
            if (char.IsHighSurrogate(current) && index + 1 < value.Length && char.IsLowSurrogate(value[index + 1]))
            {
                index++;
                continue;
            }

            if (IsUnsupported(current))
            {
                throw Unsupported(current);
            }
        }
    }

    private static bool IsUnsupported(char value) =>
        value is (< ' ' and not ('\t' or '\n' or '\r')) or (>= '\u007F' and <= '\u009F') or '\u2028' or '\u2029'
        || char.IsSurrogate(value);

    /// <summary>The code point of a <c>\uXXXX</c> or <c>\UXXXXXXXX</c> escape in the surrogate range.</summary>
    private static int? SurrogateEscape(string text, int index)
    {
        if (index >= text.Length || text[index] is not ('u' or 'U'))
        {
            return null;
        }

        int digits = text[index] == 'u' ? 4 : 8;
        if (index + 1 + digits > text.Length)
        {
            return null;
        }

        ReadOnlySpan<char> hex = text.AsSpan(index + 1, digits);
        foreach (char digit in hex)
        {
            if (!char.IsAsciiHexDigit(digit))
            {
                return null;
            }
        }

        long value = long.Parse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        return value is >= 0xD800 and <= 0xDFFF ? (int)value : null;
    }

    private static InvalidDataException Unsupported(int codePoint) =>
        new($"Privacy profile contains unsupported character U+{codePoint:X4}.");
}

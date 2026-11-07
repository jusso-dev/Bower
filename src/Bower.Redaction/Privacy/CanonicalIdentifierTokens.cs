using System.Buffers;
using System.Collections.Frozen;

namespace Bower.Redaction.Privacy;

/// <summary>
/// Canonical identifier tokens: a UUID in 8-4-4-4-12 form or a 32-hex-digit dashless GUID
/// (either case, any version), bounded by the start or end of the value or by a character
/// that is not an ASCII letter, digit, hyphen or underscore. A structured number detector
/// (Australian identifiers, card, bank account, IBAN and SWIFT numbers) cannot claim a span
/// that lies wholly inside one: random identifiers pass those checksums by chance (about 1
/// in 450 UUIDv4 for the TFN check), and no person writes a TFN, card number or IBAN as a
/// UUID. Every other detector, including secrets and custom detectors, still scans the token.
/// Mirrored by <c>rust/crates/bower-redaction/src/identifier_tokens.rs</c>.
/// </summary>
public static class CanonicalIdentifierTokens
{
    private const int GuidLength = 32;
    private const int UuidLength = 36;

    private static readonly SearchValues<char> HexDigits = SearchValues.Create("0123456789abcdefABCDEF");

    /// <summary>Detectors whose matches are dropped inside a canonical identifier token.</summary>
    public static FrozenSet<string> StructuredNumberDetectorIds { get; } = new[]
    {
        DetectorIds.Tfn,
        DetectorIds.Crn,
        DetectorIds.Medicare,
        DetectorIds.Ihi,
        DetectorIds.Passport,
        DetectorIds.DriverLicence,
        DetectorIds.Abn,
        DetectorIds.Acn,
        DetectorIds.Dva,
        DetectorIds.CreditCard,
        DetectorIds.BsbAccount,
        DetectorIds.Iban,
        DetectorIds.SwiftBic
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>True when <paramref name="token"/> is exactly a canonical UUID or dashless GUID.</summary>
    public static bool IsCanonicalIdentifier(ReadOnlySpan<char> token)
    {
        if (token.Length == GuidLength)
        {
            return !token.ContainsAnyExcept(HexDigits);
        }

        if (token.Length != UuidLength)
        {
            return false;
        }

        for (int index = 0; index < UuidLength; index++)
        {
            bool valid = index is 8 or 13 or 18 or 23 ? token[index] == '-' : char.IsAsciiHexDigit(token[index]);
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Start and end (exclusive) of every canonical identifier token in <paramref name="text"/>.</summary>
    public static List<(int Start, int End)> Find(ReadOnlySpan<char> text)
    {
        List<(int Start, int End)> found = [];
        int index = 0;
        while (index < text.Length)
        {
            if (!IsTokenCharacter(text[index]))
            {
                index++;
                continue;
            }

            int start = index;
            while (index < text.Length && IsTokenCharacter(text[index]))
            {
                index++;
            }

            if (IsCanonicalIdentifier(text[start..index]))
            {
                found.Add((start, index));
            }
        }

        return found;
    }

    /// <summary>
    /// Removes matches at or after <paramref name="from"/> that lie wholly inside a token,
    /// keeping order. <paramref name="tokens"/> must come from <see cref="Find"/> (disjoint and
    /// in order), so each match costs one binary search, not a scan of every token.
    /// </summary>
    /// <returns>Token ranges examined; tests use it to bound the work.</returns>
    public static int RemoveContained(List<(int Start, int End)> tokens, List<DetectionMatch> matches, int from)
    {
        if (tokens.Count == 0)
        {
            return 0;
        }

        int examined = 0;
        int kept = from;
        for (int index = from; index < matches.Count; index++)
        {
            DetectionMatch match = matches[index];
            if (!IsContained(tokens, match, ref examined))
            {
                matches[kept++] = match;
            }
        }

        matches.RemoveRange(kept, matches.Count - kept);
        return examined;
    }

    // Only the last token starting at or before the match can contain it.
    private static bool IsContained(List<(int Start, int End)> tokens, DetectionMatch match, ref int examined)
    {
        int low = 0;
        int high = tokens.Count;
        while (low < high)
        {
            examined++;
            int middle = low + ((high - low) / 2);
            if (tokens[middle].Start <= match.Start)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        return low > 0 && match.End <= tokens[low - 1].End;
    }

    private static bool IsTokenCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is '-' or '_';
}

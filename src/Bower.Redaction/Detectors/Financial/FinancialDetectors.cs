using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;
using Bower.Redaction.Validation;

namespace Bower.Redaction.Detectors.Financial;

public sealed partial class CreditCardDetector : ISensitiveDetector
{
    public string Id => DetectorIds.CreditCard;
    public string Category => DetectorCategories.Financial;

    public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        foreach (Match match in CardRegex().Matches(s))
        {
            string digits = ChecksumAlgorithms.DigitsOnly(match.Value);
            if (digits.Length is < 13 or > 19)
            {
                continue;
            }

            if (!ChecksumAlgorithms.Luhn(digits))
            {
                continue;
            }

            string? network = ClassifyNetwork(digits);
            if (network is null)
            {
                continue;
            }

            matches.Add(new DetectionMatch(
                Id,
                Category,
                match.Index,
                match.Length,
                Validated: true,
                SubKind: network));
        }
    }

    private static string? ClassifyNetwork(string digits)
    {
        if (digits[0] == '4' && digits.Length is 13 or 16 or 19)
        {
            return "Visa";
        }

        if (digits.Length == 16)
        {
            int prefix2 = (digits[0] - '0') * 10 + (digits[1] - '0');
            if (prefix2 is >= 51 and <= 55)
            {
                return "Mastercard";
            }

            if (digits.StartsWith("2221", StringComparison.Ordinal) ||
                digits.StartsWith("2720", StringComparison.Ordinal) ||
                (int.TryParse(digits.AsSpan(0, 4), out int p4) && p4 is >= 2221 and <= 2720))
            {
                return "Mastercard";
            }

            if (digits.StartsWith("6011", StringComparison.Ordinal) ||
                digits.StartsWith("65", StringComparison.Ordinal))
            {
                return "Discover";
            }

            if (digits.StartsWith("35", StringComparison.Ordinal))
            {
                return "JCB";
            }
        }

        if (digits.Length == 15 &&
            (digits.StartsWith("34", StringComparison.Ordinal) ||
             digits.StartsWith("37", StringComparison.Ordinal)))
        {
            return "Amex";
        }

        if (digits.Length is 14 or 16 &&
            (digits.StartsWith("36", StringComparison.Ordinal) ||
             digits.StartsWith("38", StringComparison.Ordinal) ||
             digits.StartsWith("300", StringComparison.Ordinal)))
        {
            return "Diners";
        }

        return null;
    }

    [GeneratedRegex(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.CultureInvariant)]
    private static partial Regex CardRegex();
}

public sealed partial class BsbAccountDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.BsbAccount;
    public override string Category => DetectorCategories.Financial;
    protected override Regex Pattern => BsbRegex();

    [GeneratedRegex(
        @"\b(\d{3}[-\s]?\d{3})(?:[/\s:]+|[\s]*account[\s#:]*)(\d{4,10})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BsbRegex();
}

public sealed partial class IbanDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Iban;
    public override string Category => DetectorCategories.Financial;
    protected override Regex Pattern => IbanRegex();
    protected override bool RequiresValidation => true;

    protected override bool Validate(ReadOnlySpan<char> matched)
    {
        string compact = string.Concat(matched.ToString().Where(c => !char.IsWhiteSpace(c))).ToUpperInvariant();
        if (compact.Length is < 15 or > 34)
        {
            return false;
        }

        // ISO 13616 mod-97 check
        string rearranged = compact[4..] + compact[..4];
        int total = 0;
        foreach (char c in rearranged)
        {
            if (c is >= '0' and <= '9')
            {
                total = ((total * 10) + (c - '0')) % 97;
            }
            else if (c is >= 'A' and <= 'Z')
            {
                int v = c - 'A' + 10;
                total = ((total * 10) + (v / 10)) % 97;
                total = ((total * 10) + (v % 10)) % 97;
            }
            else
            {
                return false;
            }
        }

        return total == 1;
    }

    [GeneratedRegex(@"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IbanRegex();
}

public sealed partial class SwiftBicDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.SwiftBic;
    public override string Category => DetectorCategories.Financial;
    protected override Regex Pattern => SwiftRegex();

    [GeneratedRegex(@"\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b", RegexOptions.CultureInvariant)]
    private static partial Regex SwiftRegex();
}

public sealed partial class PayIdDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.PayId;
    public override string Category => DetectorCategories.Financial;
    protected override Regex Pattern => PayIdRegex();

    // PayID is typically email, phone, or ABN — flag explicit PayID labels.
    [GeneratedRegex(
        @"\bPayID[:\s=]+(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PayIdRegex();

    public override void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        foreach (Match match in Pattern.Matches(s))
        {
            Group g = match.Groups.Count > 1 ? match.Groups[1] : match.Groups[0];
            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: false));
        }
    }
}

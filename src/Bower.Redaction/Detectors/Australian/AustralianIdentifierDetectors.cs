using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;
using Bower.Redaction.Validation;

namespace Bower.Redaction.Detectors.Australian;

public sealed partial class TfnDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Tfn;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => TfnRegex();
    protected override bool RequiresValidation => true;

    protected override bool Validate(ReadOnlySpan<char> matched)
    {
        string digits = ChecksumAlgorithms.DigitsOnly(matched);
        return ChecksumAlgorithms.IsValidTfn(digits);
    }

    // 8–9 digits with optional spaces/hyphens; context labels increase confidence but checksum is required.
    [GeneratedRegex(
        @"\b(?:TFN|Tax\s*File\s*Number)?[:\s#-]*(\d{3}[\s-]?\d{3}[\s-]?\d{2,3})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TfnRegex();

    public override void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        foreach (Match match in Pattern.Matches(s))
        {
            if (!match.Success)
            {
                continue;
            }

            // Prefer capture group of digits when present.
            Group digitsGroup = match.Groups.Count > 1 ? match.Groups[1] : match.Groups[0];
            string digits = ChecksumAlgorithms.DigitsOnly(digitsGroup.Value);
            if (!ChecksumAlgorithms.IsValidTfn(digits))
            {
                continue;
            }

            matches.Add(new DetectionMatch(
                Id,
                Category,
                digitsGroup.Index,
                digitsGroup.Length,
                Validated: true));
        }
    }
}

public sealed partial class CrnDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Crn;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => CrnRegex();

    [GeneratedRegex(
        @"\b(?:CRN|Customer\s*Reference\s*Number|Centrelink)?[:\s#-]*(\d{3}[\s-]?\d{3}[\s-]?\d{3}[A-Za-z])\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CrnRegex();

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
            if (!g.Success)
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: true));
        }
    }
}

public sealed partial class MedicareDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Medicare;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => MedicareRegex();
    protected override bool RequiresValidation => true;

    [GeneratedRegex(@"\b(\d{4}[\s-]?\d{5}[\s-]?\d)\b", RegexOptions.CultureInvariant)]
    private static partial Regex MedicareRegex();

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
            string digits = ChecksumAlgorithms.DigitsOnly(g.Value);
            if (!ChecksumAlgorithms.IsValidMedicare(digits))
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: true));
        }
    }
}

public sealed partial class IhiDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Ihi;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => IhiRegex();

    [GeneratedRegex(@"\b(800360\d{10})\b", RegexOptions.CultureInvariant)]
    private static partial Regex IhiRegex();

    public override void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        foreach (Match match in Pattern.Matches(s))
        {
            if (!ChecksumAlgorithms.IsValidIhi(match.Value))
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, match.Index, match.Length, Validated: true));
        }
    }
}

public sealed partial class PassportDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Passport;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => PassportRegex();

    // Common AU passport: letter + 7 digits, or 1–2 letters + 7 digits.
    [GeneratedRegex(
        @"\b(?:passport(?:\s*no(?:\.|mber)?)?|australian\s*passport)[:\s#-]*([A-Z]{1,2}\d{7})\b|\b([A-Z]\d{7})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PassportRegex();

    public override void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        bool hasContext = s.Contains("passport", StringComparison.OrdinalIgnoreCase);
        foreach (Match match in Pattern.Matches(s))
        {
            Group g = match.Groups[1].Success ? match.Groups[1]
                : match.Groups[2].Success ? match.Groups[2]
                : match.Groups[0];

            // Bare letter+7digits only when contextual label present (reduces false positives).
            if (!hasContext && match.Groups[2].Success && !match.Groups[1].Success)
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: false));
        }
    }
}

public sealed partial class AbnDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Abn;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => AbnRegex();

    [GeneratedRegex(@"\b(\d{2}[\s]?\d{3}[\s]?\d{3}[\s]?\d{3})\b", RegexOptions.CultureInvariant)]
    private static partial Regex AbnRegex();

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
            string digits = ChecksumAlgorithms.DigitsOnly(g.Value);
            if (digits.Length != 11 || !ChecksumAlgorithms.IsValidAbn(digits))
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: true));
        }
    }
}

public sealed partial class AcnDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Acn;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => AcnRegex();

    [GeneratedRegex(@"\b(\d{3}[\s]?\d{3}[\s]?\d{3})\b", RegexOptions.CultureInvariant)]
    private static partial Regex AcnRegex();

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
            string digits = ChecksumAlgorithms.DigitsOnly(g.Value);
            if (digits.Length != 9 || !ChecksumAlgorithms.IsValidAcn(digits))
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: true));
        }
    }
}

public sealed partial class DvaDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Dva;
    public override string Category => DetectorCategories.Australian;
    protected override Regex Pattern => DvaRegex();

    // State letter + 1–8 digits + optional war code letter.
    [GeneratedRegex(
        @"\b(?:DVA|Veterans'?\s*Affairs)?[:\s#-]*([NQVSTW][A-Z]?\d{4,8}[A-Z]?)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DvaRegex();

    public override void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        bool contextual = s.Contains("DVA", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Veteran", StringComparison.OrdinalIgnoreCase);

        foreach (Match match in Pattern.Matches(s))
        {
            Group g = match.Groups.Count > 1 && match.Groups[1].Success
                ? match.Groups[1]
                : match.Groups[0];

            if (!contextual && match.Value.Length < 6)
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: false));
        }
    }
}

/// <summary>
/// State-specific Australian driver licence format detectors.
/// Each state pattern is independently configurable via policy detector id suffix.
/// </summary>
public sealed partial class DriverLicenceDetector : ISensitiveDetector
{
    public string Id => DetectorIds.DriverLicence;
    public string Category => DetectorCategories.Australian;

    public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        bool hasContext = s.Contains("licence", StringComparison.OrdinalIgnoreCase)
            || s.Contains("license", StringComparison.OrdinalIgnoreCase)
            || s.Contains("driver", StringComparison.OrdinalIgnoreCase)
            || s.Contains("DLN", StringComparison.OrdinalIgnoreCase);

        if (!hasContext)
        {
            return;
        }

        foreach (Match match in LicenceRegex().Matches(s))
        {
            matches.Add(new DetectionMatch(
                Id,
                Category,
                match.Index,
                match.Length,
                Validated: false,
                SubKind: InferState(match.Value)));
        }
    }

    private static string? InferState(string value)
    {
        string compact = string.Concat(value.Where(c => !char.IsWhiteSpace(c)));
        // Heuristic format buckets — not authoritative registries.
        if (Regex.IsMatch(compact, @"^\d{8}$"))
        {
            return "NSW/VIC/QLD-like";
        }

        if (Regex.IsMatch(compact, @"^\d{6,7}$"))
        {
            return "SA/TAS/WA-like";
        }

        if (Regex.IsMatch(compact, @"^[A-Z]{2}\d{6}$", RegexOptions.IgnoreCase))
        {
            return "ACT-like";
        }

        if (Regex.IsMatch(compact, @"^\d{10}$"))
        {
            return "NT-like";
        }

        return "unknown";
    }

    // Broad licence token after contextual keywords only (context gated in Detect).
    [GeneratedRegex(
        @"\b([A-Z]{0,2}\d{6,10}[A-Z]?)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LicenceRegex();
}

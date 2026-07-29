using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors.Identity;

public sealed partial class EmailDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Email;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => EmailRegex();

    [GeneratedRegex(
        @"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EmailRegex();
}

public sealed partial class PhoneAuDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.PhoneAu;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => PhoneAuRegex();

    [GeneratedRegex(
        @"\b(?:\+?61[\s\-]?|0)(?:4\d{2}|[2378]\d)[\s\-]?\d{3}[\s\-]?\d{3}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex PhoneAuRegex();
}

public sealed partial class PhoneInternationalDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.PhoneInternational;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => PhoneIntlRegex();

    [GeneratedRegex(
        @"\b\+[1-9]\d{6,14}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex PhoneIntlRegex();
}

public sealed partial class DateOfBirthDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.DateOfBirth;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => DobRegex();

    [GeneratedRegex(
        @"\b(?:DOB|Date\s*of\s*Birth|born)[:\s#\-]*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DobRegex();

    public override void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        string s = text.ToString();
        foreach (Match match in Pattern.Matches(s))
        {
            Group g = match.Groups.Count > 1 && match.Groups[1].Success
                ? match.Groups[1]
                : match.Groups[0];
            matches.Add(new DetectionMatch(Id, Category, g.Index, g.Length, Validated: false));
        }
    }
}

public sealed partial class AddressDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Address;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => AddressRegex();

    // Opt-in: Australian-style street address heuristic.
    [GeneratedRegex(
        @"\b\d{1,5}\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,3}\s+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Court|Ct|Place|Pl|Lane|Ln|Parade|Pde|Crescent|Cres|Boulevard|Blvd|Highway|Hwy)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AddressRegex();
}

public sealed partial class GpsCoordinateDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Gps;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => GpsRegex();

    [GeneratedRegex(
        @"\b-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex GpsRegex();
}

public sealed partial class IpAddressDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.IpAddress;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => IpRegex();

    [GeneratedRegex(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex IpRegex();
}

public sealed partial class HostnameDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Hostname;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => HostRegex();

    [GeneratedRegex(
        @"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|au|local|internal|corp)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HostRegex();
}

public sealed partial class UsernameDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.Username;
    public override string Category => DetectorCategories.Identity;
    protected override Regex Pattern => UsernameRegex();

    [GeneratedRegex(
        @"\b(?:username|user\s*name|login)[:\s=]+([A-Za-z0-9._\-]{2,64})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UsernameRegex();

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

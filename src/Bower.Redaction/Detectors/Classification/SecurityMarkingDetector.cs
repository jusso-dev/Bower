using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors.Classification;

/// <summary>
/// Australian Government protective security markings (optional / opt-in).
/// AlertOnly by default — does not rewrite content unless policy overrides.
/// </summary>
public sealed partial class SecurityMarkingDetector : RegexDetectorBase
{
    public override string Id => DetectorIds.SecurityMarking;
    public override string Category => DetectorCategories.Classification;
    protected override Regex Pattern => MarkingRegex();

    protected override string? SubKind(ReadOnlySpan<char> matched) => matched.ToString().Trim().ToUpperInvariant();

    [GeneratedRegex(
        @"\b(?:OFFICIAL(?::\s*Sensitive)?|PROTECTED|SECRET|TOP\s*SECRET|CABINET-IN-CONFIDENCE)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MarkingRegex();
}

using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors;

/// <summary>Shared regex scan helper for value-based detectors.</summary>
public abstract partial class RegexDetectorBase : ISensitiveDetector
{
    public abstract string Id { get; }

    public abstract string Category { get; }

    protected abstract Regex Pattern { get; }

    protected virtual bool RequiresValidation => false;

    protected virtual bool Validate(ReadOnlySpan<char> matched) => true;

    protected virtual string? SubKind(ReadOnlySpan<char> matched) => null;

    public virtual void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        // Span-based enumeration: no string copy or Match objects per scanned value.
        foreach (ValueMatch match in Pattern.EnumerateMatches(text))
        {
            ReadOnlySpan<char> span = text.Slice(match.Index, match.Length);
            bool validated = !RequiresValidation || Validate(span);
            if (RequiresValidation && !validated)
            {
                continue;
            }

            matches.Add(new DetectionMatch(
                Id,
                Category,
                match.Index,
                match.Length,
                validated,
                SubKind(span)));
        }
    }

    /// <summary>
    /// Cheap span-based pre-check for overrides that need capture groups: most values
    /// never match, so they skip the string copy and <see cref="Match"/> allocations.
    /// </summary>
    protected bool MayMatch(ReadOnlySpan<char> text) => !text.IsEmpty && Pattern.IsMatch(text);
}

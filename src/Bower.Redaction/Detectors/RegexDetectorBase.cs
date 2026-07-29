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
        // Regex operates on string; single allocation only when content present.
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

            ReadOnlySpan<char> span = s.AsSpan(match.Index, match.Length);
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
}

using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors;

/// <summary>
/// Value detector for a privacy profile's custom detector. Runs wherever built-in value
/// detectors run, reports category <c>custom</c> and joins the engine's longest-first
/// overlap resolution. Matches that would split a UTF-16 surrogate pair are skipped
/// (the Rust engine scans scalars and cannot represent them), as are, with
/// <c>wholeWord</c>, matches next to an ASCII word character. Skipped matches do not
/// stop the scan: matching continues after them as usual.
/// </summary>
public sealed class CustomPatternDetector : ISensitiveDetector
{
    private const int MaximumWarmUpAttempts = 20;

    private readonly CustomDetectorDefinition definition;

    public CustomPatternDetector(CustomDetectorDefinition definition)
    {
        this.definition = definition ?? throw new ArgumentNullException(nameof(definition));
    }

    public string Id => definition.Id;

    public string Category => DetectorCategories.Custom;

    public CustomDetectorDefinition Definition => definition;

    public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches)
    {
        if (text.IsEmpty)
        {
            return;
        }

        foreach (ValueMatch match in definition.Regex.EnumerateMatches(text))
        {
            int start = match.Index;
            int end = match.Index + match.Length;
            if (match.Length == 0 || SplitsSurrogatePair(text, start) || SplitsSurrogatePair(text, end))
            {
                continue;
            }

            if (definition.WholeWord && (IsAsciiWordAt(text, start - 1) || IsAsciiWordAt(text, end)))
            {
                continue;
            }

            matches.Add(new DetectionMatch(Id, DetectorCategories.Custom, start, match.Length, Validated: true));
        }
    }

    /// <summary>
    /// True when this detector alone finds at least one match (profile tests). The
    /// non-backtracking engine builds its automaton lazily and keeps what it built when a
    /// match times out, so a cold first match is retried: the outcome then depends on the
    /// pattern and sample only, never on machine speed (the Rust engine has no timeout).
    /// </summary>
    /// <exception cref="RegexMatchTimeoutException">Still timing out after warm-up retries.</exception>
    public bool Matches(string sample)
    {
        ArgumentNullException.ThrowIfNull(sample);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                List<DetectionMatch> found = [];
                Detect(sample, "$", found);
                return found.Count > 0;
            }
            catch (RegexMatchTimeoutException) when (attempt < MaximumWarmUpAttempts)
            {
            }
        }
    }

    private static bool SplitsSurrogatePair(ReadOnlySpan<char> text, int index) =>
        index > 0 && index < text.Length && char.IsHighSurrogate(text[index - 1]) && char.IsLowSurrogate(text[index]);

    private static bool IsAsciiWordAt(ReadOnlySpan<char> text, int index) =>
        index >= 0 && index < text.Length && (char.IsAsciiLetterOrDigit(text[index]) || text[index] == '_');
}

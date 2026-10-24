using System.Text.RegularExpressions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors;

/// <summary>
/// Value detector for a privacy profile's custom detector. Runs wherever built-in value
/// detectors run, reports category <c>custom</c> and joins the engine's longest-first
/// overlap resolution (unless its action does not redact; see <see cref="PrivacyEngine"/>).
/// <c>wholeWord</c> is part of the compiled pattern (a non-word character or the start or
/// end of the text on both ends), and a
/// match whose start or end falls inside a UTF-16 surrogate pair is widened to the whole
/// pair. The Rust engine produces exactly the same spans.
/// </summary>
public sealed class CustomPatternDetector : ISensitiveDetector
{
    /// <summary>
    /// Longest value (UTF-16 units) custom detectors scan; a longer value fails the
    /// redaction (quarantine) while any custom detector is enabled.
    /// </summary>
    public const int MaximumScannedLength = 65_536;

    /// <summary>Most custom detector matches per event (all custom detectors and values).</summary>
    public const int MaximumMatchesPerEvent = 4_096;

    private const int MaximumWarmUpAttempts = 20;

    private static readonly string Sentinel = CustomPatternTranslator.WholeWordSentinel.ToString();

    private readonly CustomDetectorDefinition definition;

    public CustomPatternDetector(CustomDetectorDefinition definition)
    {
        this.definition = definition ?? throw new ArgumentNullException(nameof(definition));
    }

    public string Id => definition.Id;

    public string Category => DetectorCategories.Custom;

    public CustomDetectorDefinition Definition => definition;

    public void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches) =>
        Detect(text, matches, int.MaxValue);

    /// <summary>
    /// Appends at most <paramref name="limit"/> matches. Returns false (having stopped
    /// scanning) when the text holds more.
    /// </summary>
    public bool Detect(ReadOnlySpan<char> text, ICollection<DetectionMatch> matches, int limit)
    {
        ArgumentNullException.ThrowIfNull(matches);
        if (text.IsEmpty)
        {
            return true;
        }

        int found = 0;
        if (definition.WholeWord)
        {
            // The text is wrapped in the sentinel, so every match is one boundary character,
            // the redacted span, then one boundary character. The next search starts at the
            // span's last character, so a non-word last character can be the leading
            // boundary of an adjacent match.
            string wrapped = string.Concat(Sentinel, text, Sentinel);
            int start = 0;
            while (start < wrapped.Length)
            {
                ValueMatch match = default;
                bool success = false;
                foreach (ValueMatch candidate in definition.Regex.EnumerateMatches(wrapped, start))
                {
                    match = candidate;
                    success = true;
                    break;
                }

                if (!success)
                {
                    break;
                }

                if (++found > limit)
                {
                    return false;
                }

                // Wrapped offsets: the span is [Index + 1, Index + Length - 1); text offsets are one less.
                int end = match.Index + match.Length - 2;
                Add(text, match.Index, end, matches);
                start = end;
            }

            return true;
        }

        foreach (ValueMatch match in definition.Regex.EnumerateMatches(text))
        {
            if (++found > limit)
            {
                return false;
            }

            Add(text, match.Index, match.Index + match.Length, matches);
        }

        return true;
    }

    /// <summary>
    /// True when this detector alone finds at least one match (profile tests). The
    /// non-backtracking engine builds its automaton lazily and keeps what it built when a
    /// match times out, so a cold first match is retried: the outcome then depends on the
    /// pattern and sample only, never on machine speed (the Rust engine has no timeout).
    /// Running every sample at load also warms the automaton used at runtime.
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
                Detect(sample, found, int.MaxValue);
                return found.Count > 0;
            }
            catch (RegexMatchTimeoutException) when (attempt < MaximumWarmUpAttempts)
            {
            }
        }
    }

    private void Add(ReadOnlySpan<char> text, int start, int end, ICollection<DetectionMatch> matches)
    {
        // Widen outward so a surrogate pair is never split (redact the whole character).
        if (start > 0 && start < text.Length && char.IsHighSurrogate(text[start - 1]) && char.IsLowSurrogate(text[start]))
        {
            start--;
        }

        if (end > 0 && end < text.Length && char.IsHighSurrogate(text[end - 1]) && char.IsLowSurrogate(text[end]))
        {
            end++;
        }

        matches.Add(new DetectionMatch(Id, DetectorCategories.Custom, start, end - start, Validated: true));
    }
}

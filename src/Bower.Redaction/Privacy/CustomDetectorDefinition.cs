using System.Text.RegularExpressions;

namespace Bower.Redaction.Privacy;

/// <summary>
/// A validated custom detector (custom redaction rule) from a privacy profile's
/// <c>customDetectors:</c> section. Instances only come from <see cref="Create"/> (or the
/// profile loader), so the pattern is always restricted syntax, bounded in complexity,
/// never empty-matching and compiled with the non-backtracking engine.
/// </summary>
public sealed class CustomDetectorDefinition
{
    public const int MaximumIdLength = 64;
    public const int MaximumDescriptionLength = 256;
    public const int MaximumPatternLength = 512;

    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private CustomDetectorDefinition(
        string id,
        string? description,
        string pattern,
        string canonicalPattern,
        bool ignoreCase,
        bool wholeWord,
        PrivacyAction action,
        Regex regex)
    {
        Id = id;
        Description = description;
        Pattern = pattern;
        CanonicalPattern = canonicalPattern;
        IgnoreCase = ignoreCase;
        WholeWord = wholeWord;
        Action = action;
        Regex = regex;
    }

    /// <summary>Stable id, <c>custom.&lt;name&gt;</c>.</summary>
    public string Id { get; }

    public string? Description { get; }

    /// <summary>Pattern as written in the profile.</summary>
    public string Pattern { get; }

    /// <summary>Translated pattern that is compiled (identical in the Rust engine).</summary>
    public string CanonicalPattern { get; }

    public bool IgnoreCase { get; }

    /// <summary>Keep only matches not adjacent to an ASCII word character.</summary>
    public bool WholeWord { get; }

    public PrivacyAction Action { get; }

    internal Regex Regex { get; }

    /// <summary>Validates and compiles a custom detector.</summary>
    /// <exception cref="InvalidDataException">The definition is invalid; the message is safe to show.</exception>
    public static CustomDetectorDefinition Create(
        string id,
        string pattern,
        PrivacyAction action,
        bool ignoreCase = false,
        bool wholeWord = false,
        string? description = null)
    {
        RequireValidId(id);
        RequireValidDescription(id, description);
        (string canonical, Regex regex) = CompilePattern(id, pattern, ignoreCase);
        return new CustomDetectorDefinition(id, description, pattern, canonical, ignoreCase, wholeWord, action, regex);
    }

    internal static CustomDetectorDefinition FromValidated(
        string id,
        string? description,
        string pattern,
        string canonical,
        Regex regex,
        bool ignoreCase,
        bool wholeWord,
        PrivacyAction action) =>
        new(id, description, pattern, canonical, ignoreCase, wholeWord, action, regex);

    /// <summary><c>^custom\.[a-z0-9]+(-[a-z0-9]+)*$</c>, at most 64 characters.</summary>
    public static bool IsValidId(string? id)
    {
        const string prefix = "custom.";
        if (id is null || id.Length > MaximumIdLength || !id.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string name = id[prefix.Length..];
        return name.Length > 0
            && name.Split('-').All(part => part.Length > 0 && part.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9')));
    }

    internal static void RequireValidId(string? id)
    {
        if (!IsValidId(id))
        {
            throw new InvalidDataException(
                $"Custom detector id '{id}' must be custom.<name> using lowercase letters, digits and hyphens (at most 64 characters).");
        }
    }

    internal static void RequireValidDescription(string id, string? description)
    {
        if (description is { Length: > MaximumDescriptionLength })
        {
            throw new InvalidDataException($"Custom detector '{id}' description must be at most 256 characters.");
        }
    }

    internal static (string Canonical, Regex Regex) CompilePattern(string id, string? pattern, bool ignoreCase)
    {
        if (pattern is not { Length: > 0 and <= MaximumPatternLength })
        {
            throw new InvalidDataException($"Custom detector '{id}' pattern must be 1-512 characters.");
        }

        CustomPatternTranslation translation;
        try
        {
            translation = CustomPatternTranslator.Translate(pattern, ignoreCase);
        }
        catch (CustomPatternSyntaxException exception)
        {
            throw new InvalidDataException(
                $"Custom detector '{id}' pattern has unsupported syntax at position {exception.Position}: {exception.Reason}.",
                exception);
        }

        if (translation.Complexity > CustomPatternTranslator.MaximumComplexity)
        {
            throw new InvalidDataException($"Custom detector '{id}' pattern is too complex.");
        }

        if (translation.MatchesEmpty)
        {
            throw new InvalidDataException($"Custom detector '{id}' pattern must not match an empty string.");
        }

        try
        {
            Regex regex = new(
                translation.CanonicalPattern,
                RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
                MatchTimeout);
            return (translation.CanonicalPattern, regex);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or InvalidOperationException)
        {
            throw new InvalidDataException($"Custom detector '{id}' pattern is too complex.", exception);
        }
    }
}

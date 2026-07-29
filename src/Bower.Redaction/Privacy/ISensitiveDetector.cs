namespace Bower.Redaction.Privacy;

/// <summary>
/// Pluggable sensitive-data detector. Runtime must stay deterministic:
/// compiled patterns, checksums, structure and entropy — no AI at runtime.
/// </summary>
public interface ISensitiveDetector
{
    /// <summary>Stable id used in policy and metadata (e.g. <c>au.tfn</c>).</summary>
    string Id { get; }

    /// <summary>Module category (australian, financial, secrets, …).</summary>
    string Category { get; }

    /// <summary>
    /// Scan <paramref name="text"/> and append matches to <paramref name="matches"/>.
    /// Implementations must not allocate when no match is found where practical.
    /// </summary>
    void Detect(ReadOnlySpan<char> text, string path, ICollection<DetectionMatch> matches);
}

/// <summary>
/// Detector that also decides whole JSON properties by field name
/// (password, authorization, …) rather than value content.
/// </summary>
public interface IFieldNameDetector
{
    string Id { get; }

    string Category { get; }

    /// <summary>Returns true when the normalised field name should be treated as secret.</summary>
    bool MatchesFieldName(string normalizedFieldName);
}

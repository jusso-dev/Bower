namespace Bower.Redaction.Privacy;

/// <summary>
/// Sanitisation summary attached to processed events.
/// Must never contain original sensitive values.
/// </summary>
public sealed record PrivacyMetadata(
    IReadOnlyList<string> Detected,
    IReadOnlyDictionary<string, string> Actions)
{
    public static PrivacyMetadata Empty { get; } = new([], new Dictionary<string, string>());

    public bool HasFindings => Detected.Count > 0;
}

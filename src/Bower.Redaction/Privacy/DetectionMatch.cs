namespace Bower.Redaction.Privacy;

/// <summary>
/// A single sensitive span inside a field value.
/// Indices are UTF-16 char offsets into the original string.
/// </summary>
public readonly record struct DetectionMatch(
    string DetectorId,
    string Category,
    int Start,
    int Length,
    bool Validated,
    string? SubKind = null)
{
    public int End => Start + Length;
}

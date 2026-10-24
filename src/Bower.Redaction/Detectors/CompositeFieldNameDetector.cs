using Bower.Redaction.Privacy;

namespace Bower.Redaction.Detectors;

/// <summary>
/// Adds a privacy profile's secret field names to an existing field-name detector. A
/// property whose normalised name equals a configured name is handled exactly like the
/// inner detector's matches: same detector id, category and action resolution.
/// </summary>
public sealed class CompositeFieldNameDetector : IFieldNameDetector
{
    private readonly IFieldNameDetector inner;
    private readonly HashSet<string> names;

    /// <param name="inner">Detector whose id, category and matches are kept.</param>
    /// <param name="normalizedNames">Names already normalised with <see cref="FieldNameNormalizer.Normalize"/>.</param>
    public CompositeFieldNameDetector(IFieldNameDetector inner, IEnumerable<string> normalizedNames)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        ArgumentNullException.ThrowIfNull(normalizedNames);
        names = new HashSet<string>(normalizedNames, StringComparer.Ordinal);
    }

    public string Id => inner.Id;

    public string Category => inner.Category;

    public bool MatchesFieldName(string normalizedFieldName) =>
        (!string.IsNullOrEmpty(normalizedFieldName) && names.Contains(normalizedFieldName))
        || inner.MatchesFieldName(normalizedFieldName);
}

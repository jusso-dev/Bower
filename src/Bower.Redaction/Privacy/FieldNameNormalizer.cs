namespace Bower.Redaction.Privacy;

/// <summary>Field-name normalisation used by field-name secret detection.</summary>
public static class FieldNameNormalizer
{
    /// <summary>
    /// Letters and digits only, lower-cased invariantly. Surrogates are not letters or
    /// digits here, so per-char invariant lowering equals string.ToLowerInvariant.
    /// Returns the input unchanged (no allocation) when it is already normalised.
    /// </summary>
    public static string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Span<char> buffer = value.Length <= 256 ? stackalloc char[value.Length] : new char[value.Length];
        int length = 0;
        bool changed = false;
        foreach (char character in value)
        {
            if (!char.IsLetterOrDigit(character))
            {
                changed = true;
                continue;
            }

            char lower = char.ToLowerInvariant(character);
            changed |= lower != character;
            buffer[length++] = lower;
        }

        return changed ? new string(buffer[..length]) : value;
    }
}

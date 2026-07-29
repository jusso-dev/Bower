namespace Bower.Redaction.Validation;

/// <summary>
/// Deterministic checksum validators for regulated identifiers and payment data.
/// No network I/O; pure functions only.
/// </summary>
public static class ChecksumAlgorithms
{
    private static readonly int[] TfnWeights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    private static readonly int[] AbnWeights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    private static readonly int[] MedicareWeights = [1, 3, 7, 9, 1, 3, 7, 9];

    public static bool Luhn(ReadOnlySpan<char> digits)
    {
        if (digits.IsEmpty)
        {
            return false;
        }

        int sum = 0;
        bool alternate = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            char c = digits[i];
            if (c is < '0' or > '9')
            {
                return false;
            }

            int n = c - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9)
                {
                    n -= 9;
                }
            }

            sum += n;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }

    /// <summary>
    /// ATO TFN algorithm. Accepts 8 or 9 digit numbers (8-digit treated as leading zero).
    /// </summary>
    public static bool IsValidTfn(ReadOnlySpan<char> digits)
    {
        Span<char> padded = stackalloc char[9];
        if (digits.Length == 8)
        {
            padded[0] = '0';
            digits.CopyTo(padded[1..]);
        }
        else if (digits.Length == 9)
        {
            digits.CopyTo(padded);
        }
        else
        {
            return false;
        }

        int sum = 0;
        for (int i = 0; i < 9; i++)
        {
            char c = padded[i];
            if (c is < '0' or > '9')
            {
                return false;
            }

            sum += (c - '0') * TfnWeights[i];
        }

        return sum % 11 == 0;
    }

    /// <summary>Australian Business Number (11 digits).</summary>
    public static bool IsValidAbn(ReadOnlySpan<char> digits)
    {
        if (digits.Length != 11)
        {
            return false;
        }

        int first = digits[0] - '0';
        if (first is < 0 or > 9)
        {
            return false;
        }

        int sum = (first - 1) * AbnWeights[0];
        for (int i = 1; i < 11; i++)
        {
            char c = digits[i];
            if (c is < '0' or > '9')
            {
                return false;
            }

            sum += (c - '0') * AbnWeights[i];
        }

        return sum % 89 == 0;
    }

    /// <summary>Australian Company Number (9 digits).</summary>
    public static bool IsValidAcn(ReadOnlySpan<char> digits)
    {
        if (digits.Length != 9)
        {
            return false;
        }

        int sum = 0;
        for (int i = 0; i < 8; i++)
        {
            char c = digits[i];
            if (c is < '0' or > '9')
            {
                return false;
            }

            sum += (c - '0') * (8 - i);
        }

        char check = digits[8];
        if (check is < '0' or > '9')
        {
            return false;
        }

        int expected = (10 - (sum % 10)) % 10;
        return check - '0' == expected;
    }

    /// <summary>
    /// Medicare card number: 10 digits (8 body + check + issue).
    /// First digit must be 2–6.
    /// </summary>
    public static bool IsValidMedicare(ReadOnlySpan<char> digits)
    {
        if (digits.Length != 10)
        {
            return false;
        }

        char first = digits[0];
        if (first is < '2' or > '6')
        {
            return false;
        }

        int sum = 0;
        for (int i = 0; i < 8; i++)
        {
            char c = digits[i];
            if (c is < '0' or > '9')
            {
                return false;
            }

            sum += (c - '0') * MedicareWeights[i];
        }

        char check = digits[8];
        char issue = digits[9];
        if (check is < '0' or > '9' || issue is < '1' or > '9')
        {
            return false;
        }

        return (sum % 10) == (check - '0');
    }

    /// <summary>
    /// Individual Healthcare Identifier: 16 digits starting with 800360, Luhn check.
    /// </summary>
    public static bool IsValidIhi(ReadOnlySpan<char> digits)
    {
        if (digits.Length != 16)
        {
            return false;
        }

        ReadOnlySpan<char> prefix = digits[..6];
        if (!prefix.SequenceEqual("800360"))
        {
            return false;
        }

        return Luhn(digits);
    }

    public static string DigitsOnly(ReadOnlySpan<char> value)
    {
        Span<char> buffer = stackalloc char[value.Length];
        int count = 0;
        foreach (char c in value)
        {
            if (c is >= '0' and <= '9')
            {
                buffer[count++] = c;
            }
        }

        return new string(buffer[..count]);
    }

    public static int CountDigits(ReadOnlySpan<char> value)
    {
        int count = 0;
        foreach (char c in value)
        {
            if (c is >= '0' and <= '9')
            {
                count++;
            }
        }

        return count;
    }
}

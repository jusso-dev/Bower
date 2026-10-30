using System.Globalization;
using System.Text;

namespace Bower.Pipeline.Transforms;

/// <summary>
/// Timestamp parsing for <c>parse_timestamp</c>: fixed, named formats with exact grammars and
/// integer tick arithmetic (100 ns since 0001-01-01T00:00:00Z), so both runtimes agree. No
/// culture, time zone database or clock is consulted; RFC 3164 infers its missing year from
/// the explicit evaluation time only.
/// </summary>
internal static class TransformTime
{
    public static readonly string[] Formats =
        ["rfc3339", "rfc3164", "common_log", "unix_seconds", "unix_milliseconds", "unix_microseconds"];

    private const long TicksPerSecond = 10_000_000;
    private const long TicksPerMinute = 60 * TicksPerSecond;
    private const long TicksPerDay = 86_400 * TicksPerSecond;
    private const long UnixEpochTicks = 621_355_968_000_000_000;
    private const long MaximumTicks = 3_155_378_975_999_999_999;

    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    /// <summary>Canonical UTC text: <c>yyyy-MM-ddTHH:mm:ss[.fffffff]Z</c>, trailing fraction zeros trimmed.</summary>
    public static string Format(long ticks)
    {
        long days = ticks / TicksPerDay;
        long remainder = ticks % TicksPerDay;
        (long year, long month, long day) = CivilFromDays(days);
        long seconds = remainder / TicksPerSecond;
        long fraction = remainder % TicksPerSecond;
        StringBuilder text = new();
        text.Append(CultureInfo.InvariantCulture, $"{year:D4}-{month:D2}-{day:D2}T{seconds / 3600:D2}:{seconds / 60 % 60:D2}:{seconds % 60:D2}");
        if (fraction > 0)
        {
            text.Append('.').Append(fraction.ToString("D7", CultureInfo.InvariantCulture).TrimEnd('0'));
        }

        return text.Append('Z').ToString();
    }

    /// <summary>Ticks for the value, or null when it does not match the format or is out of range.</summary>
    public static long? Parse(string format, TransformValue value, long evaluationTicks)
    {
        if (format.StartsWith("unix_", StringComparison.Ordinal))
        {
            long? number = value.Kind == TransformKind.Int ? value.Int : UnixText(value.Text);
            long factor = format switch
            {
                "unix_seconds" => TicksPerSecond,
                "unix_milliseconds" => 10_000,
                _ => 10
            };
            if (number is not { } count || count < -(UnixEpochTicks / factor) || count > (MaximumTicks - UnixEpochTicks) / factor)
            {
                return null;
            }

            return UnixEpochTicks + (count * factor);
        }

        string text = value.Text;
        return format switch
        {
            "rfc3339" => Rfc3339(text),
            "rfc3164" => Rfc3164(text, evaluationTicks),
            _ => CommonLog(text)
        };
    }

    private static long? UnixText(string text)
    {
        int start = text.StartsWith('-') ? 1 : 0;
        if (text.Length - start is < 1 or > 19 || !AllDigits(text, start, text.Length - start))
        {
            return null;
        }

        return long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long value) ? value : null;
    }

    // YYYY-MM-DD(T|t| )hh:mm:ss(.f{1,9})?(Z|z|(+|-)hh:mm)
    private static long? Rfc3339(string text)
    {
        if (text.Length < 20
            || !Digits(text, 0, 4, out long year) || text[4] != '-'
            || !Digits(text, 5, 2, out long month) || text[7] != '-'
            || !Digits(text, 8, 2, out long day) || text[10] is not ('T' or 't' or ' ')
            || !Digits(text, 11, 2, out long hour) || text[13] != ':'
            || !Digits(text, 14, 2, out long minute) || text[16] != ':'
            || !Digits(text, 17, 2, out long second))
        {
            return null;
        }

        int position = 19;
        long fraction = 0;
        if (text[position] == '.')
        {
            int start = ++position;
            while (position < text.Length && char.IsAsciiDigit(text[position]))
            {
                position++;
            }

            int digits = position - start;
            if (digits is < 1 or > 9)
            {
                return null;
            }

            string kept = text.Substring(start, Math.Min(digits, 7)).PadRight(7, '0');
            fraction = long.Parse(kept, CultureInfo.InvariantCulture);
        }

        long offsetMinutes;
        if (position == text.Length - 1 && text[position] is 'Z' or 'z')
        {
            offsetMinutes = 0;
        }
        else if (position == text.Length - 6 && text[position] is '+' or '-'
            && Digits(text, position + 1, 2, out long offsetHour) && text[position + 3] == ':'
            && Digits(text, position + 4, 2, out long offsetMinute) && offsetHour <= 23 && offsetMinute <= 59)
        {
            offsetMinutes = ((offsetHour * 60) + offsetMinute) * (text[position] == '-' ? -1 : 1);
        }
        else
        {
            return null;
        }

        return Ticks(year, month, day, hour, minute, second) is { } local
            ? InRange(local + fraction - (offsetMinutes * TicksPerMinute))
            : null;
    }

    // Mmm dd hh:mm:ss or Mmm  d hh:mm:ss, in UTC, year from the evaluation time.
    private static long? Rfc3164(string text, long evaluationTicks)
    {
        if (text.Length != 15 || text[3] != ' ' || text[6] != ' ' || text[9] != ':' || text[12] != ':')
        {
            return null;
        }

        int month = Array.IndexOf(Months, text[..3]) + 1;
        long day;
        if (text[4] == ' ')
        {
            if (!Digits(text, 5, 1, out day))
            {
                return null;
            }
        }
        else if (!Digits(text, 4, 2, out day))
        {
            return null;
        }

        if (month == 0
            || !Digits(text, 7, 2, out long hour)
            || !Digits(text, 10, 2, out long minute)
            || !Digits(text, 13, 2, out long second))
        {
            return null;
        }

        long year = CivilFromDays(evaluationTicks / TicksPerDay).Year;
        long? candidate = Ticks(year, month, day, hour, minute, second);
        if (candidate is null || candidate > evaluationTicks + TicksPerDay)
        {
            candidate = Ticks(year - 1, month, day, hour, minute, second);
        }

        return candidate;
    }

    // dd/Mmm/yyyy:hh:mm:ss (+|-)hhmm
    private static long? CommonLog(string text)
    {
        if (text.Length != 26 || text[2] != '/' || text[6] != '/' || text[11] != ':' || text[14] != ':'
            || text[17] != ':' || text[20] != ' ' || text[21] is not ('+' or '-')
            || !Digits(text, 0, 2, out long day)
            || !Digits(text, 7, 4, out long year)
            || !Digits(text, 12, 2, out long hour)
            || !Digits(text, 15, 2, out long minute)
            || !Digits(text, 18, 2, out long second)
            || !Digits(text, 22, 2, out long offsetHour)
            || !Digits(text, 24, 2, out long offsetMinute)
            || offsetHour > 23 || offsetMinute > 59)
        {
            return null;
        }

        int month = Array.IndexOf(Months, text[3..6]) + 1;
        long offsetMinutes = ((offsetHour * 60) + offsetMinute) * (text[21] == '-' ? -1 : 1);
        return month > 0 && Ticks(year, month, day, hour, minute, second) is { } local
            ? InRange(local - (offsetMinutes * TicksPerMinute))
            : null;
    }

    private static long? InRange(long ticks) => ticks is >= 0 and <= MaximumTicks ? ticks : null;

    private static long? Ticks(long year, long month, long day, long hour, long minute, long second)
    {
        if (year is < 1 or > 9999 || month is < 1 or > 12 || day < 1 || day > DaysInMonth(year, month)
            || hour > 23 || minute > 59 || second > 59)
        {
            return null;
        }

        return (DaysFromCivil(year, month, day) * TicksPerDay) + (((hour * 3600) + (minute * 60) + second) * TicksPerSecond);
    }

    private static long DaysInMonth(long year, long month) => month switch
    {
        2 => (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 ? 29 : 28,
        4 or 6 or 9 or 11 => 30,
        _ => 31
    };

    // Days since 0001-01-01 (proleptic Gregorian), after H. Hinnant's days_from_civil.
    private static long DaysFromCivil(long year, long month, long day)
    {
        year -= month <= 2 ? 1 : 0;
        long era = year / 400;
        long yearOfEra = year - (era * 400);
        long dayOfYear = ((153 * (month > 2 ? month - 3 : month + 9)) + 2) / 5 + day - 1;
        long dayOfEra = (yearOfEra * 365) + (yearOfEra / 4) - (yearOfEra / 100) + dayOfYear;
        return (era * 146_097) + dayOfEra - 306;
    }

    private static (long Year, long Month, long Day) CivilFromDays(long days)
    {
        long shifted = days + 306;
        long era = shifted / 146_097;
        long dayOfEra = shifted - (era * 146_097);
        long yearOfEra = (dayOfEra - (dayOfEra / 1460) + (dayOfEra / 36_524) - (dayOfEra / 146_096)) / 365;
        long dayOfYear = dayOfEra - ((365 * yearOfEra) + (yearOfEra / 4) - (yearOfEra / 100));
        long monthPart = ((5 * dayOfYear) + 2) / 153;
        long day = dayOfYear - (((153 * monthPart) + 2) / 5) + 1;
        long month = monthPart < 10 ? monthPart + 3 : monthPart - 9;
        long year = yearOfEra + (era * 400) + (month <= 2 ? 1 : 0);
        return (year, month, day);
    }

    private static bool Digits(string text, int start, int count, out long value)
    {
        value = 0;
        if (start + count > text.Length || !AllDigits(text, start, count))
        {
            return false;
        }

        for (int index = start; index < start + count; index++)
        {
            value = (value * 10) + (text[index] - '0');
        }

        return true;
    }

    private static bool AllDigits(string text, int start, int count)
    {
        for (int index = start; index < start + count; index++)
        {
            if (!char.IsAsciiDigit(text[index]))
            {
                return false;
            }
        }

        return true;
    }
}

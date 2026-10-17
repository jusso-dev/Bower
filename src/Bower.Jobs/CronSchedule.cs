namespace Bower.Jobs;

/// <summary>Standard schedules, written as five-field cron expressions (UTC).</summary>
public static class Cron
{
    public static string Minutely() => "* * * * *";

    public static string Hourly() => "0 * * * *";

    public static string Daily(int hour)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(hour);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(hour, 23);
        return $"0 {hour} * * *";
    }
}

/// <summary>
/// A five-field cron expression (minute, hour, day of month, month, day of week) evaluated
/// in UTC. Fields accept <c>*</c>, values, ranges (<c>a-b</c>), steps (<c>*/n</c>,
/// <c>a-b/n</c>) and lists. As in standard cron, when both day fields are restricted a day
/// matches either. Day of week 0 and 7 are Sunday. Names and seconds are not supported.
/// </summary>
public sealed class CronSchedule
{
    private readonly ulong minutes;
    private readonly uint hours;
    private readonly uint daysOfMonth;
    private readonly ushort months;
    private readonly byte daysOfWeek;
    private readonly bool dayOfMonthRestricted;
    private readonly bool dayOfWeekRestricted;

    private CronSchedule(string expression, ulong minutes, uint hours, uint daysOfMonth, ushort months,
        byte daysOfWeek, bool dayOfMonthRestricted, bool dayOfWeekRestricted)
    {
        Expression = expression;
        this.minutes = minutes;
        this.hours = hours;
        this.daysOfMonth = daysOfMonth;
        this.months = months;
        this.daysOfWeek = daysOfWeek;
        this.dayOfMonthRestricted = dayOfMonthRestricted;
        this.dayOfWeekRestricted = dayOfWeekRestricted;
    }

    public string Expression { get; }

    public static CronSchedule Parse(string expression)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expression);
        string[] fields = expression.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length != 5)
        {
            throw new FormatException("A cron expression needs five fields: minute hour day month weekday.");
        }

        ulong minute = ParseField(fields[0], 0, 59, out _);
        ulong hour = ParseField(fields[1], 0, 23, out _);
        ulong dayOfMonth = ParseField(fields[2], 1, 31, out bool domRestricted);
        ulong month = ParseField(fields[3], 1, 12, out _);
        ulong dayOfWeek = ParseField(fields[4], 0, 7, out bool dowRestricted);
        if ((dayOfWeek & (1UL << 7)) != 0)
        {
            dayOfWeek = (dayOfWeek | 1UL) & ~(1UL << 7);
        }

        return new CronSchedule(
            expression,
            minute,
            (uint)hour,
            (uint)dayOfMonth,
            (ushort)month,
            (byte)dayOfWeek,
            domRestricted,
            dowRestricted);
    }

    /// <summary>The first occurrence strictly after <paramref name="after"/>, in UTC.</summary>
    public DateTimeOffset GetNextOccurrence(DateTimeOffset after)
    {
        DateTime utc = after.UtcDateTime;
        DateTime candidate = new DateTime(utc.Year, utc.Month, utc.Day, utc.Hour, utc.Minute, 0, DateTimeKind.Utc)
            .AddMinutes(1);
        // Every valid expression matches within a leap-year cycle (for example 29 February).
        DateTime limit = candidate.AddYears(5);
        while (candidate < limit)
        {
            if ((months & (1 << candidate.Month)) == 0)
            {
                candidate = new DateTime(candidate.Year, candidate.Month, 1, 0, 0, 0, DateTimeKind.Utc).AddMonths(1);
                continue;
            }

            if (!DayMatches(candidate))
            {
                candidate = candidate.Date.AddDays(1);
                continue;
            }

            if ((hours & (1U << candidate.Hour)) == 0)
            {
                candidate = candidate.Date.AddHours(candidate.Hour + 1);
                continue;
            }

            if ((minutes & (1UL << candidate.Minute)) == 0)
            {
                candidate = candidate.AddMinutes(1);
                continue;
            }

            return new DateTimeOffset(candidate);
        }

        throw new InvalidOperationException($"Cron expression '{Expression}' never matches.");
    }

    public override string ToString() => Expression;

    private bool DayMatches(DateTime day)
    {
        bool dom = (daysOfMonth & (1U << day.Day)) != 0;
        bool dow = (daysOfWeek & (1 << (int)day.DayOfWeek)) != 0;
        return dayOfMonthRestricted && dayOfWeekRestricted ? dom || dow : dom && dow;
    }

    private static ulong ParseField(string field, int minimum, int maximum, out bool restricted)
    {
        restricted = field != "*";
        ulong bits = 0;
        foreach (string part in field.Split(','))
        {
            string range = part;
            int step = 1;
            int slash = part.IndexOf('/', StringComparison.Ordinal);
            if (slash >= 0)
            {
                step = ParseNumber(part[(slash + 1)..], 1, maximum - minimum + 1);
                range = part[..slash];
            }

            int start;
            int end;
            if (range == "*")
            {
                start = minimum;
                end = maximum;
            }
            else
            {
                int dash = range.IndexOf('-', StringComparison.Ordinal);
                if (dash >= 0)
                {
                    start = ParseNumber(range[..dash], minimum, maximum);
                    end = ParseNumber(range[(dash + 1)..], minimum, maximum);
                    if (end < start)
                    {
                        throw new FormatException($"Cron range '{range}' is reversed.");
                    }
                }
                else
                {
                    start = ParseNumber(range, minimum, maximum);
                    end = slash >= 0 ? maximum : start;
                }
            }

            for (int value = start; value <= end; value += step)
            {
                bits |= 1UL << value;
            }
        }

        return bits;
    }

    private static int ParseNumber(string text, int minimum, int maximum)
    {
        if (!int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int value)
            || value < minimum
            || value > maximum)
        {
            throw new FormatException($"Cron value '{text}' must be between {minimum} and {maximum}.");
        }

        return value;
    }
}

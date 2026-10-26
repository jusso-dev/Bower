using System.Globalization;
using System.Text.RegularExpressions;

namespace Bower.Cli.Commands;

internal static partial class CliOptions
{
    private const string TimestampShape = "YYYY-MM-DDTHH:MM[:SS[.FFFFFFF]](Z|+HH:MM|-HH:MM)";

    /// <summary>
    /// A time option (<c>--at</c>, <c>--from</c>, <c>--to</c>) as UTC; null when absent. Only
    /// <see cref="TimestampShape"/> is accepted: an explicit <c>Z</c> or offset (at most
    /// 14:00), at most 7 fractional digits, no date-only or time-only values, so no input is
    /// rounded or completed with today's date. The Rust CLI (<c>support::timestamp</c>)
    /// applies the same rule.
    /// </summary>
    public static DateTimeOffset? Timestamp(string? value, string name)
    {
        if (value is null)
        {
            return null;
        }

        Match match = TimestampPattern().Match(value);
        return match.Success && TryBuildTimestamp(match, out DateTimeOffset parsed)
            ? parsed
            : throw new ArgumentException($"{name} must be an ISO 8601 timestamp with Z or an offset: {TimestampShape}.");
    }

    private static bool TryBuildTimestamp(Match match, out DateTimeOffset value)
    {
        value = default;
        int Part(int group) => int.Parse(match.Groups[group].ValueSpan, NumberStyles.None, CultureInfo.InvariantCulture);
        int year = Part(1), month = Part(2), day = Part(3), hour = Part(4), minute = Part(5);
        int second = match.Groups[6].Success ? Part(6) : 0;
        long ticks = match.Groups[7].Success
            ? long.Parse(match.Groups[7].ValueSpan[1..].ToString().PadRight(7, '0'), NumberStyles.None, CultureInfo.InvariantCulture)
            : 0;
        string offset = match.Groups[8].Value;
        int offsetMinutes = 0;
        if (offset != "Z")
        {
            int hours = int.Parse(offset.AsSpan(1, 2), NumberStyles.None, CultureInfo.InvariantCulture);
            int minutes = int.Parse(offset.AsSpan(4, 2), NumberStyles.None, CultureInfo.InvariantCulture);
            if (minutes > 59 || (hours * 60) + minutes > 14 * 60)
            {
                return false;
            }

            offsetMinutes = ((hours * 60) + minutes) * (offset[0] == '-' ? -1 : 1);
        }

        if (year < 1 || month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month)
            || hour > 23 || minute > 59 || second > 59)
        {
            return false;
        }

        try
        {
            value = new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.FromMinutes(offsetMinutes))
                .AddTicks(ticks)
                .ToUniversalTime();
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            // The UTC instant falls outside DateTimeOffset's range.
            return false;
        }
    }

    [GeneratedRegex(@"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(\.[0-9]{1,7})?)?(Z|[+-][0-9]{2}:[0-9]{2})\z", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPattern();

    public static string? Get(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    public static string Required(string[] args, string name) =>
        Get(args, name) ?? throw new ArgumentException($"{name} is required.");

    public static IReadOnlyList<string> All(string[] args, string name)
    {
        List<string> values = [];
        for (int index = 0; index < args.Length - 1; index++)
        {
            if (args[index] == name)
            {
                values.Add(args[index + 1]);
            }
        }

        return values;
    }

    public static bool Has(string[] args, string name) => Array.IndexOf(args, name) >= 0;

    /// <summary>
    /// First argument that is not an option or an option's value. Every <c>--option</c>,
    /// known or not, consumes the argument after it, so an unknown option's value is
    /// never taken as the positional.
    /// </summary>
    public static string? Positional(string[] args)
    {
        for (int index = 0; index < args.Length; index++)
        {
            if (args[index].StartsWith("--", StringComparison.Ordinal))
            {
                index++;
                continue;
            }

            return args[index];
        }

        return null;
    }

    public static int Int(string[] args, string name, int fallback) =>
        Get(args, name) is { } value ? int.Parse(value, System.Globalization.CultureInfo.InvariantCulture) : fallback;
}

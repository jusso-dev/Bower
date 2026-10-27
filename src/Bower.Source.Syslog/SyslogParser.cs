using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Bower.Source.Syslog;

public enum SyslogFormat
{
    Rfc5424,
    Rfc3164
}

/// <summary>One RFC 5424 SD-ELEMENT. Parameter names are unique within an element.</summary>
public sealed record SyslogStructuredElement(string Id, IReadOnlyList<KeyValuePair<string, string>> Parameters);

/// <summary>A parsed syslog message. Absent (NILVALUE) fields are null.</summary>
public sealed record SyslogMessage(
    SyslogFormat Format,
    int Facility,
    int Severity,
    DateTimeOffset? Timestamp,
    string? Hostname,
    string? AppName,
    string? ProcId,
    string? MessageId,
    IReadOnlyList<SyslogStructuredElement> StructuredData,
    string? Message);

/// <summary>Stable failure codes (shared with the Rust port). Metadata only.</summary>
public static class SyslogFailures
{
    public const string Empty = "syslog-empty";
    public const string InvalidUtf8 = "syslog-invalid-utf8";
    public const string PriorityInvalid = "syslog-priority-invalid";
    public const string VersionUnsupported = "syslog-version-unsupported";
    public const string TimestampInvalid = "syslog-timestamp-invalid";
    public const string HeaderInvalid = "syslog-header-invalid";
    public const string StructuredDataInvalid = "syslog-structured-data-invalid";
    public const string StructuredDataDuplicate = "syslog-structured-data-duplicate";
    public const string RecordTooLarge = "syslog-record-too-large";
    public const string FrameTooLarge = "syslog-frame-too-large";
    public const string OctetCountInvalid = "syslog-octet-count-invalid";
    public const string FramingInvalid = "syslog-framing-invalid";
    public const string FrameTruncated = "syslog-frame-truncated";
}

/// <summary>A frame that cannot become a record. <see cref="Code"/> is a <see cref="SyslogFailures"/> value.</summary>
public sealed class SyslogFormatException(string code) : FormatException(code)
{
    public string Code { get; } = code;
}

/// <summary>
/// Strict, allocation-bounded RFC 5424 and RFC 3164 parser. The whole frame must be valid
/// UTF-8; anything ambiguous (duplicate structured data, out-of-range priority, malformed
/// timestamps) fails closed with a stable code instead of being guessed.
/// </summary>
public static class SyslogParser
{
    public const int MaximumPriority = 191;
    private const char Bom = '﻿';
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    public static bool TryParse(
        ReadOnlySpan<byte> frame,
        DateTimeOffset receivedAt,
        [NotNullWhen(true)] out SyslogMessage? message,
        [NotNullWhen(false)] out string? failure)
    {
        try
        {
            message = Parse(frame, receivedAt);
            failure = null;
            return true;
        }
        catch (SyslogFormatException exception)
        {
            message = null;
            failure = exception.Code;
            return false;
        }
    }

    public static SyslogMessage Parse(ReadOnlySpan<byte> frame, DateTimeOffset receivedAt)
    {
        if (frame.IsEmpty)
        {
            throw new SyslogFormatException(SyslogFailures.Empty);
        }

        string text;
        try
        {
            text = StrictUtf8.GetString(frame);
        }
        catch (DecoderFallbackException)
        {
            throw new SyslogFormatException(SyslogFailures.InvalidUtf8);
        }

        int position = 0;
        int priority = ReadPriority(text, ref position);
        int run = position;
        while (run < text.Length && run - position < 4 && char.IsAsciiDigit(text[run]))
        {
            run++;
        }

        if (run - position is >= 1 and <= 3 && run < text.Length && text[run] == ' ')
        {
            if (run - position != 1 || text[position] != '1')
            {
                throw new SyslogFormatException(SyslogFailures.VersionUnsupported);
            }

            return Parse5424(text, run + 1, priority);
        }

        return Parse3164(text, position, priority, receivedAt);
    }

    private static int ReadPriority(string text, ref int position)
    {
        if (text[0] != '<')
        {
            throw new SyslogFormatException(SyslogFailures.PriorityInvalid);
        }

        int end = 1;
        while (end < text.Length && end <= 4 && char.IsAsciiDigit(text[end]))
        {
            end++;
        }

        int digits = end - 1;
        if (digits is 0 or > 3 || end >= text.Length || text[end] != '>' || (digits > 1 && text[1] == '0'))
        {
            throw new SyslogFormatException(SyslogFailures.PriorityInvalid);
        }

        int value = 0;
        for (int index = 1; index < end; index++)
        {
            value = (value * 10) + (text[index] - '0');
        }

        if (value > MaximumPriority)
        {
            throw new SyslogFormatException(SyslogFailures.PriorityInvalid);
        }

        position = end + 1;
        return value;
    }

    private static SyslogMessage Parse5424(string text, int position, int priority)
    {
        string timestampToken = Token(text, ref position, SyslogFailures.HeaderInvalid);
        DateTimeOffset? timestamp = timestampToken == "-"
            ? null
            : ParseTimestamp(timestampToken) ?? throw new SyslogFormatException(SyslogFailures.TimestampInvalid);
        string? hostname = Field(text, ref position, 255);
        string? appName = Field(text, ref position, 48);
        string? procId = Field(text, ref position, 128);
        string? messageId = Field(text, ref position, 32);
        if (position >= text.Length)
        {
            throw new SyslogFormatException(SyslogFailures.HeaderInvalid);
        }

        List<SyslogStructuredElement> elements = [];
        if (text[position] == '-')
        {
            position++;
        }
        else if (text[position] == '[')
        {
            ReadStructuredData(text, ref position, elements);
        }
        else
        {
            throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
        }

        string? message = null;
        if (position < text.Length)
        {
            if (text[position] != ' ')
            {
                throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
            }

            message = Body(text[(position + 1)..]);
        }

        return new SyslogMessage(SyslogFormat.Rfc5424, priority / 8, priority % 8, timestamp,
            hostname, appName, procId, messageId, elements, message);
    }

    private static SyslogMessage Parse3164(string text, int position, int priority, DateTimeOffset receivedAt)
    {
        DateTimeOffset timestamp;
        if (position + 15 < text.Length && text[position + 15] == ' '
            && TryBsdTimestamp(text.AsSpan(position, 15), receivedAt, out DateTimeOffset? bsd))
        {
            timestamp = bsd ?? throw new SyslogFormatException(SyslogFailures.TimestampInvalid);
            position += 16;
        }
        else
        {
            int space = text.IndexOf(' ', position);
            timestamp = space < 0
                ? throw new SyslogFormatException(SyslogFailures.TimestampInvalid)
                : ParseTimestamp(text[position..space]) ?? throw new SyslogFormatException(SyslogFailures.TimestampInvalid);
            position = space + 1;
        }

        // HOSTNAME is optional in practice: a first token that looks like a tag starts the content.
        string? hostname = null;
        int end = text.IndexOf(' ', position);
        if (end == position)
        {
            throw new SyslogFormatException(SyslogFailures.HeaderInvalid);
        }

        if (end > position)
        {
            string token = text[position..end];
            if (!token.EndsWith(':') && !token.Contains('[', StringComparison.Ordinal))
            {
                hostname = IsPrintable(token, 255) ? token : throw new SyslogFormatException(SyslogFailures.HeaderInvalid);
                position = end + 1;
            }
        }

        string content = text[position..];
        string? appName = null;
        string? procId = null;
        string? message = content;
        int tag = 0;
        while (tag < content.Length && tag <= 48 && IsPrintable(content[tag]) && content[tag] is not ('[' or ':'))
        {
            tag++;
        }

        if (tag is >= 1 and <= 48)
        {
            int next = tag;
            string? pid = null;
            if (next < content.Length && content[next] == '[')
            {
                int close = next + 1;
                while (close < content.Length && close - next <= 129 && IsPrintable(content[close]) && content[close] != ']')
                {
                    close++;
                }

                bool closed = close < content.Length && content[close] == ']' && close - next - 1 is >= 1 and <= 128;
                pid = closed ? content[(next + 1)..close] : null;
                next = closed ? close + 1 : -1;
            }

            if (next >= 0 && next < content.Length && content[next] == ':')
            {
                appName = content[..tag];
                procId = pid;
                next++;
                if (next < content.Length && content[next] == ' ')
                {
                    next++;
                }

                message = content[next..];
            }
        }

        return new SyslogMessage(SyslogFormat.Rfc3164, priority / 8, priority % 8, timestamp,
            hostname, appName, procId, null, [], Body(message));
    }

    private static string? Body(string message)
    {
        if (message.Length > 0 && message[0] == Bom)
        {
            message = message[1..];
        }

        return message.Length == 0 ? null : message;
    }

    /// <summary>Header token followed by exactly one SP.</summary>
    private static string Token(string text, ref int position, string failure)
    {
        int end = text.IndexOf(' ', position);
        if (end <= position)
        {
            throw new SyslogFormatException(failure);
        }

        string token = text[position..end];
        position = end + 1;
        return token;
    }

    private static string? Field(string text, ref int position, int maximum)
    {
        string token = Token(text, ref position, SyslogFailures.HeaderInvalid);
        if (!IsPrintable(token, maximum))
        {
            throw new SyslogFormatException(SyslogFailures.HeaderInvalid);
        }

        return token == "-" ? null : token;
    }

    private static void ReadStructuredData(string text, ref int position, List<SyslogStructuredElement> elements)
    {
        HashSet<string> ids = new(StringComparer.Ordinal);
        while (position < text.Length && text[position] == '[')
        {
            position++;
            string id = SdName(text, ref position);
            if (!ids.Add(id))
            {
                throw new SyslogFormatException(SyslogFailures.StructuredDataDuplicate);
            }

            List<KeyValuePair<string, string>> parameters = [];
            HashSet<string> names = new(StringComparer.Ordinal);
            while (true)
            {
                if (position >= text.Length)
                {
                    throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
                }

                if (text[position] == ']')
                {
                    position++;
                    break;
                }

                if (text[position] != ' ')
                {
                    throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
                }

                position++;
                string name = SdName(text, ref position);
                if (position + 1 >= text.Length || text[position] != '=' || text[position + 1] != '"')
                {
                    throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
                }

                position += 2;
                StringBuilder value = new();
                while (true)
                {
                    if (position >= text.Length)
                    {
                        throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
                    }

                    char character = text[position];
                    if (character == '\\' && position + 1 < text.Length && text[position + 1] is '"' or '\\' or ']')
                    {
                        value.Append(text[position + 1]);
                        position += 2;
                    }
                    else if (character == '"')
                    {
                        position++;
                        break;
                    }
                    else
                    {
                        value.Append(character);
                        position++;
                    }
                }

                if (!names.Add(name))
                {
                    throw new SyslogFormatException(SyslogFailures.StructuredDataDuplicate);
                }

                parameters.Add(new KeyValuePair<string, string>(name, value.ToString()));
            }

            elements.Add(new SyslogStructuredElement(id, parameters));
        }
    }

    /// <summary>SD-NAME: 1–32 PRINTUSASCII except '=', SP, ']' and '"'.</summary>
    private static string SdName(string text, ref int position)
    {
        int start = position;
        while (position < text.Length && position - start <= 32 && IsPrintable(text[position])
            && text[position] is not ('=' or ']' or '"'))
        {
            position++;
        }

        int length = position - start;
        return length is >= 1 and <= 32
            ? text[start..position]
            : throw new SyslogFormatException(SyslogFailures.StructuredDataInvalid);
    }

    private static bool IsPrintable(char character) => character is >= '!' and <= '~';

    private static bool IsPrintable(string token, int maximum) =>
        token.Length >= 1 && token.Length <= maximum && token.All(IsPrintable);

    /// <summary>RFC 5424 TIMESTAMP: uppercase T and Z, at most six fraction digits, no leap seconds.</summary>
    internal static DateTimeOffset? ParseTimestamp(string token)
    {
        ReadOnlySpan<char> span = token;
        if (span.Length < 20 || span[4] != '-' || span[7] != '-' || span[10] != 'T' || span[13] != ':' || span[16] != ':'
            || !Number(span[..4], out int year) || !Number(span[5..7], out int month) || !Number(span[8..10], out int day)
            || !Number(span[11..13], out int hour) || !Number(span[14..16], out int minute) || !Number(span[17..19], out int second))
        {
            return null;
        }

        int position = 19;
        long microseconds = 0;
        if (span[position] == '.')
        {
            int start = ++position;
            while (position < span.Length && char.IsAsciiDigit(span[position]))
            {
                position++;
            }

            int digits = position - start;
            if (digits is < 1 or > 6 || !Number(span[start..position], out int fraction))
            {
                return null;
            }

            microseconds = fraction;
            for (int index = digits; index < 6; index++)
            {
                microseconds *= 10;
            }
        }

        TimeSpan offset;
        ReadOnlySpan<char> zone = span[position..];
        if (zone is "Z")
        {
            offset = TimeSpan.Zero;
        }
        else if (zone.Length == 6 && zone[0] is '+' or '-' && zone[3] == ':'
            && Number(zone[1..3], out int offsetHours) && Number(zone[4..6], out int offsetMinutes)
            && offsetMinutes <= 59 && (offsetHours * 60) + offsetMinutes <= 14 * 60)
        {
            offset = new TimeSpan(offsetHours, offsetMinutes, 0);
            offset = zone[0] == '-' ? -offset : offset;
        }
        else
        {
            return null;
        }

        if (year < 1 || month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month)
            || hour > 23 || minute > 59 || second > 59)
        {
            return null;
        }

        try
        {
            DateTimeOffset value = new DateTimeOffset(year, month, day, hour, minute, second, offset)
                .AddTicks(microseconds * 10);
            return value.UtcDateTime.Year is >= 1 and <= 9999 ? value : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>
    /// RFC 3164 "Mmm dd hh:mm:ss" (day space- or zero-padded), read as UTC. The year is the
    /// receive year, or the year before when that date would be more than a day ahead of
    /// the receive time (or does not exist, such as 29 February).
    /// </summary>
    /// <returns>False when the text does not start with a month name (try RFC 3339 instead).</returns>
    private static bool TryBsdTimestamp(ReadOnlySpan<char> span, DateTimeOffset receivedAt, out DateTimeOffset? value)
    {
        value = null;
        int month = Array.IndexOf(Months, span[..3].ToString()) + 1;
        if (month == 0)
        {
            return false;
        }

        if (span[3] != ' ' || span[6] != ' ' || span[9] != ':' || span[12] != ':')
        {
            return true;
        }

        int day;
        if (span[4] == ' ' && span[5] is >= '1' and <= '9')
        {
            day = span[5] - '0';
        }
        else if (!Number(span[4..6], out day))
        {
            return true;
        }

        if (!Number(span[7..9], out int hour) || !Number(span[10..12], out int minute) || !Number(span[13..15], out int second)
            || hour > 23 || minute > 59 || second > 59 || day is < 1 or > 31)
        {
            return true;
        }

        int year = receivedAt.UtcDateTime.Year;
        DateTimeOffset? current = Date(year);
        value = current is { } candidate && candidate <= receivedAt.AddDays(1) ? candidate : Date(year - 1);
        return true;

        DateTimeOffset? Date(int candidateYear) =>
            candidateYear is >= 1 and <= 9999 && day <= DateTime.DaysInMonth(candidateYear, month)
                ? new DateTimeOffset(candidateYear, month, day, hour, minute, second, TimeSpan.Zero)
                : null;
    }

    private static bool Number(ReadOnlySpan<char> digits, out int value)
    {
        value = 0;
        foreach (char digit in digits)
        {
            if (!char.IsAsciiDigit(digit))
            {
                return false;
            }

            value = (value * 10) + (digit - '0');
        }

        return digits.Length > 0;
    }
}

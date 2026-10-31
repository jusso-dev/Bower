using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace Bower.Source.WindowsEventLog;

/// <summary>Stable, metadata-only failure codes. Never carry event content.</summary>
public static class WindowsEventFailures
{
    public const string XmlTooLarge = "winevt-xml-too-large";
    public const string XmlInvalid = "winevt-xml-invalid";
    public const string SystemInvalid = "winevt-system-invalid";
    public const string RecordTooLarge = "winevt-record-too-large";
}

public sealed class WindowsEventFormatException(string code) : FormatException(code)
{
    public string Code { get; } = code;
}

/// <summary>One parsed event: the System header and the EventData/UserData values.</summary>
public sealed record WindowsEvent(
    string Channel,
    string Provider,
    int EventId,
    long RecordId,
    DateTimeOffset TimeCreated,
    string Computer,
    IReadOnlyList<KeyValuePair<string, string>> Header,
    IReadOnlyList<KeyValuePair<string, string>> Data);

/// <summary>
/// Parses the event XML the Windows event log service renders (<c>EvtRender</c>,
/// <c>EventRecord.ToXml()</c>). Platform-neutral so it is tested everywhere from recorded
/// fixtures. Bounded and fail closed: 64 KiB, no DTD, no external resolution.
/// </summary>
public static class WindowsEventXml
{
    public const int MaximumXmlCharacters = 65_536;
    private const string EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";
    private const int MaximumDataItems = 128;

    /// <summary>
    /// Writes raw characters XML 1.0 forbids (C0 controls other than tab, LF and CR,
    /// unpaired surrogates, U+FFFE and U+FFFF) as character references, which the reader
    /// accepts with character checking off. The event keeps its exact values.
    /// </summary>
    internal static string EscapeForbiddenCharacters(string xml)
    {
        System.Text.StringBuilder? escaped = null;
        for (int index = 0; index < xml.Length; index++)
        {
            char character = xml[index];
            bool pairedSurrogate = char.IsHighSurrogate(character) && index + 1 < xml.Length && char.IsLowSurrogate(xml[index + 1]);
            bool forbidden = (character < '\u0020' && character is not ('\t' or '\n' or '\r'))
                || character is '\uFFFE' or '\uFFFF'
                || (char.IsSurrogate(character) && !pairedSurrogate
                    && !(char.IsLowSurrogate(character) && index > 0 && char.IsHighSurrogate(xml[index - 1])));
            if (forbidden)
            {
                escaped ??= new System.Text.StringBuilder(xml, 0, index, xml.Length + 16);
                escaped.Append("&#x").Append(((int)character).ToString("X", CultureInfo.InvariantCulture)).Append(';');
            }
            else
            {
                escaped?.Append(character);
            }
        }

        return escaped?.ToString() ?? xml;
    }

    /// <summary>
    /// Makes a value safe for JSON without collisions. JSON cannot carry an unpaired
    /// surrogate (the writer replaces it with U+FFFD), so two account names differing only
    /// there would share one pseudonym. U+FFFD is the escape: an unpaired surrogate becomes
    /// U+FFFD and its four hex digits, an existing U+FFFD becomes U+FFFD and <c>FFFD</c>.
    /// Values with neither are unchanged; the mapping is reversible.
    /// </summary>
    [return: System.Diagnostics.CodeAnalysis.NotNullIfNotNull(nameof(value))]
    internal static string? EscapeUnpairedSurrogates(string? value)
    {
        if (value is null || !value.Any(character => char.IsSurrogate(character) || character == '\uFFFD'))
        {
            return value;
        }

        System.Text.StringBuilder escaped = new(value.Length + 8);
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if (char.IsHighSurrogate(character) && index + 1 < value.Length && char.IsLowSurrogate(value[index + 1]))
            {
                escaped.Append(character).Append(value[++index]);
            }
            else if (char.IsSurrogate(character) || character == '\uFFFD')
            {
                escaped.Append('\uFFFD').Append(((int)character).ToString("X4", CultureInfo.InvariantCulture));
            }
            else
            {
                escaped.Append(character);
            }
        }

        return escaped.ToString();
    }

    public static WindowsEvent Parse(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (xml.Length > MaximumXmlCharacters)
        {
            throw new WindowsEventFormatException(WindowsEventFailures.XmlTooLarge);
        }

        XDocument document;
        try
        {
            using StringReader text = new(EscapeForbiddenCharacters(xml));
            using XmlReader reader = XmlReader.Create(text, new XmlReaderSettings
            {
                // Rendered event XML can carry characters XML 1.0 forbids (for example a
                // control character an attacker typed as an account name). Refusing them
                // would drop exactly that failed logon; values are still bounded, mapped by
                // the signed pack and redacted before persistence.
                CheckCharacters = false,
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                // The size limit applies to the rendered text above; escaping only lengthens it.
                MaxCharactersInDocument = MaximumXmlCharacters * 8,
                MaxCharactersFromEntities = 0,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException)
        {
            throw new WindowsEventFormatException(WindowsEventFailures.XmlInvalid);
        }

        XNamespace ns = EventNamespace;
        XElement root = document.Root!;
        XElement system = root.Name == ns + "Event" ? root.Element(ns + "System") ?? throw SystemInvalid() : throw SystemInvalid();

        string provider = Text(EscapeUnpairedSurrogates(system.Element(ns + "Provider")?.Attribute("Name")?.Value)) ?? throw SystemInvalid();
        int eventId = Number(system.Element(ns + "EventID")?.Value, ushort.MaxValue) is ulong id ? (int)id : throw SystemInvalid();
        long recordId = Number(system.Element(ns + "EventRecordID")?.Value, long.MaxValue) is ulong record && record > 0
            ? (long)record
            : throw SystemInvalid();
        DateTimeOffset created = ParseSystemTime(system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value) ?? throw SystemInvalid();
        string channel = Text(EscapeUnpairedSurrogates(system.Element(ns + "Channel")?.Value)) ?? throw SystemInvalid();
        string computer = Text(EscapeUnpairedSurrogates(system.Element(ns + "Computer")?.Value)) ?? throw SystemInvalid();

        List<KeyValuePair<string, string>> header = [];
        AddNumber("version", system.Element(ns + "Version")?.Value, byte.MaxValue);
        AddNumber("level", system.Element(ns + "Level")?.Value, byte.MaxValue);
        AddNumber("task", system.Element(ns + "Task")?.Value, ushort.MaxValue);
        AddNumber("opcode", system.Element(ns + "Opcode")?.Value, byte.MaxValue);
        if (system.Element(ns + "Keywords")?.Value is { } keywords && IsHex64(keywords))
        {
            header.Add(new("keywords", keywords));
        }

        if (system.Element(ns + "Security")?.Attribute("UserID")?.Value is { } sid && IsSid(sid))
        {
            header.Add(new("userSid", sid));
        }

        XElement? execution = system.Element(ns + "Execution");
        AddNumber("processId", execution?.Attribute("ProcessID")?.Value, uint.MaxValue);
        AddNumber("threadId", execution?.Attribute("ThreadID")?.Value, uint.MaxValue);
        if (system.Element(ns + "Correlation")?.Attribute("ActivityID")?.Value is { } activity
            && Guid.TryParseExact(activity, "B", out Guid activityId))
        {
            header.Add(new("activityId", activityId.ToString("D", CultureInfo.InvariantCulture)));
        }

        List<KeyValuePair<string, string>> data = [];
        if (root.Element(ns + "EventData") is { } eventData)
        {
            int index = 0;
            foreach (XElement item in eventData.Elements(ns + "Data"))
            {
                string name = item.Attribute("Name")?.Value ?? index.ToString(CultureInfo.InvariantCulture);
                Add("data." + name, item.Value);
                index++;
            }
        }

        // UserData holds one provider-defined element; its leaf children are the values.
        if (root.Element(ns + "UserData")?.Elements().FirstOrDefault() is { } userData)
        {
            foreach (XElement item in userData.Elements().Where(element => !element.HasElements))
            {
                Add("userData." + item.Name.LocalName, item.Value);
            }
        }

        return new WindowsEvent(channel, provider, eventId, recordId, created, computer, header, data);

        void AddNumber(string name, string? value, ulong maximum)
        {
            if (Number(value, maximum) is { } number)
            {
                header.Add(new(name, number.ToString(CultureInfo.InvariantCulture)));
            }
        }

        void Add(string name, string value)
        {
            if (data.Count >= MaximumDataItems)
            {
                throw new WindowsEventFormatException(WindowsEventFailures.RecordTooLarge);
            }

            data.Add(new(name, EscapeUnpairedSurrogates(value)));
        }
    }

    /// <summary>
    /// <c>yyyy-MM-ddTHH:mm:ss[.f…]Z</c> with up to 9 fraction digits (truncated to 100 ns),
    /// as the event log service renders <c>SystemTime</c>.
    /// </summary>
    internal static DateTimeOffset? ParseSystemTime(string? value)
    {
        if (value is not { Length: >= 20 and <= 30 } || value[^1] != 'Z')
        {
            return null;
        }

        string whole = value[..19];
        string rest = value[19..^1];
        if (!DateTime.TryParseExact(whole, "yyyy'-'MM'-'dd'T'HH':'mm':'ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime parsed))
        {
            return null;
        }

        long ticks = 0;
        if (rest.Length > 0)
        {
            if (rest[0] != '.' || rest.Length is < 2 or > 10 || !rest[1..].All(char.IsAsciiDigit))
            {
                return null;
            }

            string fraction = (rest[1..] + "0000000")[..7];
            ticks = long.Parse(fraction, NumberStyles.None, CultureInfo.InvariantCulture);
        }

        return new DateTimeOffset(DateTime.SpecifyKind(parsed, DateTimeKind.Utc).AddTicks(ticks), TimeSpan.Zero);
    }

    private static ulong? Number(string? value, ulong maximum) =>
        value is { Length: >= 1 and <= 20 } && value.All(char.IsAsciiDigit) && (value.Length == 1 || value[0] != '0')
        && ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong number) && number <= maximum
            ? number
            : null;

    private static string? Text(string? value) =>
        value is { Length: >= 1 and <= 255 } && !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl) ? value : null;

    private static bool IsHex64(string value) =>
        value.Length is >= 3 and <= 18 && value.StartsWith("0x", StringComparison.Ordinal) && value[2..].All(char.IsAsciiHexDigit);

    private static bool IsSid(string value) =>
        value.Length is >= 5 and <= 184 && value.StartsWith("S-1-", StringComparison.Ordinal)
        && value.All(character => char.IsAsciiDigit(character) || character is 'S' or '-');

    private static WindowsEventFormatException SystemInvalid() => new(WindowsEventFailures.SystemInvalid);
}

using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace Bower.Source.WindowsEventLog;

/// <summary>Receiving-log position, distinct from a forwarded event's origin ID.</summary>
public static class WindowsNativeBookmark
{
    public static string Create(string channel, long position)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(channel);
        ArgumentOutOfRangeException.ThrowIfNegative(position);
        return new XElement("BookmarkList", new XElement("Bookmark",
            new XAttribute("Channel", channel),
            new XAttribute("RecordId", position.ToString(CultureInfo.InvariantCulture)),
            new XAttribute("IsCurrent", "true"))).ToString(SaveOptions.DisableFormatting);
    }

    public static long Position(string xml, string channel)
    {
        using StringReader text = new(xml);
        using XmlReader reader = XmlReader.Create(text, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 4096
        });
        XElement root = XElement.Load(reader);
        XElement? bookmark = root.Name == "BookmarkList" ? root.Elements("Bookmark").SingleOrDefault() : null;
        if (bookmark is null || (string?)bookmark.Attribute("Channel") != channel
            || !long.TryParse((string?)bookmark.Attribute("RecordId"), NumberStyles.None,
                CultureInfo.InvariantCulture, out long position) || position < 0)
        {
            throw new WindowsEventChannelException(WindowsEventChannelFailures.BookmarkInvalid);
        }
        return position;
    }
}

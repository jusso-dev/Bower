using System.Globalization;

namespace Bower.Source.Kubernetes;

/// <summary>One parsed CRI container log line: <c>&lt;timestamp&gt; &lt;stdout|stderr&gt; &lt;P|F&gt; &lt;message&gt;</c>.</summary>
public sealed record CriLogLine(
    DateTimeOffset Timestamp,
    string Stream,
    bool IsPartial,
    string Message);

public static class CriLogParser
{
    public static bool TryParse(string line, out CriLogLine? parsed)
    {
        parsed = null;
        if (string.IsNullOrEmpty(line))
        {
            return false;
        }

        int sp1 = line.IndexOf(' ');
        if (sp1 <= 0)
        {
            return false;
        }

        int sp2 = line.IndexOf(' ', sp1 + 1);
        if (sp2 <= sp1 + 1)
        {
            return false;
        }

        int sp3 = line.IndexOf(' ', sp2 + 1);
        if (sp3 <= sp2 + 1)
        {
            return false;
        }

        ReadOnlySpan<char> timeSpan = line.AsSpan(0, sp1);
        ReadOnlySpan<char> streamSpan = line.AsSpan(sp1 + 1, sp2 - sp1 - 1);
        ReadOnlySpan<char> tagSpan = line.AsSpan(sp2 + 1, sp3 - sp2 - 1);

        if (!DateTimeOffset.TryParse(
            timeSpan,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out DateTimeOffset timestamp))
        {
            return false;
        }

        string stream;
        if (streamSpan.Equals("stdout", StringComparison.Ordinal))
        {
            stream = "stdout";
        }
        else if (streamSpan.Equals("stderr", StringComparison.Ordinal))
        {
            stream = "stderr";
        }
        else
        {
            return false;
        }

        bool isPartial;
        if (tagSpan.Equals("P", StringComparison.Ordinal))
        {
            isPartial = true;
        }
        else if (tagSpan.Equals("F", StringComparison.Ordinal))
        {
            isPartial = false;
        }
        else
        {
            return false;
        }

        string message = line[(sp3 + 1)..];
        parsed = new CriLogLine(timestamp.ToUniversalTime(), stream, isPartial, message);
        return true;
    }
}

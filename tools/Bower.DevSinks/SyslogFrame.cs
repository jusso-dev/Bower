using System.Buffers.Text;
using System.Text;

namespace Bower.DevSinks;

/// <summary>
/// Decodes the frame <c>Bower.Output.AmaSyslog</c> writes:
/// <c>&lt;PRI&gt;Mmm dd hh:mm:ss bower: bower-b64:&lt;base64 envelope&gt;</c>.
/// </summary>
public static class SyslogFrame
{
    public const string MessagePrefix = "bower-b64:";

    /// <summary>The decoded envelope JSON, or null when the datagram is not a Bower frame.</summary>
    public static string? DecodeEnvelope(ReadOnlySpan<byte> datagram)
    {
        int start = datagram.IndexOf(Encoding.ASCII.GetBytes(MessagePrefix));
        if (start < 0 || datagram.Length == 0 || datagram[0] != (byte)'<')
        {
            return null;
        }

        ReadOnlySpan<byte> encoded = datagram[(start + MessagePrefix.Length)..].TrimEnd("\r\n\0"u8);
        byte[] json = new byte[Base64.GetMaxDecodedFromUtf8Length(encoded.Length)];
        return Base64.DecodeFromUtf8(encoded, json, out _, out int written) == System.Buffers.OperationStatus.Done
            ? Encoding.UTF8.GetString(json, 0, written)
            : null;
    }
}

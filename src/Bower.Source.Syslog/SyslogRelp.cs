using System.Globalization;
using System.Text;

namespace Bower.Source.Syslog;

/// <summary>Stable RELP failure codes. A RELP failure ends the session; it is never answered with an error code.</summary>
public static class RelpFailures
{
    public const string FrameInvalid = "relp-frame-invalid";
    public const string FrameTruncated = "relp-frame-truncated";
    public const string DataTooLarge = "relp-data-too-large";
    public const string OffersInvalid = "relp-offers-invalid";
}

/// <summary>The RELP commands Bower understands. Anything else is <see cref="Unknown"/> and ends the session.</summary>
public enum RelpCommand
{
    Unknown,
    Open,
    Syslog,
    Close,
    Response,
    ServerClose
}

/// <summary>
/// One RELP frame (<c>TXNR SP COMMAND SP DATALEN [SP DATA] LF</c>), the end of the stream, a
/// failure (the session must close), or a <c>syslog</c> frame whose data exceeded the limit and
/// was skipped without buffering (<see cref="Oversized"/>). Data is valid until the next read.
/// </summary>
public readonly record struct RelpFrameResult(
    long Transaction,
    RelpCommand Command,
    ReadOnlyMemory<byte> Data,
    string? Failure,
    bool IsEnd,
    bool Oversized)
{
    internal static RelpFrameResult End => new(0, RelpCommand.Unknown, default, null, true, false);

    internal static RelpFrameResult Failed(string code) => new(0, RelpCommand.Unknown, default, code, false, false);
}

/// <summary>
/// RELP framing as librelp parses it: TXNR and DATALEN are 1–9 ASCII digits, the command 1–32
/// ASCII letters, a zero DATALEN is followed directly by the LF trailer. Memory is one fixed
/// buffer of the data limit plus header room. A <c>syslog</c> frame that exceeds the limit is
/// read past without buffering (at most 999,999,999 bytes, within the caller's frame timeout)
/// so the session can answer it as a final drop instead of making the sender resend it forever;
/// any other oversized or malformed frame fails, and the caller closes the session. Every field
/// separator must be exactly one space.
/// </summary>
public sealed class RelpFrameReader
{
    public const int MaximumDigits = 9;
    public const int MaximumCommandLength = 32;

    // TXNR SP COMMAND SP DATALEN SP: 9 + 1 + 32 + 1 + 9 + 1, plus the trailer.
    private const int Headroom = 64;
    private readonly Stream stream;
    private readonly int maximum;
    private readonly byte[] buffer;
    private int start;
    private int end;

    public RelpFrameReader(Stream stream, int maximumDataBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumDataBytes, 1);
        this.stream = stream;
        maximum = maximumDataBytes;
        buffer = new byte[maximumDataBytes + Headroom];
    }

    /// <summary>Waits until the first byte of the next frame is buffered. False at end of stream.</summary>
    public async ValueTask<bool> WaitForFrameAsync(CancellationToken cancellationToken)
    {
        while (start == end)
        {
            if (!await FillAsync(cancellationToken))
            {
                return false;
            }
        }

        return true;
    }

    public async ValueTask<RelpFrameResult> ReadFrameAsync(CancellationToken cancellationToken)
    {
        if (start == end && !await FillAsync(cancellationToken))
        {
            return RelpFrameResult.End;
        }

        (long transaction, int digits, string? failure) = await NumberAsync(0, cancellationToken);
        if (failure is not null)
        {
            return RelpFrameResult.Failed(failure);
        }

        int separator = await ByteAtAsync(digits, cancellationToken);
        if (separator != ' ')
        {
            return RelpFrameResult.Failed(separator < 0 ? RelpFailures.FrameTruncated : RelpFailures.FrameInvalid);
        }

        int offset = digits + 1;
        int letters = 0;
        while (true)
        {
            int value = await ByteAtAsync(offset + letters, cancellationToken);
            if (value < 0)
            {
                return RelpFrameResult.Failed(RelpFailures.FrameTruncated);
            }

            if (value == ' ' && letters > 0)
            {
                break;
            }

            if (!char.IsAsciiLetter((char)value) || ++letters > MaximumCommandLength)
            {
                return RelpFrameResult.Failed(RelpFailures.FrameInvalid);
            }
        }

        RelpCommand command = Command(buffer.AsSpan(start + offset, letters));
        offset += letters + 1;
        (long length, digits, failure) = await NumberAsync(offset, cancellationToken);
        if (failure is not null)
        {
            return RelpFrameResult.Failed(failure);
        }

        offset += digits;
        separator = await ByteAtAsync(offset, cancellationToken);
        if (separator < 0)
        {
            return RelpFrameResult.Failed(RelpFailures.FrameTruncated);
        }

        if (length == 0)
        {
            if (separator != '\n')
            {
                return RelpFrameResult.Failed(RelpFailures.FrameInvalid);
            }

            start += offset + 1;
            return new RelpFrameResult(transaction, command, ReadOnlyMemory<byte>.Empty, null, false, false);
        }

        if (separator != ' ')
        {
            return RelpFrameResult.Failed(RelpFailures.FrameInvalid);
        }

        offset++;
        if (length > maximum)
        {
            return command == RelpCommand.Syslog
                ? await SkipAsync(transaction, offset, length, cancellationToken)
                : RelpFrameResult.Failed(RelpFailures.DataTooLarge);
        }

        int trailer = await ByteAtAsync(offset + (int)length, cancellationToken);
        if (trailer < 0)
        {
            return RelpFrameResult.Failed(RelpFailures.FrameTruncated);
        }

        if (trailer != '\n')
        {
            return RelpFrameResult.Failed(RelpFailures.FrameInvalid);
        }

        ReadOnlyMemory<byte> data = buffer.AsMemory(start + offset, (int)length);
        start += offset + (int)length + 1;
        return new RelpFrameResult(transaction, command, data, null, false, false);
    }

    /// <summary>1–9 digits followed by a non-digit (left unread), as librelp accepts them.</summary>
    private async ValueTask<(long Value, int Digits, string? Failure)> NumberAsync(int offset, CancellationToken cancellationToken)
    {
        long value = 0;
        int digits = 0;
        while (true)
        {
            int next = await ByteAtAsync(offset + digits, cancellationToken);
            if (next < 0)
            {
                return (0, 0, RelpFailures.FrameTruncated);
            }

            if (next is < '0' or > '9')
            {
                break;
            }

            if (++digits > MaximumDigits)
            {
                return (0, 0, RelpFailures.FrameInvalid);
            }

            value = (value * 10) + (next - '0');
        }

        return digits == 0 ? (0, 0, RelpFailures.FrameInvalid) : (value, digits, null);
    }

    /// <summary>Reads past <paramref name="length"/> data bytes and checks the trailer.</summary>
    private async ValueTask<RelpFrameResult> SkipAsync(long transaction, int offset, long length, CancellationToken cancellationToken)
    {
        start += offset;
        long remaining = length;
        while (remaining > 0)
        {
            if (start == end && !await FillAsync(cancellationToken))
            {
                return RelpFrameResult.Failed(RelpFailures.FrameTruncated);
            }

            int take = (int)Math.Min(remaining, end - start);
            start += take;
            remaining -= take;
        }

        int trailer = await ByteAtAsync(0, cancellationToken);
        if (trailer != '\n')
        {
            return RelpFrameResult.Failed(trailer < 0 ? RelpFailures.FrameTruncated : RelpFailures.FrameInvalid);
        }

        start++;
        return new RelpFrameResult(transaction, RelpCommand.Syslog, ReadOnlyMemory<byte>.Empty, null, false, true);
    }

    private static RelpCommand Command(ReadOnlySpan<byte> name) =>
        name.SequenceEqual("syslog"u8) ? RelpCommand.Syslog
        : name.SequenceEqual("open"u8) ? RelpCommand.Open
        : name.SequenceEqual("close"u8) ? RelpCommand.Close
        : name.SequenceEqual("rsp"u8) ? RelpCommand.Response
        : name.SequenceEqual("serverclose"u8) ? RelpCommand.ServerClose
        : RelpCommand.Unknown;

    /// <summary>The byte <paramref name="offset"/> past the frame start, reading more as needed; -1 at end of stream.</summary>
    private async ValueTask<int> ByteAtAsync(int offset, CancellationToken cancellationToken)
    {
        while (end - start <= offset)
        {
            if (!await FillAsync(cancellationToken))
            {
                return -1;
            }
        }

        return buffer[start + offset];
    }

    /// <summary>Reads more bytes, compacting first. False at end of stream.</summary>
    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        if (start > 0 && (end == buffer.Length || start == end))
        {
            Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
            end -= start;
            start = 0;
        }

        if (end == buffer.Length)
        {
            // Callers check their bound before asking for more, so a full buffer is a bug.
            throw new InvalidOperationException("RELP frame buffer is full.");
        }

        int read = await stream.ReadAsync(buffer.AsMemory(end), cancellationToken);
        end += read;
        return read > 0;
    }
}

/// <summary>RELP session rules shared by the listener and its tests: offers, transaction numbers and responses.</summary>
public static class RelpProtocol
{
    /// <summary>The only RELP protocol version (librelp's current version).</summary>
    public const int Version = 0;

    /// <summary>Largest <c>open</c> offer data Bower reads; librelp sends about 100 bytes.</summary>
    public const int MaximumOfferBytes = 4_096;

    public const int MaximumOfferNameLength = 32;
    public const int MaximumOfferValueLength = 255;
    public const int MaximumOffers = 16;
    public const int MaximumOfferValues = 16;

    /// <summary>librelp wraps transaction numbers after 999,999,999 back to 1.</summary>
    public const long MaximumTransaction = 999_999_999;

    private static readonly byte[] Acknowledgement = "200 OK"u8.ToArray();

    /// <summary>The transaction number a client must use after <paramref name="current"/>.</summary>
    public static long Next(long current) => current >= MaximumTransaction ? 1 : current + 1;

    /// <summary>
    /// Checks a client's <c>open</c> offers: <c>relp_version</c> must be a non-negative integer and
    /// <c>commands</c> must include <c>syslog</c>. Unknown offers are ignored, as librelp does.
    /// Names, values and counts are bounded; anything else fails with <see cref="RelpFailures.OffersInvalid"/>.
    /// </summary>
    public static bool TryAcceptOffers(ReadOnlySpan<byte> data, out string? failure)
    {
        failure = RelpFailures.OffersInvalid;
        if (data.Length > MaximumOfferBytes)
        {
            return false;
        }

        bool version = false;
        bool syslog = false;
        int offers = 0;
        while (!data.IsEmpty)
        {
            int newline = data.IndexOf((byte)'\n');
            ReadOnlySpan<byte> line = newline < 0 ? data : data[..newline];
            data = newline < 0 ? [] : data[(newline + 1)..];
            if (line.IsEmpty)
            {
                continue;
            }

            if (++offers > MaximumOffers)
            {
                return false;
            }

            int equals = line.IndexOf((byte)'=');
            ReadOnlySpan<byte> name = equals < 0 ? line : line[..equals];
            if (name.IsEmpty || name.Length > MaximumOfferNameLength || !Printable(name))
            {
                return false;
            }

            List<string> values = [];
            if (equals >= 0)
            {
                foreach (Range range in line[(equals + 1)..].Split((byte)','))
                {
                    ReadOnlySpan<byte> value = line[(equals + 1)..][range];
                    if (value.IsEmpty)
                    {
                        continue;
                    }

                    if (value.Length > MaximumOfferValueLength || !Printable(value) || values.Count == MaximumOfferValues)
                    {
                        return false;
                    }

                    values.Add(Encoding.ASCII.GetString(value));
                }
            }

            if (name.SequenceEqual("relp_version"u8))
            {
                if (values.Count == 0 || !values.All(value => value.All(char.IsAsciiDigit) && value.Length <= 9))
                {
                    return false;
                }

                version = true;
            }
            else if (name.SequenceEqual("commands"u8))
            {
                syslog |= values.Contains("syslog", StringComparer.Ordinal);
            }
        }

        if (!version || !syslog)
        {
            return false;
        }

        failure = null;
        return true;
    }

    /// <summary><c>TXNR rsp LEN 200 OK LF relp_version=0 LF relp_software=bower LF commands=syslog LF</c>, as librelp's server answers.</summary>
    public static byte[] OpenAccepted(long transaction) =>
        Frame(transaction, "rsp", "200 OK\nrelp_version=0\nrelp_software=bower\ncommands=syslog"u8);

    /// <summary>The acknowledgement for a <c>syslog</c> transaction, sent only after a final durable decision.</summary>
    public static byte[] Acknowledge(long transaction) => Frame(transaction, "rsp", Acknowledgement);

    /// <summary>Refuses an <c>open</c>; the session closes after it. Never used for a <c>syslog</c> transaction.</summary>
    public static byte[] OpenRefused(long transaction) =>
        Frame(transaction, "rsp", "500 required command not supported by client"u8);

    /// <summary>The empty response to a client's <c>close</c>.</summary>
    public static byte[] CloseAccepted(long transaction) => Frame(transaction, "rsp", []);

    /// <summary>The server's hint that it is closing (transaction 0, no response expected).</summary>
    public static byte[] ServerClose() => Frame(0, "serverclose", []);

    internal static byte[] Frame(long transaction, string command, ReadOnlySpan<byte> data)
    {
        string header = data.IsEmpty
            ? string.Create(CultureInfo.InvariantCulture, $"{transaction} {command} 0")
            : string.Create(CultureInfo.InvariantCulture, $"{transaction} {command} {data.Length} ");
        byte[] frame = new byte[header.Length + data.Length + 1];
        Encoding.ASCII.GetBytes(header, frame);
        data.CopyTo(frame.AsSpan(header.Length));
        frame[^1] = (byte)'\n';
        return frame;
    }

    private static bool Printable(ReadOnlySpan<byte> value)
    {
        foreach (byte character in value)
        {
            if (character is < (byte)' ' or > (byte)'~')
            {
                return false;
            }
        }

        return true;
    }
}

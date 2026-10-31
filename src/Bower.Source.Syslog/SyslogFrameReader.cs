namespace Bower.Source.Syslog;

/// <summary>One frame, the end of the stream, or a framing failure (the connection must close).</summary>
public readonly record struct SyslogFrameResult(ReadOnlyMemory<byte> Frame, string? Failure, bool IsEnd)
{
    internal static SyslogFrameResult End => new(default, null, true);

    internal static SyslogFrameResult Failed(string code) => new(default, code, false);
}

/// <summary>
/// RFC 6587 framing over a byte stream: octet counting (<c>MSG-LEN SP SYSLOG-MSG</c>) when a
/// frame starts with a digit, non-transparent LF framing when it starts with <c>&lt;</c>.
/// Memory is bounded by one fixed buffer of the maximum message size; a frame that would
/// exceed it fails before more is read. Framing errors cannot be resynchronised safely,
/// so callers close the connection. A returned frame is valid until the next read.
/// </summary>
public sealed class SyslogFrameReader
{
    // MSG-LEN digits and the separating SP fit in this headroom for any allowed maximum.
    private const int Headroom = 8;
    private readonly Stream stream;
    private readonly int maximum;
    private readonly byte[] buffer;
    private int start;
    private int end;

    public SyslogFrameReader(Stream stream, int maximumMessageBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumMessageBytes, 1);
        this.stream = stream;
        maximum = maximumMessageBytes;
        buffer = new byte[maximumMessageBytes + Headroom];
    }

    /// <summary>
    /// Waits until the first byte of the next frame is buffered, skipping blank lines, so a
    /// caller can time an idle connection separately from a frame in progress. False at end
    /// of stream.
    /// </summary>
    public async ValueTask<bool> WaitForFrameAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            while (start < end && buffer[start] is (byte)'\n' or (byte)'\r')
            {
                start++;
            }

            if (start < end)
            {
                return true;
            }

            if (!await FillAsync(cancellationToken))
            {
                return false;
            }
        }
    }

    public async ValueTask<SyslogFrameResult> ReadFrameAsync(CancellationToken cancellationToken)
    {
        // Blank lines between frames (trailing CR LF from some senders) are not frames.
        while (true)
        {
            if (start == end && !await FillAsync(cancellationToken))
            {
                return SyslogFrameResult.End;
            }

            if (buffer[start] is not ((byte)'\n' or (byte)'\r'))
            {
                break;
            }

            start++;
        }

        byte first = buffer[start];
        if (first is >= (byte)'1' and <= (byte)'9')
        {
            return await ReadOctetCountedAsync(cancellationToken);
        }

        return first == (byte)'<'
            ? await ReadDelimitedAsync(cancellationToken)
            : SyslogFrameResult.Failed(SyslogFailures.FramingInvalid);
    }

    private async ValueTask<SyslogFrameResult> ReadOctetCountedAsync(CancellationToken cancellationToken)
    {
        int digits = 0;
        int length = 0;
        while (true)
        {
            if (start + digits == end && !await FillAsync(cancellationToken))
            {
                return SyslogFrameResult.Failed(SyslogFailures.FrameTruncated);
            }

            byte value = buffer[start + digits];
            if (value == (byte)' ')
            {
                break;
            }

            if (value is < (byte)'0' or > (byte)'9')
            {
                return SyslogFrameResult.Failed(SyslogFailures.OctetCountInvalid);
            }

            digits++;
            length = (length * 10) + (value - '0');
            if (length > maximum)
            {
                return SyslogFrameResult.Failed(SyslogFailures.FrameTooLarge);
            }
        }

        int total = digits + 1 + length;
        while (end - start < total)
        {
            if (!await FillAsync(cancellationToken))
            {
                return SyslogFrameResult.Failed(SyslogFailures.FrameTruncated);
            }
        }

        ReadOnlyMemory<byte> frame = buffer.AsMemory(start + digits + 1, length);
        start += total;
        return new SyslogFrameResult(frame, null, false);
    }

    private async ValueTask<SyslogFrameResult> ReadDelimitedAsync(CancellationToken cancellationToken)
    {
        int scanned = start;
        while (true)
        {
            int newline = Array.IndexOf(buffer, (byte)'\n', scanned, end - scanned);
            if (newline >= 0)
            {
                int length = newline - start;
                if (length > 0 && buffer[newline - 1] == (byte)'\r')
                {
                    length--;
                }

                if (length > maximum)
                {
                    return SyslogFrameResult.Failed(SyslogFailures.FrameTooLarge);
                }

                ReadOnlyMemory<byte> frame = buffer.AsMemory(start, length);
                start = newline + 1;
                return new SyslogFrameResult(frame, null, false);
            }

            // Allow one byte past the maximum for a CR before the LF.
            if (end - start > maximum + 1)
            {
                return SyslogFrameResult.Failed(SyslogFailures.FrameTooLarge);
            }

            int buffered = end - start;
            if (!await FillAsync(cancellationToken))
            {
                return SyslogFrameResult.Failed(SyslogFailures.FrameTruncated);
            }

            scanned = start + buffered;
        }
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
            throw new InvalidOperationException("Syslog frame buffer is full.");
        }

        int read = await stream.ReadAsync(buffer.AsMemory(end), cancellationToken);
        end += read;
        return read > 0;
    }
}

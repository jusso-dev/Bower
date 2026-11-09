using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bower.Source.File;

/// <summary>
/// Turns one line into the flat JSON record a signed pack parser reads (<c>PackRuntime</c>):
/// <c>id</c>, <c>input</c>, <c>path</c>, <c>offset</c>, <c>readAt</c>, then <c>message</c>
/// (text) or <c>json</c> (json-lines, the line's object). The record lives in memory for one
/// submission; it is never logged or persisted, and only the fields the pack parser maps
/// reach the envelope, after redaction.
/// </summary>
public static class FileTailRecord
{
    /// <summary>Nesting a json-lines object may use; the record adds one level (PackRuntime allows 16).</summary>
    public const int MaximumJsonDepth = 8;

    /// <summary>Stable, metadata-only reasons a line is not a record.</summary>
    public const string InvalidUtf8 = "file-line-invalid-utf8";
    public const string InvalidJson = "file-line-invalid-json";

    /// <summary>
    /// The record would exceed <see cref="MaximumRecordBytes"/> once JSON-escaped (a line within
    /// <c>maxLineBytes</c> can: a control character becomes six bytes). Counted as oversized.
    /// </summary>
    public const string TooLarge = "file-record-too-large";

    /// <summary>The largest record a pack parser reads (<c>PackRuntime.MaximumRecordBytes</c>; a test keeps them equal).</summary>
    public const int MaximumRecordBytes = 32 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <returns>The record, or null with a failure code when the line is malformed.</returns>
    public static string? TryBuild(
        FileTailInputOptions input,
        FileTailLine line,
        DateTimeOffset readAt,
        out string? failure)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(line);
        failure = null;
        string text;
        try
        {
            text = StrictUtf8.GetString(line.Bytes);
        }
        catch (DecoderFallbackException)
        {
            failure = InvalidUtf8;
            return null;
        }

        JsonDocument? document = null;
        try
        {
            if (input.IsJsonLines)
            {
                try
                {
                    document = JsonDocument.Parse(line.Bytes, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth });
                }
                catch (JsonException)
                {
                    failure = InvalidJson;
                    return null;
                }

                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    failure = InvalidJson;
                    return null;
                }
            }

            ArrayBufferWriter<byte> buffer = new();
            using (Utf8JsonWriter writer = new(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("id", EventId(input.Id, line.Fingerprint, line.StartOffset, line.Bytes));
                writer.WriteString("input", input.Id);
                writer.WriteString("path", input.Path);
                writer.WriteString("offset", line.StartOffset.ToString(CultureInfo.InvariantCulture));
                writer.WriteString("readAt", Format(readAt));
                if (document is not null)
                {
                    writer.WritePropertyName("json");
                    document.RootElement.WriteTo(writer);
                }
                else
                {
                    writer.WriteString("message", text);
                }

                writer.WriteEndObject();
            }

            if (buffer.WrittenCount > MaximumRecordBytes)
            {
                failure = TooLarge;
                return null;
            }

            return Encoding.UTF8.GetString(buffer.WrittenSpan);
        }
        catch (InvalidOperationException)
        {
            // An escaped lone surrogate parses but cannot be written as text.
            failure = InvalidJson;
            return null;
        }
        finally
        {
            document?.Dispose();
        }
    }

    /// <summary>
    /// <c>file-</c> + 32 hex characters of SHA-256 over input id, file fingerprint, the line's
    /// start offset and its bytes. Re-reading the same line after a crash, a backpressure
    /// rewind or a restart yields the same id, so the queue deduplicates it; the line bytes
    /// keep two files that happen to share their first 64 bytes from merging distinct lines.
    /// </summary>
    public static string EventId(string inputId, string fingerprint, long startOffset, ReadOnlySpan<byte> line)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(inputId));
        hash.AppendData([0x1F]);
        hash.AppendData(Encoding.UTF8.GetBytes(fingerprint));
        hash.AppendData([0x1F]);
        hash.AppendData(Encoding.UTF8.GetBytes(startOffset.ToString(CultureInfo.InvariantCulture)));
        hash.AppendData([0x1F]);
        hash.AppendData(line);
        return "file-" + Convert.ToHexStringLower(hash.GetHashAndReset())[..32];
    }

    /// <summary>UTC, microsecond precision (truncated), so the text is stable.</summary>
    public static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'ffffff'Z'", CultureInfo.InvariantCulture);
}

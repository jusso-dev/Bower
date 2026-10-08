using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Bower.Source.Aws;

public sealed record FirehoseLogObjectOptions
{
    public required string SourceId { get; init; }

    /// <summary>Upper bound on the decompressed object, so a gzip bomb cannot exhaust memory.</summary>
    public long MaximumDecompressedBytes { get; init; } = 64L * 1024 * 1024;

    public int MaximumLogEventBytes { get; init; } = 1_048_576;

    public int MaximumEnvelopes { get; init; } = 50_000;
}

/// <summary>Candidate Bower events found in an object, plus counts of what was skipped.</summary>
public sealed record FirehoseLogObject(IReadOnlyList<string> Envelopes, int LogEvents, int Skipped);

/// <summary>
/// Reads CloudWatch Logs data that Amazon Data Firehose delivered to S3 (gzip, possibly
/// several concatenated gzip members, each holding a subscription payload; or decompressed,
/// newline-delimited messages). Only log messages that are Bower event envelopes are kept;
/// everything else is ordinary application logging and is dropped here.
/// </summary>
public static class FirehoseLogObjectReader
{
    public static FirehoseLogObject Read(Stream content, FirehoseLogObjectOptions options)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(options);
        byte[] data = ReadBounded(content, options);

        List<string> envelopes = [];
        int logEvents = 0;
        int skipped = 0;

        void Consider(string message)
        {
            logEvents++;
            if (Encoding.UTF8.GetByteCount(message) > options.MaximumLogEventBytes
                || TryExtractEnvelope(message) is not { } envelope)
            {
                skipped++;
                return;
            }

            if (envelopes.Count >= options.MaximumEnvelopes)
            {
                throw new AwsTelemetryBatchTooLargeException(options.SourceId, envelopes.Count + 1, options.MaximumEnvelopes);
            }

            envelopes.Add(envelope);
        }

        if (!TryReadJsonSequence(data, Consider))
        {
            // Firehose message extraction writes raw messages, which need not be JSON.
            envelopes.Clear();
            logEvents = 0;
            skipped = 0;
            foreach (string line in Encoding.UTF8.GetString(data).Split('\n'))
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    Consider(line.TrimEnd('\r'));
                }
            }
        }

        return new FirehoseLogObject(envelopes, logEvents, skipped);
    }

    /// <summary>
    /// Returns the envelope JSON when a log message is a Bower event: either the whole message,
    /// a Lambda JSON log whose "message" is the envelope, or text with an envelope after a prefix.
    /// </summary>
    public static string? TryExtractEnvelope(string message)
    {
        int start = message.IndexOf('{', StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        if (TryReadObject(message.AsSpan(start)) is not { } document)
        {
            int marker = message.IndexOf("{\"schemaVersion\"", start + 1, StringComparison.Ordinal);
            if (marker < 0 || TryReadObject(message.AsSpan(marker)) is not { } fallback)
            {
                return null;
            }

            document = fallback;
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (IsEnvelope(root))
            {
                return root.GetRawText();
            }

            return root.TryGetProperty("message", out JsonElement inner) && IsEnvelope(inner)
                ? inner.GetRawText()
                : null;
        }
    }

    private static bool IsEnvelope(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty("schemaVersion", out JsonElement version) && version.ValueKind == JsonValueKind.String
        && element.TryGetProperty("eventId", out JsonElement id) && id.ValueKind == JsonValueKind.String
        && element.TryGetProperty("eventType", out JsonElement type) && type.ValueKind == JsonValueKind.String;

    private static JsonDocument? TryReadObject(ReadOnlySpan<char> text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text.ToArray());
        Utf8JsonReader reader = new(bytes, new JsonReaderOptions { MaxDepth = 32, AllowMultipleValues = true });
        try
        {
            return JsonDocument.TryParseValue(ref reader, out JsonDocument? document)
                && document.RootElement.ValueKind == JsonValueKind.Object
                    ? document
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool TryReadJsonSequence(byte[] data, Action<string> consider)
    {
        List<string> messages = [];
        Utf8JsonReader reader = new(data, new JsonReaderOptions { MaxDepth = 64, AllowMultipleValues = true });
        try
        {
            while (reader.Read())
            {
                using (JsonDocument document = JsonDocument.ParseValue(ref reader))
                {
                    JsonElement root = document.RootElement;
                    if (root.ValueKind != JsonValueKind.Object)
                    {
                        return false;
                    }

                    if (root.TryGetProperty("logEvents", out JsonElement logEvents) && logEvents.ValueKind == JsonValueKind.Array)
                    {
                        // CONTROL_MESSAGE payloads are CloudWatch reachability checks with no data.
                        if (root.TryGetProperty("messageType", out JsonElement type) && type.ValueEquals("CONTROL_MESSAGE"))
                        {
                            continue;
                        }

                        foreach (JsonElement logEvent in logEvents.EnumerateArray())
                        {
                            messages.Add(logEvent.TryGetProperty("message", out JsonElement message)
                                && message.ValueKind == JsonValueKind.String
                                    ? message.GetString()!
                                    : string.Empty);
                        }
                    }
                    else
                    {
                        messages.Add(root.GetRawText());
                    }
                }
            }
        }
        catch (JsonException)
        {
            return false;
        }

        foreach (string message in messages)
        {
            consider(message);
        }

        return true;
    }

    private static byte[] ReadBounded(Stream content, FirehoseLogObjectOptions options)
    {
        using MemoryStream raw = new();
        CopyBounded(content, raw, options);
        raw.Position = 0;
        bool gzip = raw.Length >= 2 && raw.GetBuffer()[0] == 0x1f && raw.GetBuffer()[1] == 0x8b;
        if (!gzip)
        {
            return raw.ToArray();
        }

        // GZipStream reads concatenated members, which is how Firehose writes CloudWatch Logs records.
        using GZipStream decompressed = new(raw, CompressionMode.Decompress);
        using MemoryStream output = new();
        try
        {
            CopyBounded(decompressed, output, options);
        }
        catch (InvalidDataException)
        {
            throw new AwsTelemetryMalformedRecordException(options.SourceId, JsonValueKind.Undefined);
        }

        return output.ToArray();
    }

    private static void CopyBounded(Stream source, Stream destination, FirehoseLogObjectOptions options)
    {
        byte[] buffer = new byte[81_920];
        long total = 0;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > options.MaximumDecompressedBytes)
            {
                throw new AwsTelemetryPayloadTooLargeException(
                    options.SourceId,
                    (int)Math.Min(total, int.MaxValue),
                    (int)Math.Min(options.MaximumDecompressedBytes, int.MaxValue));
            }

            destination.Write(buffer, 0, read);
        }
    }
}

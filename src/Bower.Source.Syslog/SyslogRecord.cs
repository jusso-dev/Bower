using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bower.Source.Syslog;

/// <summary>
/// Turns a parsed message into the flat JSON record a signed pack parser reads
/// (<c>PackRuntime</c>): string values only, at most 64 fields. The record lives in memory
/// for one submission; it is never logged or persisted, and only the fields the pack
/// parser maps can reach the envelope, after redaction.
/// </summary>
public static class SyslogRecord
{
    public const int MaximumFields = 64;

    /// <summary>A pack parser cannot read longer values, so they are left out of the record.</summary>
    public const int MaximumValueLength = 2048;

    public static string Build(
        SyslogMessage message,
        ReadOnlySpan<byte> frame,
        string listenerId,
        string protocol,
        string senderAddress,
        DateTimeOffset receivedAt)
    {
        ArgumentNullException.ThrowIfNull(message);
        string received = Format(receivedAt);
        List<KeyValuePair<string, string>> fields =
        [
            new("id", EventId(listenerId, senderAddress, frame, message.Timestamp is null ? received : null)),
            new("listener", listenerId),
            new("protocol", protocol),
            new("senderAddress", senderAddress),
            new("receivedAt", received),
            new("format", message.Format == SyslogFormat.Rfc5424 ? "rfc5424" : "rfc3164"),
            new("facility", message.Facility.ToString(CultureInfo.InvariantCulture)),
            new("severity", message.Severity.ToString(CultureInfo.InvariantCulture)),
            new("timestamp", message.Timestamp is { } timestamp ? Format(timestamp) : received)
        ];
        Add("hostname", message.Hostname);
        Add("appName", message.AppName);
        Add("procId", message.ProcId);
        Add("msgId", message.MessageId);
        Add("message", message.Message);
        foreach (SyslogStructuredElement element in message.StructuredData)
        {
            foreach (KeyValuePair<string, string> parameter in element.Parameters)
            {
                Add($"sd.{element.Id}.{parameter.Key}", parameter.Value);
            }
        }

        if (fields.Count > MaximumFields)
        {
            throw new SyslogFormatException(SyslogFailures.RecordTooLarge);
        }

        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            foreach (KeyValuePair<string, string> field in fields)
            {
                writer.WriteString(field.Key, field.Value);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);

        void Add(string name, string? value)
        {
            if (value is not null && value.Length <= MaximumValueLength)
            {
                fields.Add(new KeyValuePair<string, string>(name, value));
            }
        }
    }

    /// <summary>
    /// <c>syslog-</c> + 32 hex characters of SHA-256 over listener, sender and the exact
    /// frame bytes, so a retransmitted frame deduplicates. Without a message timestamp the
    /// receive time is included, because the record's time would differ on retransmit.
    /// </summary>
    internal static string EventId(string listenerId, string senderAddress, ReadOnlySpan<byte> frame, string? receivedAt)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(listenerId));
        hash.AppendData([0x1F]);
        hash.AppendData(Encoding.UTF8.GetBytes(senderAddress));
        hash.AppendData([0x1F]);
        hash.AppendData(frame);
        if (receivedAt is not null)
        {
            hash.AppendData([0x1F]);
            hash.AppendData(Encoding.UTF8.GetBytes(receivedAt));
        }

        return "syslog-" + Convert.ToHexStringLower(hash.GetHashAndReset())[..32];
    }

    /// <summary>UTC, microsecond precision (truncated), so both runtimes write identical text.</summary>
    internal static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'ffffff'Z'", CultureInfo.InvariantCulture);
}

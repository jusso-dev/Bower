using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Bower.Forwarding;

namespace Bower.Collector.Relay;

/// <summary>
/// Downstream collectors a relay accepts (BOWER_RELAY_DOWNSTREAMS_FILE). Each entry binds
/// one collector id to the SHA-256 pin of its client certificate. The mutual TLS handshake
/// refuses any other certificate, and a downstream can only submit events and open tunnels
/// as the collector id its pin names. Loaded once at start-up; a change needs a restart.
/// </summary>
/// <example>
/// <code>{"downstreams":[{"collectorId":"edge-01","certificateSha256":"3f2a…"}]}</code>
/// </example>
public sealed class RelayDownstreams
{
    public const int MaximumEntries = 1024;
    public const long MaximumFileBytes = 256 * 1024;
    private const string Invalid =
        "BOWER_RELAY_DOWNSTREAMS_FILE must be a JSON object with a downstreams array of 1 to 1024 " +
        "{collectorId, certificateSha256} entries, each pin a distinct SHA-256 hex value.";

    private readonly Dictionary<string, string> collectorByPin;

    private RelayDownstreams(Dictionary<string, string> collectorByPin) => this.collectorByPin = collectorByPin;

    /// <summary>Distinct collector ids, ordered.</summary>
    public IReadOnlyList<string> CollectorIds =>
        [.. collectorByPin.Values.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];

    public static RelayDownstreams Load(string path)
    {
        byte[] content;
        try
        {
            FileInfo file = new(path);
            if (!file.Exists || file.Length > MaximumFileBytes)
            {
                throw new InvalidOperationException(Invalid);
            }

            content = File.ReadAllBytes(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(Invalid);
        }

        return Parse(content);
    }

    public static RelayDownstreams Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length > MaximumFileBytes)
        {
            throw new InvalidOperationException(Invalid);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !TryGetSingle(document.RootElement, "downstreams", out JsonElement list)
                || list.ValueKind != JsonValueKind.Array
                || list.GetArrayLength() is < 1 or > MaximumEntries)
            {
                throw new InvalidOperationException(Invalid);
            }

            Dictionary<string, string> pins = new(StringComparer.Ordinal);
            foreach (JsonElement entry in list.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object
                    || !TryGetSingle(entry, "collectorId", out JsonElement id)
                    || !TryGetSingle(entry, "certificateSha256", out JsonElement pin)
                    || id.ValueKind != JsonValueKind.String
                    || pin.ValueKind != JsonValueKind.String
                    || !RelayProtocol.IsValidIdentifier(id.GetString())
                    || NormalisePin(pin.GetString()) is not { } normalised
                    || !pins.TryAdd(normalised, id.GetString()!))
                {
                    throw new InvalidOperationException(Invalid);
                }
            }

            return new RelayDownstreams(pins);
        }
        catch (JsonException)
        {
            throw new InvalidOperationException(Invalid);
        }
    }

    /// <summary>The collector id a presented certificate may act as, or null.</summary>
    public string? Resolve(X509Certificate2? certificate, DateTimeOffset now)
    {
        if (certificate is null || !RelayCertificates.IsUsableClientCertificate(certificate, now))
        {
            return null;
        }

        return collectorByPin.TryGetValue(RelayCertificates.Pin(certificate), out string? collectorId)
            ? collectorId
            : null;
    }

    /// <summary>64 hex digits, case-insensitive, optionally colon separated (openssl output).</summary>
    internal static string? NormalisePin(string? value)
    {
        if (value is null)
        {
            return null;
        }

        string compact = value.Replace(":", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
        return compact.Length == 64 && compact.All(character => char.IsAsciiHexDigitLower(character) || char.IsAsciiDigit(character))
            ? compact
            : null;
    }

    /// <summary>Exactly one property with this name (a repeated key is refused, not last-wins).</summary>
    private static bool TryGetSingle(JsonElement element, string name, out JsonElement value)
    {
        value = default;
        int count = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                value = property.Value;
                count++;
            }
        }

        return count == 1;
    }
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Bower.Contracts;

namespace Bower.Persistence;

public static class EventIdentity
{
    public static string Create(SecurityEventEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);
        // Length framing prevents delimiter collisions. Identity, never semantic similarity.
        string[] parts =
        [
            "bower-identity-v2",
            value.Collector?.Id ?? string.Empty,
            value.Collector?.SourceAdapter ?? string.Empty,
            value.Application?.Name ?? string.Empty,
            value.Application?.Environment ?? string.Empty,
            value.Application?.TenantId ?? string.Empty,
            value.Application?.Instance ?? string.Empty,
            value.Source?.Hostname ?? string.Empty,
            string.IsNullOrEmpty(value.EventOriginalId) ? "event" : "original",
            string.IsNullOrEmpty(value.EventOriginalId) ? value.EventId : value.EventOriginalId
        ];
        string material = string.Concat(parts.Select(part =>
            Encoding.UTF8.GetByteCount(part).ToString(CultureInfo.InvariantCulture) + ":" + part));
        return "sha256:v2:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }
}

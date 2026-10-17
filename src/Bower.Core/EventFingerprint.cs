using System.Security.Cryptography;
using System.Text;
using Bower.Contracts;

namespace Bower.Core;

public static class EventFingerprint
{
    public static string Create(SecurityEventEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);

        string stableMaterial = string.Join(
            '\u001f',
            value.EventOriginalId ?? string.Empty,
            value.EventType,
            value.EventAction,
            // Null only for invalid events that never reach the queue; never throw on them.
            value.Application?.Name ?? string.Empty,
            value.Application?.Environment ?? string.Empty,
            value.Application?.TenantId ?? string.Empty,
            value.Actor?.UserId ?? value.Actor?.Username ?? string.Empty,
            value.Target?.Type ?? string.Empty,
            value.Target?.Id ?? string.Empty,
            value.EventResult.ToString(),
            value.TimeGenerated.ToUniversalTime().ToString("O"));

        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.UTF8.GetBytes(stableMaterial), digest);
        return "sha256:" + Convert.ToHexStringLower(digest);
    }
}

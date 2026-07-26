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
            value.Application.Name,
            value.Application.Environment,
            value.Application.TenantId ?? string.Empty,
            value.Actor?.UserId ?? value.Actor?.Username ?? string.Empty,
            value.Target?.Type ?? string.Empty,
            value.Target?.Id ?? string.Empty,
            value.EventResult.ToString(),
            value.TimeGenerated.ToUniversalTime().ToString("O"));

        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(stableMaterial));
        return $"sha256:{Convert.ToHexStringLower(digest)}";
    }
}

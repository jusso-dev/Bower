using System.Security.Cryptography;
using System.Text;

namespace Bower.Redaction;

public sealed class KeyedFieldHasher
{
    private readonly byte[] key;

    public KeyedFieldHasher(ReadOnlySpan<byte> key)
    {
        if (key.Length < 32)
        {
            throw new ArgumentException("Key must contain at least 32 bytes.", nameof(key));
        }

        this.key = key.ToArray();
    }

    public string Hash(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        byte[] digest = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));
        return $"hmac-sha256:{Convert.ToHexStringLower(digest)}";
    }
}

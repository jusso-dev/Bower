using System.Security.Cryptography;
using System.Text;

namespace Bower.Redaction.Privacy;

/// <summary>Applies <see cref="PrivacyAction"/> to a matched substring. Never logs originals.</summary>
public sealed class PolicyApplicator
{
    private readonly PrivacyPolicy policy;
    private readonly KeyedFieldHasher? hmacHasher;

    public PolicyApplicator(PrivacyPolicy policy)
    {
        this.policy = policy;
        hmacHasher = policy.HmacKey is { Length: >= 32 } key
            ? new KeyedFieldHasher(key)
            : null;
        if (hmacHasher is null && policy.UsesAction(PrivacyAction.Hmac))
        {
            // Fail closed: an unkeyed fallback would silently weaken pseudonymisation.
            throw new InvalidOperationException(
                "Privacy policy uses the Hmac action but no HMAC key of at least 32 bytes is configured.");
        }
    }

    public string Apply(string original, DetectionMatch match, PrivacyAction action)
    {
        string span = original.Substring(match.Start, match.Length);
        return action switch
        {
            PrivacyAction.Allow => span,
            PrivacyAction.AlertOnly => span,
            PrivacyAction.Remove => string.Empty,
            PrivacyAction.Replace => policy.ReplacementText,
            PrivacyAction.Mask => Mask(span, match.DetectorId),
            PrivacyAction.Sha256 => Sha256(span),
            PrivacyAction.Hmac => hmacHasher!.Hash(span, policy.HmacKeyId),
            PrivacyAction.Encrypt => Encrypt(span) ?? string.Empty,
            _ => policy.ReplacementText
        };
    }

    /// <summary>Applies an action to a whole field value (field rules and length limits).</summary>
    public string? ApplyToValue(string value, PrivacyAction action, int? maxLength = null)
    {
        return action switch
        {
            PrivacyAction.Allow or PrivacyAction.AlertOnly => value,
            PrivacyAction.Remove => null,
            PrivacyAction.Replace => policy.ReplacementText,
            PrivacyAction.Mask => Mask(value, string.Empty),
            PrivacyAction.Sha256 => Sha256(value),
            PrivacyAction.Hmac => value.Length == 0 ? value : hmacHasher!.Hash(value, policy.HmacKeyId),
            PrivacyAction.Encrypt => Encrypt(value),
            PrivacyAction.Truncate => Truncate(value, maxLength ?? policy.MaximumFieldLength),
            _ => policy.ReplacementText
        };
    }

    internal static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength)
        {
            return value;
        }

        // Never split a surrogate pair.
        int cut = maxLength;
        if (cut > 0 && char.IsHighSurrogate(value[cut - 1]))
        {
            cut--;
        }

        return value[..cut];
    }

    public static string ActionLabel(PrivacyAction action) => action switch
    {
        PrivacyAction.Allow => "Allow",
        PrivacyAction.Remove => "Removed",
        PrivacyAction.Replace => "Replaced",
        PrivacyAction.Mask => "Masked",
        PrivacyAction.Sha256 => "SHA256",
        PrivacyAction.Hmac => "HMAC",
        PrivacyAction.Encrypt => "Encrypted",
        PrivacyAction.AlertOnly => "AlertOnly",
        PrivacyAction.Truncate => "Truncated",
        _ => action.ToString()
    };

    private static string Sha256(string value)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return "sha256:" + Convert.ToHexStringLower(digest);
    }

    private string? Encrypt(string value)
    {
        if (policy.EncryptionKey is not { Length: 32 } key)
        {
            return null;
        }

        byte[] plaintext = Encoding.UTF8.GetBytes(value);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using AesGcm aes = new(key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return "enc:aesgcm:" +
               Convert.ToBase64String(nonce) + ":" +
               Convert.ToBase64String(tag) + ":" +
               Convert.ToBase64String(ciphertext);
    }

    private static string Mask(string value, string detectorId)
    {
        if (detectorId == DetectorIds.Email)
        {
            int at = value.IndexOf('@');
            if (at > 0)
            {
                return value[0] + "***" + value[at..];
            }
        }

        if (detectorId == DetectorIds.CreditCard)
        {
            string cardDigits = Validation.ChecksumAlgorithms.DigitsOnly(value);
            if (cardDigits.Length >= 4)
            {
                return "****-****-****-" + cardDigits[^4..];
            }
        }

        if (detectorId is DetectorIds.Tfn or DetectorIds.Medicare
            or DetectorIds.Ihi or DetectorIds.Crn or DetectorIds.Abn or DetectorIds.Acn
            or DetectorIds.BsbAccount)
        {
            string digits = Validation.ChecksumAlgorithms.DigitsOnly(value);
            if (digits.Length >= 4)
            {
                return new string('*', Math.Max(0, digits.Length - 4)) + digits[^4..];
            }
        }

        if (value.Length <= 4)
        {
            return "****";
        }

        return value[..2] + new string('*', value.Length - 4) + value[^2..];
    }
}

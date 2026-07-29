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
            PrivacyAction.Hmac => hmacHasher?.Hash(span) ?? Sha256(span),
            PrivacyAction.Encrypt => Encrypt(span) ?? string.Empty,
            _ => policy.ReplacementText
        };
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

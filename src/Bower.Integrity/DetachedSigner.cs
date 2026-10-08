using System.Security.Cryptography;
using System.Text;

namespace Bower.Integrity;

/// <summary>A detached ECDSA P-256 / SHA-256 signature over canonical bytes.</summary>
public sealed record DetachedSignature(string Algorithm, string KeyId, string Value)
{
    public const string EcdsaP256Sha256 = "ES256";
}

/// <summary>
/// Signs and verifies Bower artefacts (packs, evidence bundles) with ECDSA P-256 keys in
/// PEM form. Private keys never leave the signer; verification needs only public keys.
/// </summary>
public static class DetachedSigner
{
    public static DetachedSignature Sign(ReadOnlySpan<byte> content, string privateKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPem);
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(privateKeyPem);
        RequireP256(key);
        byte[] signature = key.SignData(content, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new DetachedSignature(DetachedSignature.EcdsaP256Sha256, KeyId(key), Convert.ToBase64String(signature));
    }

    /// <summary>True only when a trusted key with the signature's key id verifies the content.</summary>
    public static bool Verify(
        ReadOnlySpan<byte> content,
        DetachedSignature signature,
        IEnumerable<string> trustedPublicKeyPems)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        if (!string.Equals(signature.Algorithm, DetachedSignature.EcdsaP256Sha256, StringComparison.Ordinal))
        {
            return false;
        }

        byte[] value;
        try
        {
            value = Convert.FromBase64String(signature.Value);
        }
        catch (FormatException)
        {
            return false;
        }

        foreach (string pem in trustedPublicKeyPems)
        {
            using ECDsa key = ECDsa.Create();
            try
            {
                key.ImportFromPem(pem);
            }
            catch (Exception exception) when (exception is ArgumentException or CryptographicException)
            {
                continue;
            }

            if (key.KeySize != 256
                || !string.Equals(KeyId(key), signature.KeyId, StringComparison.Ordinal))
            {
                continue;
            }

            return key.VerifyData(content, value, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        return false;
    }

    /// <summary>Creates a new P-256 key pair as PKCS#8 private and SPKI public PEM.</summary>
    public static (string PrivateKeyPem, string PublicKeyPem, string KeyId) GenerateKeyPair()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key.ExportPkcs8PrivateKeyPem(), key.ExportSubjectPublicKeyInfoPem(), KeyId(key));
    }

    /// <summary>Stable key id: first 16 hex characters of SHA-256 over the SPKI bytes.</summary>
    public static string KeyId(ECDsa key) =>
        Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()))[..16];

    public static string KeyIdFromPublicKeyPem(string publicKeyPem)
    {
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        return KeyId(key);
    }

    private static void RequireP256(ECDsa key)
    {
        if (key.KeySize != 256)
        {
            throw new CryptographicException("Signing keys must be ECDSA P-256.");
        }
    }
}

public static class Sha256Hex
{
    public static string Of(ReadOnlySpan<byte> content) =>
        Convert.ToHexStringLower(SHA256.HashData(content));

    public static string Of(string content) => Of(Encoding.UTF8.GetBytes(content));
}

using System.Buffers.Text;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Integrity;

namespace Bower.Management.Api;

/// <summary>
/// Enrolment for collectors without an Azure identity (#109). An administrator issues a
/// one-time token (stored as a SHA-256 hash, single use, bound to an environment and
/// optionally a collector id). The collector exchanges it, with a P-256 public key it
/// generated, for a key-bound credential. The private key never leaves the collector, and
/// management never holds a secret that could authenticate as the collector. Every request
/// after that carries a short-lived assertion signed by the collector's key.
/// </summary>
public static class CollectorEnrolment
{
    /// <summary><c>bwe1.&lt;16 hex id&gt;.&lt;43 base64url secret&gt;</c>: the id is public, the whole token is secret.</summary>
    public const string TokenPrefix = "bwe1.";

    /// <summary>Bearer value prefix that routes a request to the collector credential scheme.</summary>
    public const string AssertionPrefix = "bwc1.";

    public const string AssertionKind = "bower.collector-assertion/v1";

    /// <summary>Principal object id of an enrolled collector: never a GUID, so never an Entra object id.</summary>
    public const string PrincipalPrefix = "enrolled:";

    public const string CollectorIdClaim = "bower_collector_id";
    public const string CredentialIdClaim = "bower_credential_id";

    public const int DefaultTokenLifetimeHours = 24;
    public const int MaximumTokenLifetimeHours = 168;

    /// <summary>Credential lifetime. Collectors rotate when 10 days remain.</summary>
    public static readonly TimeSpan CredentialLifetime = TimeSpan.FromDays(30);

    /// <summary>Longest assertion validity window accepted (collectors sign 5 minutes).</summary>
    public static readonly TimeSpan MaximumAssertionLifetime = TimeSpan.FromMinutes(10);

    /// <summary>Clock skew tolerated on an assertion's <c>issuedAt</c>.</summary>
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);

    public const int MaximumAssertionLength = 2048;
    public const int MaximumPublicKeyLength = 1024;

    private const int TokenSecretBytes = 32;
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    /// <summary>A new token and its public id. The caller shows the token once and stores only its hash.</summary>
    public static string NewToken(out string id)
    {
        id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        return TokenPrefix + id + "." + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenSecretBytes));
    }

    /// <summary>True for a well-formed token; <paramref name="id"/> is its public id.</summary>
    public static bool TryParseToken(string? token, out string id)
    {
        id = string.Empty;
        if (token is not { Length: 65 } || !token.StartsWith(TokenPrefix, StringComparison.Ordinal) || token[21] != '.')
        {
            return false;
        }

        string candidate = token[5..21];
        string secret = token[22..];
        if (!IsHex(candidate, 16) || !Base64Url.IsValid(secret, out int length) || length != TokenSecretBytes)
        {
            return false;
        }

        id = candidate;
        return true;
    }

    public static string HashToken(string token) => Sha256Hex.Of(token);

    public static string PrincipalFor(string collectorId) => PrincipalPrefix + collectorId;

    /// <summary>
    /// An ECDSA P-256 SubjectPublicKeyInfo PEM of bounded size, returned normalised with
    /// its key id (the credential id). Anything else, private keys included, is refused.
    /// </summary>
    public static bool TryReadPublicKey(string? pem, out string normalized, out string keyId)
    {
        normalized = string.Empty;
        keyId = string.Empty;
        if (string.IsNullOrWhiteSpace(pem) || pem.Length > MaximumPublicKeyLength
            || !pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal)
            || pem.Contains("PRIVATE", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            using ECDsa key = ECDsa.Create();
            key.ImportFromPem(pem);
            if (key.KeySize != 256)
            {
                return false;
            }

            normalized = key.ExportSubjectPublicKeyInfoPem();
            keyId = DetachedSigner.KeyId(key);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            return false;
        }
    }

    /// <summary>True when the request carries a collector assertion rather than an Entra token.</summary>
    public static bool HasAssertion(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string? header = request.Headers.Authorization;
        return header is not null
            && header.StartsWith("Bearer " + AssertionPrefix, StringComparison.Ordinal);
    }

    /// <summary>
    /// False when an enrolled collector names any collector other than itself. Entra
    /// principals carry no collector claim and stay bound by the stored principal id.
    /// </summary>
    public static bool MayActFor(ClaimsPrincipal user, string collectorId)
    {
        ArgumentNullException.ThrowIfNull(user);
        string? bound = user.FindFirstValue(CollectorIdClaim);
        return bound is null || string.Equals(bound, collectorId, StringComparison.Ordinal);
    }

    /// <summary>Canonical JSON of exactly the signed assertion fields. Must match both collectors byte for byte.</summary>
    public static byte[] AssertionBytes(
        string collectorId,
        string credentialId,
        string issuedAt,
        string expiresAt,
        string nonce) =>
        CanonicalJson.Bytes(new JsonObject
        {
            ["kind"] = AssertionKind,
            ["collectorId"] = collectorId,
            ["credentialId"] = credentialId,
            ["issuedAt"] = issuedAt,
            ["expiresAt"] = expiresAt,
            ["nonce"] = nonce
        });

    /// <summary>
    /// Reads <c>bwc1.&lt;base64url canonical payload&gt;.&lt;base64url P1363 signature&gt;</c>.
    /// Returns null and the parsed assertion, or a refusal code. The signature is checked
    /// later against the stored public key of the named credential.
    /// </summary>
    public static string? TryReadAssertion(string? value, DateTimeOffset now, out CollectorAssertion? assertion)
    {
        assertion = null;
        if (value is null || value.Length > MaximumAssertionLength
            || !value.StartsWith(AssertionPrefix, StringComparison.Ordinal))
        {
            return CredentialRefusals.Malformed;
        }

        string[] parts = value[AssertionPrefix.Length..].Split('.');
        if (parts.Length != 2
            || !Base64Url.IsValid(parts[0], out int payloadLength) || payloadLength is 0 or > 1024
            || !Base64Url.IsValid(parts[1], out int signatureLength) || signatureLength != 64)
        {
            return CredentialRefusals.Malformed;
        }

        byte[] payload = Base64Url.DecodeFromChars(parts[0]);
        byte[] signature = Base64Url.DecodeFromChars(parts[1]);
        string? collectorId, credentialId, issuedText, expiresText, nonce;
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 2 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.EnumerateObject().Count() != 6
                || Text(root, "kind") != AssertionKind)
            {
                return CredentialRefusals.Malformed;
            }

            collectorId = Text(root, "collectorId");
            credentialId = Text(root, "credentialId");
            issuedText = Text(root, "issuedAt");
            expiresText = Text(root, "expiresAt");
            nonce = Text(root, "nonce");
        }
        catch (JsonException)
        {
            return CredentialRefusals.Malformed;
        }

        if (collectorId is not { Length: > 0 and <= 128 } || !IsHex(credentialId, 16) || !IsHex(nonce, 32)
            || !TryParseTimestamp(issuedText, out DateTimeOffset issuedAt)
            || !TryParseTimestamp(expiresText, out DateTimeOffset expiresAt)
            // Exactly the canonical bytes: no duplicate keys, extra whitespace or other forms.
            || !payload.AsSpan().SequenceEqual(AssertionBytes(collectorId, credentialId!, issuedText!, expiresText!, nonce!)))
        {
            return CredentialRefusals.Malformed;
        }

        if (issuedAt > now + MaximumClockSkew)
        {
            return CredentialRefusals.NotYetValid;
        }

        if (expiresAt <= now)
        {
            return CredentialRefusals.Expired;
        }

        if (expiresAt <= issuedAt || expiresAt - issuedAt > MaximumAssertionLifetime)
        {
            return CredentialRefusals.InvalidLifetime;
        }

        assertion = new CollectorAssertion(collectorId, credentialId!, issuedAt, expiresAt, payload, signature);
        return null;
    }

    /// <summary>UTC with seven fractional digits and a <c>Z</c> suffix: the only accepted form.</summary>
    public static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);

    private static bool TryParseTimestamp(string? text, out DateTimeOffset value)
    {
        value = default;
        return text is not null && DateTimeOffset.TryParseExact(
            text,
            TimestampFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out value);
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool IsHex(string? value, int length) =>
        value is not null && value.Length == length
        && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');
}

/// <summary>A parsed, time-valid collector assertion whose signature is not yet checked.</summary>
public sealed record CollectorAssertion(
    string CollectorId,
    string CredentialId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    byte[] Payload,
    byte[] Signature)
{
    /// <summary>True only when the credential's public key verifies the canonical payload.</summary>
    public bool VerifiedBy(string publicKeyPem) =>
        DetachedSigner.Verify(
            Payload,
            new DetachedSignature(DetachedSignature.EcdsaP256Sha256, CredentialId, Convert.ToBase64String(Signature)),
            [publicKeyPem]);
}

/// <summary>Why a collector credential was refused. Logged as codes only, never the assertion.</summary>
public static class CredentialRefusals
{
    public const string Malformed = "malformed-assertion";
    public const string NotYetValid = "not-yet-valid";
    public const string Expired = "expired-assertion";
    public const string InvalidLifetime = "invalid-lifetime";
    public const string UnknownCredential = "unknown-credential";
    public const string WrongCollector = "wrong-collector";
    public const string CredentialExpired = "credential-expired";
    public const string CredentialRetired = "credential-retired";
    public const string CredentialRevoked = "credential-revoked";
    public const string InvalidSignature = "invalid-signature";
}

/// <summary>Why an enrolment token was refused. Audited as <c>enrolment-token.refused:&lt;code&gt;</c>.</summary>
public static class EnrolmentRefusals
{
    public const string Malformed = "malformed";
    public const string Unknown = "unknown";
    public const string Invalid = "invalid";
    public const string Revoked = "revoked";
    public const string Used = "used";
    public const string Expired = "expired";
    public const string WrongEnvironment = "wrong-environment";
    public const string WrongCollector = "wrong-collector";
    public const string IdentityConflict = "identity-conflict";
    public const string CollectorNotEnrollable = "collector-not-enrollable";
    public const string KeyReused = "key-reused";
}

/// <summary>Enrolment token states returned by the API (computed at read time).</summary>
public static class EnrolmentTokenStatus
{
    public const string Active = "active";
    public const string Used = "used";
    public const string Expired = "expired";
    public const string Revoked = "revoked";
}

/// <summary>Collector credential states. <c>expired</c> is computed at read time.</summary>
public static class CollectorCredentialStatus
{
    public const string Active = "active";
    public const string Retired = "retired";
    public const string Revoked = "revoked";
    public const string Expired = "expired";
}

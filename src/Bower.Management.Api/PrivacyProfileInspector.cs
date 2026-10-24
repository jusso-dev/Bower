using System.Security.Cryptography;
using Bower.Redaction.Privacy;
using YamlDotNet.RepresentationModel;

namespace Bower.Management.Api;

/// <summary>A privacy profile that passed the loader and the management version rules.</summary>
public sealed record PrivacyProfileCandidate(
    string ProfileId,
    string Version,
    string? Description,
    string Content,
    string ContentHash);

/// <summary>A submission rejected for a Bower-authored, client-safe reason (HTTP 400).</summary>
public sealed class PrivacyProfileValidationException(string message) : Exception(message);

/// <summary>
/// Validates and previews privacy profiles for the management API. Validation uses the
/// collector's own loader with a random throwaway HMAC key (as pack validation does), so a
/// profile accepted here loads on a collector with its real key. Nothing here is logged or
/// persisted; loader messages are Bower-authored and contain no secrets.
/// </summary>
public static class PrivacyProfileInspector
{
    public const int MaximumSampleBytes = 65_536;
    public const int MaximumProfileIdLength = 128;
    public const int MaximumVersionLength = 64;

    /// <summary>Loads <paramref name="content"/> or throws <see cref="PrivacyProfileValidationException"/>.</summary>
    public static (PrivacyProfileCandidate Candidate, LoadedPrivacyProfile Loaded) Load(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            throw new PrivacyProfileValidationException("Privacy profile content is required.");
        }

        LoadedPrivacyProfile loaded;
        try
        {
            loaded = PrivacyProfileLoader.Load(content, RandomNumberGenerator.GetBytes(32), "validation");
        }
        catch (Exception exception) when (exception is InvalidDataException
            or InvalidOperationException
            or ArgumentException)
        {
            throw new PrivacyProfileValidationException(exception.Message);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Unexpected parser failures can carry internal detail: fixed message only.
            throw new PrivacyProfileValidationException("Privacy profile is invalid.");
        }

        if (string.IsNullOrWhiteSpace(loaded.Id) || loaded.Id.Length > MaximumProfileIdLength)
        {
            throw new PrivacyProfileValidationException(
                $"Privacy profile metadata.id must be 1-{MaximumProfileIdLength} characters.");
        }

        if (!ProfileSemanticVersion.TryParse(loaded.Version, out _))
        {
            throw new PrivacyProfileValidationException("Privacy profile version must be MAJOR.MINOR.PATCH.");
        }

        return (
            new PrivacyProfileCandidate(loaded.Id, loaded.Version, Describe(content).Description, content, loaded.Hash),
            loaded);
    }

    /// <summary>Validation summary of the content alone; callers add the version-order check.</summary>
    public static PrivacyProfileValidation Validate(string? content)
    {
        try
        {
            (PrivacyProfileCandidate candidate, LoadedPrivacyProfile loaded) = Load(content);
            ProfileFacts facts = Describe(candidate.Content);
            return new PrivacyProfileValidation(
                true,
                [],
                candidate.ProfileId,
                candidate.Version,
                candidate.ContentHash,
                [.. loaded.Policy.CustomDetectors.Select(detector => new PrivacyProfileCustomDetectorSummary(
                    detector.Id, detector.Description, detector.Action.ToString()))],
                loaded.Policy.SecretFieldNames.Count,
                facts.DetectorOverrides,
                loaded.Policy.FieldRules.Count);
        }
        catch (PrivacyProfileValidationException exception)
        {
            return new PrivacyProfileValidation(false, [exception.Message], null, null, null, [], 0, 0, 0);
        }
    }

    /// <summary>
    /// Redacts <paramref name="sample"/> with the candidate profile and a random per-request
    /// HMAC key, so preview pseudonyms never match production values.
    /// </summary>
    public static PrivacyProfilePreview Preview(string? content, string sample)
    {
        LoadedPrivacyProfile loaded;
        try
        {
            loaded = Load(content).Loaded;
        }
        catch (PrivacyProfileValidationException exception)
        {
            return new PrivacyProfilePreview(false, [exception.Message], null, []);
        }

        PrivacyScanResult result = CreateEngine(loaded.Policy).RedactJson(sample);
        if (!result.Succeeded)
        {
            return new PrivacyProfilePreview(false, [SampleError(result.FailureCode)], null, []);
        }

        return new PrivacyProfilePreview(
            true,
            [],
            result.RedactedJson,
            [.. result.Findings.Select(finding => new PrivacyProfilePreviewFinding(
                finding.DetectorId,
                PolicyApplicator.ActionLabel(finding.Action),
                finding.Path))]);
    }

    /// <summary>Null when <paramref name="version"/> is greater than <paramref name="latest"/> (or there is none).</summary>
    public static string? RequireGreater(string version, string? latest) =>
        latest is null
        || !ProfileSemanticVersion.TryParse(latest, out ProfileSemanticVersion previous)
        || !ProfileSemanticVersion.TryParse(version, out ProfileSemanticVersion next)
        || next > previous
            ? null
            : $"Privacy profile version must be greater than {latest}.";

    private static string SampleError(string? failureCode) =>
        failureCode switch
        {
            "empty-payload" => "Preview sample is empty.",
            "invalid-json" => "Preview sample is not valid JSON.",
            "root-must-be-object" => "Preview sample must be a JSON object.",
            "payload-too-large" => "Preview sample is too large.",
            _ => "Preview sample could not be redacted."
        };

    // Built-in plus the profile's custom detectors and the field-name detector extended with
    // its secret field names, exactly as JsonEventRedactor(PrivacyPolicy) builds them.
    private static PrivacyEngine CreateEngine(PrivacyPolicy policy) => new(policy);

    private static ProfileFacts Describe(string content)
    {
        // The strict loader already accepted this document, so it is one well-formed
        // mapping; read only the metadata the loader does not expose.
        YamlStream stream = [];
        try
        {
            stream.Load(new StringReader(content));
        }
        catch (YamlDotNet.Core.YamlException)
        {
            return new ProfileFacts(null, 0);
        }

        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            return new ProfileFacts(null, 0);
        }

        string? description = Child(root, "metadata") is YamlMappingNode metadata
            && Child(metadata, "description") is YamlScalarNode scalar
            ? scalar.Value
            : null;
        int detectorOverrides = Child(root, "detectors") is YamlMappingNode detectors ? detectors.Children.Count : 0;
        return new ProfileFacts(description, detectorOverrides);
    }

    private static YamlNode? Child(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out YamlNode? value) ? value : null;

    private sealed record ProfileFacts(string? Description, int DetectorOverrides);
}

/// <summary>MAJOR.MINOR.PATCH with non-negative integers and no leading zeros (except 0).</summary>
public readonly record struct ProfileSemanticVersion(string Major, string Minor, string Patch)
    : IComparable<ProfileSemanticVersion>
{
    public static bool TryParse(string? value, out ProfileSemanticVersion version)
    {
        version = default;
        if (string.IsNullOrEmpty(value) || value.Length > PrivacyProfileInspector.MaximumVersionLength)
        {
            return false;
        }

        string[] parts = value.Split('.');
        if (parts.Length != 3 || !parts.All(IsNumber))
        {
            return false;
        }

        version = new ProfileSemanticVersion(parts[0], parts[1], parts[2]);
        return true;
    }

    public int CompareTo(ProfileSemanticVersion other)
    {
        int major = CompareNumber(Major, other.Major);
        if (major != 0)
        {
            return major;
        }

        int minor = CompareNumber(Minor, other.Minor);
        return minor != 0 ? minor : CompareNumber(Patch, other.Patch);
    }

    public override string ToString() => $"{Major}.{Minor}.{Patch}";

    public static bool operator <(ProfileSemanticVersion left, ProfileSemanticVersion right) => left.CompareTo(right) < 0;

    public static bool operator <=(ProfileSemanticVersion left, ProfileSemanticVersion right) => left.CompareTo(right) <= 0;

    public static bool operator >(ProfileSemanticVersion left, ProfileSemanticVersion right) => left.CompareTo(right) > 0;

    public static bool operator >=(ProfileSemanticVersion left, ProfileSemanticVersion right) => left.CompareTo(right) >= 0;

    private static bool IsNumber(string part) =>
        part.Length > 0
        && part.All(char.IsAsciiDigit)
        && (part.Length == 1 || part[0] != '0');

    // Canonical digit strings (no leading zeros): longer is larger, then ordinal.
    private static int CompareNumber(string left, string right) =>
        left.Length != right.Length
            ? left.Length.CompareTo(right.Length)
            : string.CompareOrdinal(left, right);
}

/// <summary>Signs managed privacy profile deployments with the configured P-256 key.</summary>
public sealed class ManagedPrivacyProfileSigner
{
    public const string KeyFileSetting = "BOWER_MANAGEMENT_PROFILE_SIGNING_KEY_FILE";

    private readonly string? privateKeyPem;

    private ManagedPrivacyProfileSigner(string? privateKeyPem) => this.privateKeyPem = privateKeyPem;

    public bool Configured => privateKeyPem is not null;

    /// <summary>
    /// Unset path: signing is not configured (the deployment endpoint returns 503). A set
    /// path that is not a readable P-256 private key fails start-up. Never logs the key.
    /// </summary>
    public static ManagedPrivacyProfileSigner FromFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return new ManagedPrivacyProfileSigner(null);
        }

        try
        {
            string pem = File.ReadAllText(path);
            // Proves the key is a usable P-256 private key before the host starts.
            _ = Bower.Integrity.DetachedSigner.Sign([], pem);
            return new ManagedPrivacyProfileSigner(pem);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or CryptographicException)
        {
            throw new InvalidOperationException(
                $"{KeyFileSetting} must name a readable ECDSA P-256 private key PEM file.");
        }
    }

    public ManagedPrivacyProfile Sign(
        string collectorId,
        string versionId,
        string profileId,
        string version,
        string contentHash,
        string content,
        DateTimeOffset issuedAt)
    {
        if (privateKeyPem is null)
        {
            throw new InvalidOperationException("Managed privacy profile signing is not configured.");
        }

        string issued = issuedAt.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        byte[] payload = SignedBytes(collectorId, versionId, profileId, version, contentHash, content, issued);
        return new ManagedPrivacyProfile(
            collectorId,
            versionId,
            profileId,
            version,
            contentHash,
            content,
            issued,
            Bower.Integrity.DetachedSigner.Sign(payload, privateKeyPem));
    }

    /// <summary>Canonical JSON of exactly the signed fields (everything but the signature).</summary>
    public static byte[] SignedBytes(
        string collectorId,
        string versionId,
        string profileId,
        string version,
        string contentHash,
        string content,
        string issuedAt) =>
        Bower.Integrity.CanonicalJson.Bytes(new System.Text.Json.Nodes.JsonObject
        {
            ["collectorId"] = collectorId,
            ["versionId"] = versionId,
            ["profileId"] = profileId,
            ["version"] = version,
            ["contentHash"] = contentHash,
            ["content"] = content,
            ["issuedAt"] = issuedAt
        });
}

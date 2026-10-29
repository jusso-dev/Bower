using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Bower.Management.Api;

/// <summary>
/// Signs approved source setup configuration with the configured P-256 key. Unset: approval
/// still works and the signed download answers 503. A set path that is not a readable P-256
/// private key fails start-up. Never logs the key.
/// </summary>
public sealed class SourceSetupSigner
{
    public const string KeyFileSetting = "BOWER_MANAGEMENT_SOURCE_SIGNING_KEY_FILE";
    public const string Kind = "bower.source-setup/v1";

    private readonly string? privateKeyPem;

    private SourceSetupSigner(string? privateKeyPem) => this.privateKeyPem = privateKeyPem;

    public bool Configured => privateKeyPem is not null;

    public static SourceSetupSigner FromFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return new SourceSetupSigner(null);
        }

        try
        {
            string pem = File.ReadAllText(path);
            _ = Bower.Integrity.DetachedSigner.Sign([], pem);
            return new SourceSetupSigner(pem);
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

    /// <summary>Signs an approved request. The approval timestamp is the review time, so every download signs the same fields.</summary>
    public SignedSourceSetup Sign(SourceSetupRequestDetail request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (privateKeyPem is null)
        {
            throw new InvalidOperationException("Source setup signing is not configured.");
        }

        if (request.Status != SourceSetupRequestStatus.Approved || request.ReviewedAt is not { } approvedAt)
        {
            throw new InvalidOperationException("Only an approved source setup request can be signed.");
        }

        string approved = approvedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        return new SignedSourceSetup(
            Kind,
            request.Id,
            request.CollectorId,
            request.Type,
            request.ContentHash,
            request.Plan.Files,
            request.Plan.Variables,
            request.Plan.Snippets,
            request.Plan.Verification,
            approved,
            Bower.Integrity.DetachedSigner.Sign(
                SignedBytes(request.Id, request.CollectorId, request.Type, request.ContentHash, request.Plan.Files, request.Plan.Variables, request.Plan.Snippets, request.Plan.Verification, approved),
                privateKeyPem));
    }

    /// <summary>Canonical JSON of every signed field: kind, requestId, collectorId, sourceType, contentHash, files, variables, sender snippets, verification and approvedAt.</summary>
    public static byte[] SignedBytes(
        string requestId,
        string collectorId,
        string sourceType,
        string contentHash,
        IReadOnlyList<SourceSetupFile> files,
        IReadOnlyList<SourceSetupVariable> variables,
        IReadOnlyList<SourceSetupSnippet> snippets,
        SourceSetupVerification verification,
        string approvedAt) =>
        Bower.Integrity.CanonicalJson.Bytes(new JsonObject
        {
            ["kind"] = Kind,
            ["requestId"] = requestId,
            ["collectorId"] = collectorId,
            ["sourceType"] = sourceType,
            ["contentHash"] = contentHash,
            ["files"] = new JsonArray([.. files.Select(file => (JsonNode)new JsonObject
            {
                ["name"] = file.Name,
                ["installPath"] = file.InstallPath,
                ["description"] = file.Description,
                ["content"] = file.Content
            })]),
            ["variables"] = SourceSetupRegistry.Variables(variables),
            ["snippets"] = new JsonArray([.. snippets.Select(snippet => (JsonNode)new JsonObject
            {
                ["title"] = snippet.Title,
                ["description"] = snippet.Description,
                ["language"] = snippet.Language,
                ["content"] = snippet.Content
            })]),
            ["verification"] = new JsonObject
            {
                ["kind"] = verification.Kind,
                ["reportId"] = verification.ReportId,
                ["description"] = verification.Description
            },
            ["approvedAt"] = approvedAt
        });
}

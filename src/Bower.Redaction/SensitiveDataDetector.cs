using Bower.Abstractions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction;

/// <summary>
/// Backward-compatible facade over <see cref="PrivacyEngine"/>.
/// Prefer <see cref="PrivacyEngine"/> for new code.
/// </summary>
public sealed class SensitiveDataDetector
{
    public const int MaximumPayloadBytes = PrivacyEngine.MaximumPayloadBytes;

    private readonly PrivacyEngine engine;

    public SensitiveDataDetector()
        : this(PrivacyPolicy.CreateDefault())
    {
    }

    public SensitiveDataDetector(PrivacyPolicy policy)
    {
        engine = new PrivacyEngine(policy);
    }

    public SensitiveScanResult ScanAndRedact(string json, bool maskInPlace = true)
    {
        _ = maskInPlace;
        PrivacyScanResult result = engine.RedactJson(json);
        if (!result.Succeeded)
        {
            return new SensitiveScanResult(false, null, [], result.FailureCode);
        }

        List<SensitiveFinding> findings = result.Findings
            .Select(MapFinding)
            .ToList();
        return new SensitiveScanResult(true, result.RedactedJson, findings, null);
    }

    public RedactionResult ToRedactionResult(string json) => engine.Redact(json);

    private static SensitiveFinding MapFinding(AppliedFinding finding)
    {
        SensitiveFindingKind kind = finding.DetectorId switch
        {
            DetectorIds.Aws => SensitiveFindingKind.AwsAccessKey,
            DetectorIds.Jwt or DetectorIds.Entra => SensitiveFindingKind.Jwt,
            DetectorIds.CryptoMaterial => SensitiveFindingKind.PrivateKeyBlock,
            DetectorIds.CreditCard => SensitiveFindingKind.CreditCard,
            DetectorIds.Email => SensitiveFindingKind.Email,
            DetectorIds.IpAddress => SensitiveFindingKind.IpAddress,
            DetectorIds.Database => SensitiveFindingKind.ConnectionString,
            DetectorIds.FieldNameSecret => SensitiveFindingKind.GenericSecret,
            _ when finding.Category == DetectorCategories.Secrets => SensitiveFindingKind.GenericSecret,
            _ => SensitiveFindingKind.GenericSecret
        };

        string action = finding.Action switch
        {
            PrivacyAction.Remove => "removed",
            PrivacyAction.Allow or PrivacyAction.AlertOnly => "alert",
            _ => "masked"
        };

        return new SensitiveFinding(kind, finding.Path, Preview: "***", action);
    }
}

public enum SensitiveFindingKind
{
    AwsAccessKey,
    AwsSecretKey,
    PrivateKeyBlock,
    Jwt,
    CreditCard,
    Email,
    IpAddress,
    BearerToken,
    ConnectionString,
    GenericSecret
}

public sealed record SensitiveFinding(
    SensitiveFindingKind Kind,
    string Path,
    string Preview,
    string Action);

public sealed record SensitiveScanResult(
    bool Succeeded,
    string? RedactedJson,
    IReadOnlyList<SensitiveFinding> Findings,
    string? FailureCode);

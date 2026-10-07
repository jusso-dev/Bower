namespace Bower.Redaction.Privacy;

/// <summary>
/// Global and per-detector privacy policy. Deterministic; no executable config.
/// </summary>
public sealed class PrivacyPolicy
{
    public PrivacyAction DefaultAction { get; init; } = PrivacyAction.Mask;

    /// <summary>Replacement text used when action is Replace.</summary>
    public string ReplacementText { get; init; } = "***REDACTED***";

    /// <summary>Per-detector action overrides keyed by <see cref="DetectorIds"/>.</summary>
    public IReadOnlyDictionary<string, PrivacyAction> DetectorActions { get; init; } =
        new Dictionary<string, PrivacyAction>(StringComparer.Ordinal);

    /// <summary>Disabled detector ids (case-sensitive stable ids).</summary>
    public IReadOnlySet<string> DisabledDetectors { get; init; } =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>Optional detectors that are off unless explicitly enabled.</summary>
    public IReadOnlySet<string> OptInDetectors { get; init; } =
        new HashSet<string>(StringComparer.Ordinal)
        {
            DetectorIds.IpAddress,
            DetectorIds.Hostname,
            DetectorIds.Username,
            DetectorIds.Address,
            DetectorIds.Gps,
            DetectorIds.SecurityMarking
        };

    /// <summary>Explicitly enable opt-in detectors.</summary>
    public IReadOnlySet<string> EnabledOptInDetectors { get; init; } =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// HMAC key for the Hmac action (min 32 bytes). Required when any action resolves to
    /// Hmac; the engine refuses to start without it rather than fall back to an unkeyed hash.
    /// </summary>
    public byte[]? HmacKey { get; init; }

    /// <summary>AES-256 key for Encrypt action (32 bytes). Null disables Encrypt (falls back to Remove).</summary>
    public byte[]? EncryptionKey { get; init; }

    /// <summary>When true, injects privacy metadata object into JSON root.</summary>
    public bool EmitMetadata { get; init; } = true;

    /// <summary>
    /// When true (default), high-risk findings should surface as a separate
    /// <c>sensitive_data_detected</c> security event for the SOC. The processor
    /// owns enqueue; this flag documents intent for hosts wiring PrivacyEngine.
    /// </summary>
    public bool EmitSecurityEventOnFindings { get; init; } = true;

    public bool IsDetectorEnabled(string detectorId)
    {
        if (DisabledDetectors.Contains(detectorId))
        {
            return false;
        }

        if (OptInDetectors.Contains(detectorId) && !EnabledOptInDetectors.Contains(detectorId))
        {
            return false;
        }

        return true;
    }

    /// <summary>True when the default or any per-detector action is <paramref name="action"/>.</summary>
    public bool UsesAction(PrivacyAction action) =>
        DefaultAction == action || DetectorActions.Values.Any(value => value == action);

    public PrivacyAction ResolveAction(string detectorId)
    {
        if (DetectorActions.TryGetValue(detectorId, out PrivacyAction action))
        {
            return action;
        }

        return DefaultAction;
    }

    /// <summary>Enterprise-safe defaults for production telemetry gateways.</summary>
    public static PrivacyPolicy CreateDefault()
    {
        return new PrivacyPolicy
        {
            DefaultAction = PrivacyAction.Mask,
            DetectorActions = new Dictionary<string, PrivacyAction>(StringComparer.Ordinal)
            {
                [DetectorIds.FieldNameSecret] = PrivacyAction.Remove,
                // TFNs have ~10^8 valid values, so an unkeyed hash is reversible by enumeration.
                [DetectorIds.Tfn] = PrivacyAction.Mask,
                [DetectorIds.Crn] = PrivacyAction.Mask,
                [DetectorIds.Medicare] = PrivacyAction.Mask,
                [DetectorIds.Ihi] = PrivacyAction.Mask,
                [DetectorIds.Passport] = PrivacyAction.Mask,
                [DetectorIds.DriverLicence] = PrivacyAction.Mask,
                [DetectorIds.Abn] = PrivacyAction.Allow,
                [DetectorIds.Acn] = PrivacyAction.Allow,
                [DetectorIds.Dva] = PrivacyAction.Mask,
                [DetectorIds.CreditCard] = PrivacyAction.Remove,
                [DetectorIds.BsbAccount] = PrivacyAction.Mask,
                [DetectorIds.Iban] = PrivacyAction.Mask,
                [DetectorIds.SwiftBic] = PrivacyAction.Allow,
                [DetectorIds.PayId] = PrivacyAction.Mask,
                [DetectorIds.Email] = PrivacyAction.Mask,
                [DetectorIds.PhoneAu] = PrivacyAction.Mask,
                [DetectorIds.PhoneInternational] = PrivacyAction.Mask,
                [DetectorIds.DateOfBirth] = PrivacyAction.Mask,
                [DetectorIds.Aws] = PrivacyAction.Remove,
                [DetectorIds.Azure] = PrivacyAction.Remove,
                [DetectorIds.Entra] = PrivacyAction.Remove,
                [DetectorIds.Gcp] = PrivacyAction.Remove,
                [DetectorIds.Jwt] = PrivacyAction.Remove,
                [DetectorIds.OAuth] = PrivacyAction.Remove,
                [DetectorIds.ApiKey] = PrivacyAction.Remove,
                [DetectorIds.Kubernetes] = PrivacyAction.Remove,
                [DetectorIds.Docker] = PrivacyAction.Remove,
                [DetectorIds.Database] = PrivacyAction.Remove,
                [DetectorIds.EnvVar] = PrivacyAction.Remove,
                [DetectorIds.CryptoMaterial] = PrivacyAction.Remove,
                [DetectorIds.SecurityMarking] = PrivacyAction.AlertOnly
            }
        };
    }
}

namespace Bower.Redaction.Privacy;

/// <summary>
/// Deterministic policy actions applied to a detected sensitive span.
/// Original values are never written into privacy metadata.
/// </summary>
public enum PrivacyAction
{
    Allow,
    Remove,
    Replace,
    Mask,
    Sha256,
    Hmac,
    Encrypt,
    AlertOnly
}

using Bower.Abstractions;
using Bower.Redaction.Privacy;

namespace Bower.Redaction;

/// <summary>
/// Compatibility redactor. Delegates to <see cref="PrivacyEngine"/> with default policy.
/// Field-name secrets are removed; emails and other PII are handled by detectors.
/// </summary>
public sealed class JsonEventRedactor : IEventRedactor
{
    public const int MaximumPayloadBytes = PrivacyEngine.MaximumPayloadBytes;

    private readonly PrivacyEngine engine;

    public JsonEventRedactor()
        : this(PrivacyPolicy.CreateDefault())
    {
    }

    public JsonEventRedactor(PrivacyPolicy policy)
    {
        engine = new PrivacyEngine(policy);
    }

    public RedactionResult Redact(string json) => engine.Redact(json);
}

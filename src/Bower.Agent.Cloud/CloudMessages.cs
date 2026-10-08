namespace Bower.Agent.Cloud;

/// <summary>One upstream message (an SQS message or a Pub/Sub received message).</summary>
public sealed record CloudMessage(string Id, string Handle, byte[] Body, int DeliveryAttempt);

/// <summary>
/// A cloud queue with at-least-once semantics. Messages stay owned by the queue until
/// acknowledged; released messages are redelivered and eventually dead-lettered by the
/// queue's own redrive policy.
/// </summary>
public interface ICloudMessageSource
{
    string Name { get; }

    Task<IReadOnlyList<CloudMessage>> ReceiveAsync(int maximum, CancellationToken cancellationToken);

    /// <summary>Deletes (SQS) or acknowledges (Pub/Sub) the message.</summary>
    Task AcknowledgeAsync(CloudMessage message, CancellationToken cancellationToken);

    /// <summary>Makes the message deliverable again after the delay; zero redelivers immediately.</summary>
    Task ReleaseAsync(CloudMessage message, TimeSpan delay, CancellationToken cancellationToken);

    /// <summary>Keeps the message invisible to other consumers while it is still being forwarded.</summary>
    Task ExtendAsync(CloudMessage message, TimeSpan lease, CancellationToken cancellationToken);
}

/// <summary>Candidate event JSON for the collector, or a reason the message is not a security event.</summary>
public sealed record CloudTranslation(IReadOnlyList<string> Events, int Skipped, string? UnsupportedReason)
{
    public static CloudTranslation Unsupported(string reason) => new([], 0, reason);
}

public interface ICloudMessageTranslator
{
    Task<CloudTranslation> TranslateAsync(CloudMessage message, CancellationToken cancellationToken);
}

/// <summary>The message can never be translated; let the queue dead-letter it.</summary>
public sealed class MalformedCloudMessageException(string reason, Exception? inner = null)
    : Exception(reason, inner);

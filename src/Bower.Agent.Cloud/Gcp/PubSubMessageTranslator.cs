using System.Text.Json;
using Bower.Contracts;
using Bower.Source.Gcp;

namespace Bower.Agent.Cloud.Gcp;

/// <summary>Maps Pub/Sub message data (Cloud Audit Logs or SCC notifications) to candidate events.</summary>
public sealed class PubSubMessageTranslator(GcpSecurityEventMapper mapper, TimeProvider clock) : ICloudMessageTranslator
{
    public Task<CloudTranslation> TranslateAsync(CloudMessage message, CancellationToken cancellationToken)
    {
        if (message.Body.Length == 0)
        {
            throw new MalformedCloudMessageException("message has no data");
        }

        GcpMappedMessage mapped;
        try
        {
            mapped = mapper.Map(message.Body, clock.GetUtcNow());
        }
        catch (Exception exception) when (exception is GcpTelemetryMalformedException or GcpTelemetryPayloadTooLargeException)
        {
            throw new MalformedCloudMessageException(exception.GetType().Name, exception);
        }

        return Task.FromResult(mapped.Event is null
            ? CloudTranslation.Unsupported(mapped.UnsupportedReason ?? "unsupported")
            : new CloudTranslation([JsonSerializer.Serialize(mapped.Event, BowerJson.Options)], 0, null));
    }
}

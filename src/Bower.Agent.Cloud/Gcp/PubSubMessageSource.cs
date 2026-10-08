using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Agent.Cloud.Gcp;

/// <summary>Supplies short-lived OAuth access tokens for Pub/Sub.</summary>
public interface IGoogleAccessTokenSource
{
    Task<string> GetAccessTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Pub/Sub pull subscriber over the REST API. Messages are acknowledged only after the
/// collector settled them; released messages get a short ack deadline so Pub/Sub
/// redelivers them and applies the subscription's dead-letter policy.
/// </summary>
public sealed class PubSubMessageSource(HttpClient http, IGoogleAccessTokenSource tokens, string subscription)
    : ICloudMessageSource
{
    private const int MaximumAckDeadlineSeconds = 600;

    public string Name => "gcp-pubsub";

    public async Task<IReadOnlyList<CloudMessage>> ReceiveAsync(int maximum, CancellationToken cancellationToken)
    {
        PullResponse? response = await PostAsync<PullResponse>(
            "pull",
            new { maxMessages = Math.Clamp(maximum, 1, 1000) },
            cancellationToken);
        return (response?.ReceivedMessages ?? [])
            .Where(item => item.AckId is not null)
            .Select(item => new CloudMessage(
                item.Message?.MessageId ?? "unknown",
                item.AckId!,
                Decode(item.Message?.Data),
                item.DeliveryAttempt ?? 0))
            .ToList();
    }

    public Task AcknowledgeAsync(CloudMessage message, CancellationToken cancellationToken) =>
        PostAsync<JsonElement>("acknowledge", new { ackIds = new[] { message.Handle } }, cancellationToken);

    public Task ReleaseAsync(CloudMessage message, TimeSpan delay, CancellationToken cancellationToken) =>
        ModifyAsync(message, delay, cancellationToken);

    public Task ExtendAsync(CloudMessage message, TimeSpan lease, CancellationToken cancellationToken) =>
        ModifyAsync(message, lease, cancellationToken);

    private async Task ModifyAsync(CloudMessage message, TimeSpan deadline, CancellationToken cancellationToken) =>
        await PostAsync<JsonElement>(
            "modifyAckDeadline",
            new
            {
                ackIds = new[] { message.Handle },
                ackDeadlineSeconds = (int)Math.Clamp(deadline.TotalSeconds, 0, MaximumAckDeadlineSeconds)
            },
            cancellationToken);

    private async Task<T?> PostAsync<T>(string verb, object body, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, $"v1/{subscription}:{verb}")
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            await tokens.GetAccessTokenAsync(cancellationToken));
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            // Status only: error bodies can echo resource names but never need logging.
            throw new HttpRequestException($"Pub/Sub {verb} returned {(int)response.StatusCode}.", null, response.StatusCode);
        }

        return await response.Content.ReadFromJsonAsync<T>(cancellationToken);
    }

    private static byte[] Decode(string? data)
    {
        if (string.IsNullOrEmpty(data))
        {
            return [];
        }

        try
        {
            return Convert.FromBase64String(data);
        }
        catch (FormatException)
        {
            // An undecodable body is malformed; the translator rejects empty data.
            return [];
        }
    }

    private sealed record PullResponse(
        [property: JsonPropertyName("receivedMessages")] IReadOnlyList<ReceivedMessage>? ReceivedMessages);

    private sealed record ReceivedMessage(
        [property: JsonPropertyName("ackId")] string? AckId,
        [property: JsonPropertyName("message")] PubSubMessage? Message,
        [property: JsonPropertyName("deliveryAttempt")] int? DeliveryAttempt);

    private sealed record PubSubMessage(
        [property: JsonPropertyName("data")] string? Data,
        [property: JsonPropertyName("messageId")] string? MessageId);
}

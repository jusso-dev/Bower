using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Bower.Forwarding;

public enum SendOutcome
{
    /// <summary>Collector queued it (202) or already had it (200).</summary>
    Accepted,

    /// <summary>Collector decided not to keep it (policy reject or quarantine). Do not retry.</summary>
    Rejected,

    /// <summary>Backpressure or transient failure. Retry later without acknowledging the source.</summary>
    RetryLater,

    /// <summary>Ingest rate limit (429). Retry the same event shortly.</summary>
    Throttled,

    /// <summary>The ingest token was refused. Retry later; needs operator action.</summary>
    Unauthorized
}

/// <summary>
/// Posts single candidate events to a Bower collector and classifies the response.
/// Shared by agents (Docker sidecar, cloud sources) so every forwarder applies the
/// same at-least-once rule: acknowledge upstream only on Accepted or Rejected.
/// </summary>
public sealed class CollectorClient(HttpClient client, string? ingestToken)
{
    public async Task<SendOutcome> SendAsync(string json, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "v1/events")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrEmpty(ingestToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ingestToken);
        }

        try
        {
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            return Classify(response.StatusCode);
        }
        catch (Exception exception) when (
            exception is HttpRequestException
                || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested))
        {
            return SendOutcome.RetryLater;
        }
    }

    /// <summary>
    /// Cheap readiness probe. Queue sources call it before receiving so a collector outage
    /// does not burn upstream delivery attempts and push healthy messages to a dead-letter queue.
    /// </summary>
    public async Task<bool> IsReachableAsync(CancellationToken cancellationToken)
    {
        try
        {
            using HttpResponseMessage response = await client.GetAsync("health", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception exception) when (
            exception is HttpRequestException
                || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested))
        {
            return false;
        }
    }

    public static SendOutcome Classify(HttpStatusCode status) =>
        status switch
        {
            HttpStatusCode.OK or HttpStatusCode.Accepted => SendOutcome.Accepted,
            HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SendOutcome.Rejected,
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SendOutcome.Unauthorized,
            // 413 can never succeed for this event; treat like a rejection.
            HttpStatusCode.RequestEntityTooLarge => SendOutcome.Rejected,
            HttpStatusCode.TooManyRequests => SendOutcome.Throttled,
            _ => SendOutcome.RetryLater
        };
}

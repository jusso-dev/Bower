using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Bower.Agent.Docker;

public enum SendOutcome
{
    /// <summary>Collector queued it (202) or already had it (200).</summary>
    Accepted,

    /// <summary>Collector decided not to keep it (policy reject or quarantine). Do not retry.</summary>
    Rejected,

    /// <summary>Backpressure or transient failure. Retry later without advancing.</summary>
    RetryLater,

    /// <summary>The ingest token was refused. Retry later; needs operator action.</summary>
    Unauthorized
}

/// <summary>Posts single events to the collector and classifies the response.</summary>
public sealed class CollectorClient(HttpClient client, SidecarSettings settings)
{
    public async Task<SendOutcome> SendAsync(string json, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "v1/events")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        if (settings.IngestToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.IngestToken);
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

    internal static SendOutcome Classify(HttpStatusCode status) =>
        status switch
        {
            HttpStatusCode.OK or HttpStatusCode.Accepted => SendOutcome.Accepted,
            HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SendOutcome.Rejected,
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SendOutcome.Unauthorized,
            // 413 can never succeed for this event; treat like a rejection.
            HttpStatusCode.RequestEntityTooLarge => SendOutcome.Rejected,
            _ => SendOutcome.RetryLater
        };
}

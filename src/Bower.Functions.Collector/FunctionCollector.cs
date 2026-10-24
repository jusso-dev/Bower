using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Redaction;
using Microsoft.Extensions.Logging;

namespace Bower.Functions.Collector;

/// <summary>One HTTP request as the function adapter sees it. The body is read at most once.</summary>
public sealed record IngestRequest(string? Authorization, string? ContentType, long? ContentLength, Stream Body);

/// <summary>A finished HTTP response: status, JSON body and extra headers (for example Retry-After).</summary>
public sealed record CollectorResponse(int StatusCode, string Body, IReadOnlyDictionary<string, string> Headers);

/// <summary>
/// Serverless Bower collector: authenticate (Entra), authorize the producer's event identity,
/// then run the unchanged <see cref="SecurityEventProcessor"/> (redact, validate, policy,
/// privacy alert) into a per-request buffer and deliver that buffer to Logs Ingestion before
/// answering. Success means the Logs Ingestion API accepted every staged record; anything
/// else answers 503/429 with Retry-After and keeps nothing, so producers retry
/// (at-least-once). Framework-free so tests drive it without the Functions host.
/// </summary>
public sealed partial class FunctionCollector(
    FunctionSettings settings,
    PolicyBundle bundle,
    IEventRedactor redactor,
    ITelemetryPolicyEvaluator policyEvaluator,
    ProducerAuthorization authorization,
    IProducerAuthenticator authenticator,
    IOutputAdapter output,
    TimeProvider clock,
    ILogger<FunctionCollector> logger)
{
    public const int MaximumPayloadBytes = JsonEventRedactor.MaximumPayloadBytes;
    public static readonly TimeSpan DefaultRetryAfter = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromHours(1);

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly IReadOnlyDictionary<string, string> NoHeaders = new Dictionary<string, string>();

    private readonly CollectorIdentity identity = new(
        settings.CollectorId, settings.Version, "azure-function", settings.ConfigurationHash());

    public static CollectorResponse Health() =>
        Json(200, new HealthResponse("healthy"), FunctionJsonContext.Default.HealthResponse);

    public async Task<CollectorResponse> StatusAsync(string? authorizationHeader, CancellationToken cancellationToken)
    {
        AuthenticationOutcome authentication = await authenticator.AuthenticateAsync(authorizationHeader, cancellationToken);
        if (authentication.Caller is null)
        {
            return AuthenticationFailed(authentication.Failure);
        }

        StatusResponse status = new(
            "healthy",
            "azure-function",
            new StatusPolicyResponse(
                bundle.Hash,
                [.. bundle.Policies.Select(item => new StatusPolicyItem(item.Policy.Metadata.Id, item.Policy.Metadata.Version))],
                [.. bundle.LoadedPacks.Select(pack => new StatusPackItem(pack.Manifest.Id, pack.Manifest.Version, pack.Manifest.PackHash))],
                bundle.PrivacyProfile),
            new StatusDeliveryResponse(
                output.Id,
                settings.StreamName,
                FunctionCredentialFactory.Select(settings).Description,
                DurableQueue: false,
                Ledger: false),
            authorization.ScopeCount);
        return Json(200, status, FunctionJsonContext.Default.StatusResponse);
    }

    public async Task<CollectorResponse> IngestAsync(IngestRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Authenticate before reading the body: unauthenticated callers cost no parsing.
        AuthenticationOutcome authentication = await authenticator.AuthenticateAsync(request.Authorization, cancellationToken);
        if (authentication.Caller is null)
        {
            return AuthenticationFailed(authentication.Failure);
        }

        string producer = authentication.Caller.Producer;
        if (!IsJsonContentType(request.ContentType))
        {
            return Error(415, "Content-Type must be application/json.");
        }

        if (request.ContentLength is > MaximumPayloadBytes)
        {
            return Error(413, "Event exceeds the 1 MiB limit.");
        }

        byte[]? body = await ReadBoundedAsync(request.Body, MaximumPayloadBytes, cancellationToken);
        if (body is null)
        {
            return Error(413, "Event exceeds the 1 MiB limit.");
        }

        string candidateJson;
        try
        {
            using JsonDocument document = JsonDocument.Parse(StrictUtf8.GetString(body));
            // Same exact producer identity tuples as the HTTP collector; missing scope denies,
            // before redaction, policy, privacy alerts or delivery.
            if (!authorization.IsAuthorized(producer, document.RootElement))
            {
                return Error(403, "Producer is not authorized for this event identity.");
            }

            candidateJson = document.RootElement.GetRawText();
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or ArgumentException)
        {
            return Error(400, "Request body must be one JSON event object.");
        }
        finally
        {
            Array.Clear(body);
        }

        // Per-request buffer: nothing outlives this call, so nothing is persisted on failure.
        RequestEventBuffer buffer = new();
        SecurityEventProcessor processor = new(redactor, policyEvaluator, buffer, clock);
        ProcessingResult result = await processor.ProcessAsync(
            candidateJson,
            identity with { SourceAdapter = $"azure-function:{producer}" },
            cancellationToken);

        bool delivered = false;
        if (buffer.Events.Count > 0)
        {
            CollectorResponse? retry = await DeliverAsync(buffer.Events, cancellationToken);
            if (retry is not null)
            {
                return retry;
            }

            delivered = buffer.Events.Any(item => string.Equals(item.EventId, result.EventId, StringComparison.Ordinal));
        }

        IngestResponse response = new(
            result.EventId,
            result.Action.ToString().ToLowerInvariant(),
            Queued: false,
            result.Duplicate,
            result.Reasons,
            result.PolicyDecision is null
                ? null
                : new IngestPolicyResponse(
                    result.PolicyDecision.PolicyId,
                    result.PolicyDecision.PolicyVersion,
                    result.PolicyDecision.PolicyHash,
                    result.PolicyDecision.Score),
            delivered);
        int statusCode = result.Action switch
        {
            DecisionAction.Accept or DecisionAction.RedactAndAccept => 202,
            DecisionAction.Reject => 422,
            _ => 400
        };
        return Json(statusCode, response, FunctionJsonContext.Default.IngestResponse);
    }

    /// <summary>Null when Logs Ingestion accepted every staged record; otherwise the retry response.</summary>
    private async Task<CollectorResponse?> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken)
    {
        DeliveryResult delivery;
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(settings.DeliveryTimeout);
        try
        {
            delivery = await output.DeliverAsync(events, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LogDeliveryFailed(logger, "delivery-timeout", events.Count);
            return Retry(503, DefaultRetryAfter, "Destination did not accept the event in time; retry later.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Never log exception text: credential and transport errors can carry secrets.
            LogDeliveryFailed(logger, "destination-exception", events.Count);
            return Retry(503, DefaultRetryAfter, "Destination is unavailable; retry later.");
        }

        HashSet<string> acknowledged = new(delivery.AcknowledgedEventIds, StringComparer.Ordinal);
        if (events.All(item => acknowledged.Contains(item.EventId)))
        {
            return null;
        }

        IReadOnlyList<DeliveryFailure> failures = delivery.Failures;
        string code = failures.Count == 0 ? "destination-unacknowledged" : failures[0].Code;
        LogDeliveryFailed(logger, code, events.Count - acknowledged.Count);
        if (failures.Count > 0 && failures.All(failure => !failure.IsRetryable))
        {
            // Permanent for this record (preflight, size, isolated 400): retrying cannot help.
            return Error(422, $"Destination rejected the event ({code}).");
        }

        DateTimeOffset now = clock.GetUtcNow();
        TimeSpan wait = failures
            .Where(failure => failure.RetryAfter is not null)
            .Select(failure => failure.RetryAfter!.Value - now)
            .DefaultIfEmpty(DefaultRetryAfter)
            .Max();
        bool throttled = failures.Any(failure => failure.Code.Contains("-http-429", StringComparison.Ordinal));
        return Retry(throttled ? 429 : 503, wait, "Destination did not accept the event; retry later.");
    }

    private CollectorResponse AuthenticationFailed(AuthenticationFailure failure)
    {
        switch (failure)
        {
            case AuthenticationFailure.Forbidden:
                return Error(403, "The caller lacks the Bower.Producer application role.");
            case AuthenticationFailure.Unavailable:
                LogAuthenticationUnavailable(logger);
                return Retry(503, DefaultRetryAfter, "Token validation is temporarily unavailable; retry later.");
            default:
                return new CollectorResponse(
                    401,
                    JsonSerializer.Serialize(
                        new ErrorResponse("A valid Microsoft Entra access token is required."),
                        FunctionJsonContext.Default.ErrorResponse),
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["WWW-Authenticate"] = "Bearer" });
        }
    }

    private static CollectorResponse Retry(int statusCode, TimeSpan wait, string message)
    {
        double seconds = Math.Clamp(Math.Ceiling(wait.TotalSeconds), 1, MaximumRetryAfter.TotalSeconds);
        return new CollectorResponse(
            statusCode,
            JsonSerializer.Serialize(new ErrorResponse(message), FunctionJsonContext.Default.ErrorResponse),
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Retry-After"] = seconds.ToString("0", CultureInfo.InvariantCulture)
            });
    }

    private static CollectorResponse Error(int statusCode, string message) =>
        Json(statusCode, new ErrorResponse(message), FunctionJsonContext.Default.ErrorResponse);

    private static CollectorResponse Json<T>(int statusCode, T value, JsonTypeInfo<T> type) =>
        new(statusCode, JsonSerializer.Serialize(value, type), NoHeaders);

    private static bool IsJsonContentType(string? value) =>
        MediaTypeHeaderValue.TryParse(value, out MediaTypeHeaderValue? media)
        && string.Equals(media.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
        && (media.CharSet is null || string.Equals(media.CharSet.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase));

    /// <summary>Reads at most <paramref name="limit"/> bytes; null when the body is larger.</summary>
    private static async Task<byte[]?> ReadBoundedAsync(Stream body, int limit, CancellationToken cancellationToken)
    {
        byte[] chunk = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            using MemoryStream buffer = new();
            int read;
            while ((read = await body.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken)) > 0)
            {
                if (buffer.Length + read > limit)
                {
                    return null;
                }

                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk, clearArray: true);
        }
    }

    [LoggerMessage(EventId = 2000, Level = LogLevel.Warning,
        Message = "Delivery not acknowledged ({FailureCode}, {Count} record(s)); caller told to retry or rejected. Nothing retained.")]
    private static partial void LogDeliveryFailed(ILogger logger, string failureCode, int count);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning,
        Message = "Entra signing metadata unavailable; ingest answered 503.")]
    private static partial void LogAuthenticationUnavailable(ILogger logger);
}

using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Persistence;
using Bower.Pipeline.Transforms;

namespace Bower.Collector;

public static partial class CollectorApplication
{
    private static void MapPackEndpoints(WebApplication app)
    {
        app.MapPost("/v1/packs/{packId}/parsers/{parserIndex:int}/events",
            async (string packId, int parserIndex, HttpContext context,
                PolicyBundle bundle, SecurityEventProcessor processor, ProducerAuthorization authorization,
                CollectorIdentity identity, EventIdentityConflicts conflicts, IngestAuthentication authentication,
                PipelineTelemetry telemetry, EventTap tap, TimeProvider clock, CancellationToken cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                LoadedPack? pack = bundle.LoadedPacks.SingleOrDefault(pack => pack.Manifest.Id == packId);
                if (pack is null || parserIndex < 0 || parserIndex >= pack.Parsers.Count || pack.Parsers[parserIndex].Runtime is null)
                {
                    return PackError(404, "pack-parser-inactive-or-unknown");
                }

                if (!context.Request.HasJsonContentType())
                {
                    return PackError(415, "pack-record-content-type");
                }
                // Read only after authentication/rate limiting. Bound bytes before JSON parsing,
                // including chunked bodies and ignored fields. No raw payload enters diagnostics.
                if (context.Request.ContentLength > PackRuntime.MaximumRecordBytes)
                {
                    return PackError(413, "pack-record-too-large");
                }
                byte[] buffer = new byte[PackRuntime.MaximumRecordBytes + 1];
                int length = 0;
                while (length < buffer.Length)
                {
                    int read = await context.Request.Body.ReadAsync(buffer.AsMemory(length), cancellationToken);
                    if (read == 0) { break; }
                    length += read;
                }
                if (length > PackRuntime.MaximumRecordBytes)
                {
                    return PackError(413, "pack-record-too-large");
                }
                string rawJson;
                try
                {
                    int offset = length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF ? 3 : 0;
                    rawJson = new UTF8Encoding(false, true).GetString(buffer, offset, length - offset);
                }
                catch (DecoderFallbackException) { return PackError(400, "pack-record-invalid"); }

                SecurityEventEnvelope? envelope;
                try
                {
                    envelope = PackRuntime.Parse(pack.Parsers[parserIndex], rawJson, clock.GetUtcNow());
                }
                catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
                {
                    return PackError(400, "pack-record-invalid");
                }
                catch (TransformException exception)
                {
                    // Quarantine without persisting: the raw record never reaches redaction,
                    // policy or the queue, and only the stable code is reported.
                    ProcessingResult quarantined = ProcessingResult.Failed(
                        DecisionAction.Quarantine, exception.Code, ProcessingStage.Transform);
                    telemetry.Record(quarantined, length);
                    // Metadata only: stage, action and code. The raw record is never tapped.
                    tap.Publish(quarantined);
                    return Results.Json(
                        new IngestResponse(null, "quarantine", false, false, quarantined.Reasons, null),
                        CollectorJsonContext.Default.IngestResponse,
                        statusCode: StatusCodes.Status400BadRequest);
                }

                if (envelope is null)
                {
                    return PackError(422, "pack-record-not-selected");
                }

                string producer = context.Items[IngestAuthenticationFilter.ProducerItem] as string ?? "anonymous";
                JsonElement candidate = JsonSerializer.SerializeToElement(envelope, BowerJson.Envelope);
                if (!authorization.IsAuthorized(producer, candidate))
                {
                    return PackError(403, "Producer is not authorized for this event identity.");
                }

                ProcessingResult result;
                try
                {
                    result = await processor.ProcessAsync(candidate.GetRawText(),
                        identity with { SourceAdapter = $"pack-http:{producer}:{packId}:{parserIndex}" }, cancellationToken);
                }
                catch (QueueCapacityExceededException)
                {
                    return PackError(503, "Collector queue is at capacity; retry later.");
                }

                IngestResponse response = new(result.EventId, result.Action.ToString().ToLowerInvariant(),
                    result.Queued, result.Duplicate, result.Reasons,
                    result.PolicyDecision is null ? null : new IngestPolicyResponse(result.PolicyDecision.PolicyId,
                        result.PolicyDecision.PolicyVersion, result.PolicyDecision.PolicyHash, result.PolicyDecision.Score));
                int status = result.Action switch
                {
                    DecisionAction.Accept or DecisionAction.RedactAndAccept => result.Duplicate ? 200 : 202,
                    DecisionAction.Reject => 422,
                    _ => 400
                };
                if (result.Reasons.Contains(EventIdentityConflicts.Reason, StringComparer.Ordinal))
                {
                    conflicts.Record(producer, authentication.Required);
                    status = StatusCodes.Status409Conflict;
                    response = response with { Remediation = EventIdentityConflicts.Remediation };
                }
                return Results.Json(response, CollectorJsonContext.Default.IngestResponse, statusCode: status);
            })
            .AddEndpointFilter<IngestAuthenticationFilter>()
            .AddEndpointFilter<ManagedPrivacyProfileGateFilter>()
            .RequireRateLimiting("ingest");
    }

    private static IResult PackError(int status, string error) =>
        Results.Json(new ErrorResponse(error), CollectorJsonContext.Default.ErrorResponse, statusCode: status);
}

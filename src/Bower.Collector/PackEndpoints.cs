using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Core;
using Bower.Packs;
using Bower.Persistence;

namespace Bower.Collector;

public static partial class CollectorApplication
{
    private static void MapPackEndpoints(WebApplication app)
    {
        app.MapPost("/v1/packs/{packId}/parsers/{parserIndex:int}/events",
            async (string packId, int parserIndex, JsonElement raw, HttpContext context,
                PolicyBundle bundle, SecurityEventProcessor processor, ProducerAuthorization authorization,
                CollectorIdentity identity, CancellationToken cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                LoadedPack? pack = bundle.LoadedPacks.SingleOrDefault(pack => pack.Manifest.Id == packId);
                if (pack is null || parserIndex < 0 || parserIndex >= pack.Parsers.Count || pack.Parsers[parserIndex].Runtime is null)
                {
                    return PackError(404, "pack-parser-inactive-or-unknown");
                }

                string rawJson = raw.GetRawText();
                if (Encoding.UTF8.GetByteCount(rawJson) > PackRuntime.MaximumRecordBytes)
                {
                    return PackError(413, "pack-record-too-large");
                }

                SecurityEventEnvelope? envelope;
                try
                {
                    envelope = PackRuntime.Parse(pack.Parsers[parserIndex], rawJson);
                }
                catch (Exception exception) when (exception is JsonException or InvalidDataException or ArgumentException)
                {
                    return PackError(400, "pack-record-invalid");
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
                return Results.Json(response, CollectorJsonContext.Default.IngestResponse, statusCode: status);
            })
            .AddEndpointFilter<IngestAuthenticationFilter>()
            .RequireRateLimiting("ingest");
    }

    private static IResult PackError(int status, string error) =>
        Results.Json(new ErrorResponse(error), CollectorJsonContext.Default.ErrorResponse, statusCode: status);
}

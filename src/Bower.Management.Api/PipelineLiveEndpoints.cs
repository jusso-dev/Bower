using System.Security.Claims;
using System.Text;

namespace Bower.Management.Api;

internal static class PipelineLiveEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet(
                "/pipelines/live",
                async (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    Results.Ok(await store.ListLivePipelinesAsync(clock.GetUtcNow(), cancellationToken)))
            .RequireAuthorization("View");

        // Operator-only redacted sample tap. Enforced server-side; Viewers receive 403.
        // Never connects to user-supplied URLs and always audits each tap request.
        api.MapPost(
                "/pipelines/collectors/{id}/tap",
                async (
                    string id,
                    PipelineTapRequest? request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    HttpContext httpContext,
                    CancellationToken cancellationToken) =>
                {
                    CollectorRecord? collector = await store.GetAsync(id, cancellationToken);
                    if (collector is null)
                    {
                        return Results.NotFound();
                    }

                    int limit = Math.Clamp(request?.Limit ?? 10, 1, 25);
                    string? source = SanitizeFilter(request?.Source);
                    string? eventType = SanitizeFilter(request?.EventType);
                    PipelineTapRequest normalized = new(source, eventType, limit);

                    DateTimeOffset now = clock.GetUtcNow();
                    string actorId = user.FindFirstValue("oid") ?? user.Identity?.Name ?? "unknown";
                    string actorName = user.FindFirstValue("name") ?? user.Identity?.Name ?? actorId;
                    await store.RecordPipelineTapAuditAsync(id, actorId, actorName, now, cancellationToken);

                    string command = BuildCliCommand(normalized);
                    ICollectorTapClient? tapClient = httpContext.RequestServices.GetService<ICollectorTapClient>();
                    if (tapClient is not null)
                    {
                        IReadOnlyList<PipelineTapFrame>? frames = await tapClient.TrySampleAsync(id, normalized, cancellationToken);
                        if (frames is not null)
                        {
                            return Results.Ok(new PipelineTapResponse(
                                id,
                                "live",
                                command,
                                "Post-redaction frames sampled from the allow-listed collector tap endpoint. Raw payloads are never shown.",
                                frames.Take(limit).ToArray(),
                                now));
                        }
                    }

                    return Results.Ok(new PipelineTapResponse(
                        id,
                        "cli",
                        command,
                        "Collectors communicate outbound only, so management does not open inbound connections to them. Run this command on the collector host (or configure an allow-listed tap relay) to inspect live redacted frames.",
                        [],
                        now));
                })
            .RequireAuthorization("Operate");
    }

    private static string? SanitizeFilter(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string trimmed = value.Trim();
        if (trimmed.Length > 128)
        {
            trimmed = trimmed[..128];
        }

        StringBuilder safe = new(trimmed.Length);
        foreach (char ch in trimmed)
        {
            if (char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-' or '/' or ':')
            {
                safe.Append(ch);
            }
        }

        return safe.Length > 0 ? safe.ToString() : null;
    }

    private static string BuildCliCommand(PipelineTapRequest request)
    {
        StringBuilder sb = new("bower tap --url http://127.0.0.1:4319 --limit ");
        sb.Append(request.Limit ?? 10);
        sb.Append(" --duration 15");
        if (!string.IsNullOrWhiteSpace(request.Source))
        {
            sb.Append(" --source ").Append(request.Source);
        }

        if (!string.IsNullOrWhiteSpace(request.EventType))
        {
            sb.Append(" --event-type ").Append(request.EventType);
        }

        return sb.ToString();
    }
}

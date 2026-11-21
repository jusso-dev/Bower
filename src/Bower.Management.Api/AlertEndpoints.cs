using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace Bower.Management.Api;

/// <summary>
/// Plain-language alert catalogue, notification channel status, and audited mute/unmute endpoints.
/// </summary>
internal static class AlertEndpoints
{
    private const long BodyLimit = 16 * 1024;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/alerts/catalogue", () => Results.Ok(AlertCatalogue.Entries))
            .RequireAuthorization("View");

        api.MapGet("/alerts/channels", (AlertNotificationOptions options) => Results.Ok(options.Status()))
            .RequireAuthorization("View");

        api.MapGet(
                "/alerts/mutes",
                async (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    Results.Ok(await store.ListActiveMutesAsync(clock.GetUtcNow(), cancellationToken)))
            .RequireAuthorization("View");

        api.MapPost(
                "/alerts/mute",
                async (
                    AlertMuteRequest request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    string conditionId = request.ConditionId?.Trim() ?? string.Empty;
                    int duration = request.DurationMinutes ?? ManagementStore.DefaultMuteMinutes;
                    try
                    {
                        AlertMuteRecord created = await store.MuteAlertAsync(
                            conditionId,
                            request.CollectorId,
                            duration,
                            request.Reason,
                            ManagementApplication.ObjectId(user),
                            ManagementApplication.DisplayName(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        return Results.Created($"/api/alerts/mutes/{created.Id}", created);
                    }
                    catch (ArgumentOutOfRangeException exception)
                    {
                        return Results.BadRequest(new ErrorResponse(exception.Message));
                    }
                    catch (ArgumentException exception)
                    {
                        return Results.BadRequest(new ErrorResponse(exception.Message));
                    }
                })
            .WithMetadata(new RequestSizeLimitAttribute(BodyLimit))
            .RequireAuthorization("Operate");

        api.MapPost(
                "/alerts/mutes/{id}/unmute",
                async (
                    string id,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (string.IsNullOrWhiteSpace(id) || id.Length != 32 || !id.All(Uri.IsHexDigit))
                    {
                        return Results.NotFound();
                    }

                    AlertMuteRecord? updated = await store.UnmuteAlertAsync(
                        id,
                        ManagementApplication.ObjectId(user),
                        ManagementApplication.DisplayName(user),
                        clock.GetUtcNow(),
                        cancellationToken);
                    return updated is null ? Results.NotFound() : Results.Ok(updated);
                })
            .RequireAuthorization("Operate");
    }
}

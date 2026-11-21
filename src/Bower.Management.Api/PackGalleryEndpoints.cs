using System.Security.Claims;
using Bower.Packs;
using Microsoft.AspNetCore.Mvc;

namespace Bower.Management.Api;

/// <summary>
/// Signed pack gallery and four-eyes pack installation requests. Every pack is signature-verified
/// server side against <c>BOWER_PACK_TRUSTED_KEYS</c> before listing, submission and approval;
/// collectors verify signatures again independently when loading <c>BOWER_PACKS</c>.
/// </summary>
internal static class PackGalleryEndpoints
{
    private const long BodyLimit = 32 * 1024;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet(
                "/packs",
                async (
                    PackGalleryService gallery,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    (IReadOnlyList<PackGalleryItem> packs, int trustedKeyCount) = gallery.List(clock);
                    IReadOnlyList<CollectorRecord> collectors = await store.ListAsync(null, cancellationToken);
                    PackTargetGroup[] groups = collectors
                        .Where(collector => collector.Status is CollectorStatus.Approved or CollectorStatus.Active)
                        .GroupBy(collector => collector.Environment, StringComparer.Ordinal)
                        .OrderBy(group => group.Key, StringComparer.Ordinal)
                        .Select(group => new PackTargetGroup(
                            group.Key,
                            group.Count(),
                            group.Select(collector => collector.Id).OrderBy(id => id, StringComparer.Ordinal).ToArray()))
                        .ToArray();

                    return Results.Ok(new PackGalleryResponse(gallery.Configured, trustedKeyCount, packs, groups));
                })
            .RequireAuthorization("View");

        api.MapGet(
                "/packs/install-requests",
                async (ManagementStore store, CancellationToken cancellationToken) =>
                    Results.Ok(await store.ListPackInstallsAsync(cancellationToken)))
            .RequireAuthorization("View");

        api.MapPost(
                "/packs/install-requests",
                SubmitInstallAsync)
            .WithMetadata(new RequestSizeLimitAttribute(BodyLimit))
            .RequireAuthorization("Operate");

        api.MapPost(
                "/packs/install-requests/{id}/approve",
                (string id, ApprovalRequest request, ClaimsPrincipal user, PackGalleryService gallery,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    ReviewInstallAsync(id, true, request, user, gallery, store, clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapPost(
                "/packs/install-requests/{id}/reject",
                (string id, ApprovalRequest request, ClaimsPrincipal user, PackGalleryService gallery,
                    ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    ReviewInstallAsync(id, false, request, user, gallery, store, clock, cancellationToken))
            .RequireAuthorization("Approve");
    }

    private static async Task<IResult> SubmitInstallAsync(
        PackInstallSubmission submission,
        ClaimsPrincipal user,
        PackGalleryService gallery,
        ManagementStore store,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        string packId = submission.PackId?.Trim() ?? string.Empty;
        string version = submission.Version?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(packId) || string.IsNullOrEmpty(version))
        {
            return Results.BadRequest(new ErrorResponse("Pack id and version are required."));
        }

        string? targetEnvironment = string.IsNullOrWhiteSpace(submission.TargetEnvironment)
            ? null
            : submission.TargetEnvironment.Trim();
        string? targetCollectorId = string.IsNullOrWhiteSpace(submission.TargetCollectorId)
            ? null
            : submission.TargetCollectorId.Trim();
        if ((targetEnvironment is null) == (targetCollectorId is null))
        {
            return Results.BadRequest(new ErrorResponse(
                "Choose either a collector group (environment) or a single collector."));
        }

        (LoadedPack? loaded, string? refusalReason) = gallery.ResolveTrusted(packId, version);
        if (loaded is null)
        {
            return Results.BadRequest(new ErrorResponse(
                refusalReason ?? "Pack is untrusted or could not be verified."));
        }

        IReadOnlyList<CollectorRecord> allCollectors = await store.ListAsync(null, cancellationToken);
        CollectorRecord[] targets = targetCollectorId is not null
            ? allCollectors.Where(item =>
                string.Equals(item.Id, targetCollectorId, StringComparison.Ordinal)
                && item.Status is CollectorStatus.Approved or CollectorStatus.Active).ToArray()
            : allCollectors.Where(item =>
                string.Equals(item.Environment, targetEnvironment, StringComparison.Ordinal)
                && item.Status is CollectorStatus.Approved or CollectorStatus.Active).ToArray();
        if (targets.Length == 0)
        {
            return Results.Conflict(new ErrorResponse(
                targetCollectorId is not null
                    ? "That collector was not found or is not approved/active."
                    : $"No approved or active collectors are in the '{targetEnvironment}' group."));
        }

        PackPopulationDiff diff = PackGalleryService.BuildDiff(loaded, targets);
        try
        {
            PackInstallRequestRecord created = await store.SubmitPackInstallAsync(
                loaded.Manifest.Id,
                loaded.Manifest.Version,
                loaded.Manifest.Name,
                loaded.Manifest.PackHash,
                loaded.SignedByKeyId,
                targetEnvironment,
                targetCollectorId,
                diff,
                submission.Reason,
                ManagementApplication.ObjectId(user),
                ManagementApplication.DisplayName(user),
                clock.GetUtcNow(),
                cancellationToken);
            return Results.Created($"/api/packs/install-requests/{created.Id}", created);
        }
        catch (ArgumentException)
        {
            return Results.ValidationProblem(
                new Dictionary<string, string[]> { ["reason"] = ["A decision reason (1-500 characters) is required."] });
        }
        catch (PackInstallConflictException exception)
        {
            return Results.Conflict(new ErrorResponse(exception.Message));
        }
    }

    private static async Task<IResult> ReviewInstallAsync(
        string id,
        bool approve,
        ApprovalRequest request,
        ClaimsPrincipal user,
        PackGalleryService gallery,
        ManagementStore store,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length != 32 || !id.All(Uri.IsHexDigit))
        {
            return Results.NotFound();
        }

        try
        {
            PackInstallRequestRecord? updated = await store.ReviewPackInstallAsync(
                id,
                approve,
                existing =>
                {
                    (LoadedPack? loaded, string? refusal) = gallery.ResolveTrusted(existing.PackId, existing.PackVersion);
                    if (loaded is null)
                    {
                        return refusal ?? "Pack is no longer trusted or available in the gallery.";
                    }

                    if (!string.Equals(loaded.Manifest.PackHash, existing.PackHash, StringComparison.Ordinal))
                    {
                        return "Pack hash changed since the install request was submitted; submit a new request.";
                    }

                    return null;
                },
                request.Reason,
                ManagementApplication.ObjectId(user),
                ManagementApplication.DisplayName(user),
                clock.GetUtcNow(),
                cancellationToken);
            return updated is null ? Results.NotFound() : Results.Ok(updated);
        }
        catch (ArgumentException)
        {
            return Results.ValidationProblem(
                new Dictionary<string, string[]> { ["reason"] = ["A decision reason (1-500 characters) is required."] });
        }
        catch (PackInstallConflictException exception)
        {
            return Results.Conflict(new ErrorResponse(exception.Message));
        }
    }
}

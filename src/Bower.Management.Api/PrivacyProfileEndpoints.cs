using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace Bower.Management.Api;

/// <summary>
/// Privacy profile versions: validate, preview, submit, two-person review, assignment to
/// collectors and the signed collector deployment endpoint. Every permission is enforced
/// here; every state change writes its audit row in the same transaction (see the store).
/// </summary>
internal static class PrivacyProfileEndpoints
{
    // A 256 KiB profile can double when JSON-escaped; previews add a 64 KiB sample.
    private const long SubmissionBodyLimit = 640 * 1024;
    private const long PreviewBodyLimit = 1024 * 1024;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost(
                "/privacy-profiles/validate",
                async (PrivacyProfileContentRequest request, ManagementStore store, CancellationToken cancellationToken) =>
                    Results.Ok(await ValidateAsync(request.Content, store, cancellationToken)))
            .WithMetadata(new RequestSizeLimitAttribute(SubmissionBodyLimit))
            .RequireAuthorization("Operate");

        api.MapPost(
                "/privacy-profiles/preview",
                (PrivacyProfilePreviewRequest request) =>
                {
                    if (request.Sample is null
                        || Encoding.UTF8.GetByteCount(request.Sample) > PrivacyProfileInspector.MaximumSampleBytes)
                    {
                        return Results.BadRequest(
                            new ErrorResponse("Preview sample must be JSON text of at most 64 KiB."));
                    }

                    // Random per-request HMAC key; the result is returned, never stored or logged.
                    return Results.Ok(PrivacyProfileInspector.Preview(request.Content, request.Sample));
                })
            .WithMetadata(new RequestSizeLimitAttribute(PreviewBodyLimit))
            .RequireAuthorization("Operate");

        api.MapGet(
                "/privacy-profiles",
                (ManagementStore store, CancellationToken cancellationToken) =>
                    store.ListPrivacyProfileVersionsAsync(cancellationToken))
            .RequireAuthorization("View");

        api.MapGet(
                "/privacy-profiles/versions/{id}",
                async (string id, ManagementStore store, CancellationToken cancellationToken) =>
                    IsVersionId(id) && await store.GetPrivacyProfileVersionAsync(id, cancellationToken) is { } detail
                        ? Results.Ok(detail)
                        : Results.NotFound())
            .RequireAuthorization("View");

        api.MapPost(
                "/privacy-profiles",
                async (
                    PrivacyProfileSubmission submission,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    try
                    {
                        PrivacyProfileCandidate candidate = PrivacyProfileInspector.Load(submission.Content).Candidate;
                        PrivacyProfileVersionDetail detail = await store.SubmitPrivacyProfileVersionAsync(
                            candidate,
                            submission.ChangeSummary,
                            ManagementApplication.ObjectId(user),
                            ManagementApplication.DisplayName(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        return Results.Created($"/api/privacy-profiles/versions/{detail.Id}", detail);
                    }
                    catch (PrivacyProfileValidationException exception)
                    {
                        return Results.BadRequest(new ErrorResponse(exception.Message));
                    }
                    catch (ArgumentException)
                    {
                        return Results.BadRequest(
                            new ErrorResponse("A change summary of 1–500 characters is required."));
                    }
                })
            .WithMetadata(new RequestSizeLimitAttribute(SubmissionBodyLimit))
            .RequireAuthorization("Operate");

        api.MapPost(
                "/privacy-profiles/versions/{id}/approve",
                (string id, ApprovalRequest request, ClaimsPrincipal user, ManagementStore store,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                    ReviewAsync(id, true, request, user, store, clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapPost(
                "/privacy-profiles/versions/{id}/reject",
                (string id, ApprovalRequest request, ClaimsPrincipal user, ManagementStore store,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                    ReviewAsync(id, false, request, user, store, clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapGet(
                "/privacy-profiles/assignments",
                (ManagementStore store, CancellationToken cancellationToken) =>
                    store.ListPrivacyProfileAssignmentsAsync(cancellationToken))
            .RequireAuthorization("View");

        api.MapPost(
                "/collectors/{id}/privacy-profile",
                (string id, PrivacyProfileAssignmentRequest request, ClaimsPrincipal user, ManagementStore store,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                    IsVersionId(request.VersionId)
                        ? AssignAsync(id, request.VersionId, request.Reason, user, store, clock, cancellationToken)
                        : Task.FromResult<IResult>(Results.BadRequest(new ErrorResponse("Privacy profile version was not found."))))
            .RequireAuthorization("Administer");

        api.MapPost(
                "/collectors/{id}/privacy-profile/clear",
                (string id, ApprovalRequest request, ClaimsPrincipal user, ManagementStore store,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                    AssignAsync(id, null, request.Reason, user, store, clock, cancellationToken))
            .RequireAuthorization("Administer");

        api.MapGet(
                "/collectors/{id}/privacy-profile/deployment",
                async (
                    string id,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    ManagedPrivacyProfileSigner signer,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    PrivacyProfileDeployment deployment = await store.GetPrivacyProfileDeploymentAsync(
                        id,
                        ManagementApplication.ObjectId(user),
                        cancellationToken);
                    switch (deployment.State)
                    {
                        case PrivacyProfileDeploymentState.NotFound:
                            return Results.NotFound();
                        case PrivacyProfileDeploymentState.NotActive:
                            return Results.Conflict(
                                new ErrorResponse("Collector is not active, so it cannot receive a privacy profile."));
                        case PrivacyProfileDeploymentState.Unassigned:
                            return Results.NoContent();
                    }

                    if (!signer.Configured)
                    {
                        return Results.Json(
                            new ErrorResponse("Managed privacy profile signing is not configured."),
                            ManagementJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status503ServiceUnavailable);
                    }

                    return Results.Ok(signer.Sign(
                        id,
                        deployment.VersionId!,
                        deployment.ProfileId!,
                        deployment.Version!,
                        deployment.ContentHash!,
                        deployment.Content!,
                        clock.GetUtcNow()));
                })
            .RequireAuthorization("Collector");
    }

    private static async Task<PrivacyProfileValidation> ValidateAsync(
        string? content,
        ManagementStore store,
        CancellationToken cancellationToken)
    {
        PrivacyProfileValidation validation = PrivacyProfileInspector.Validate(content);
        if (!validation.Valid || validation.ProfileId is null || validation.Version is null)
        {
            return validation;
        }

        string? latest = await store.LatestPrivacyProfileVersionAsync(validation.ProfileId, cancellationToken);
        return PrivacyProfileInspector.RequireGreater(validation.Version, latest) is { } versionError
            ? validation with { Valid = false, Errors = [versionError] }
            : validation;
    }

    private static async Task<IResult> ReviewAsync(
        string id,
        bool approve,
        ApprovalRequest request,
        ClaimsPrincipal user,
        ManagementStore store,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!IsVersionId(id))
        {
            return Results.NotFound();
        }

        try
        {
            PrivacyProfileVersionDetail? detail = await store.ReviewPrivacyProfileVersionAsync(
                id,
                approve,
                request.Reason,
                ManagementApplication.ObjectId(user),
                ManagementApplication.DisplayName(user),
                clock.GetUtcNow(),
                cancellationToken);
            return detail is null ? Results.NotFound() : Results.Ok(detail);
        }
        catch (ArgumentException)
        {
            return ReasonRequired();
        }
        catch (PrivacyProfileConflictException exception)
        {
            return Results.Conflict(new ErrorResponse(exception.Message));
        }
    }

    private static async Task<IResult> AssignAsync(
        string collectorId,
        string? versionId,
        string? reason,
        ClaimsPrincipal user,
        ManagementStore store,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        try
        {
            CollectorRecord? record = await store.AssignPrivacyProfileAsync(
                collectorId,
                versionId,
                reason,
                ManagementApplication.ObjectId(user),
                ManagementApplication.DisplayName(user),
                clock.GetUtcNow(),
                cancellationToken);
            return record is null ? Results.NotFound() : Results.Ok(record);
        }
        catch (ArgumentException)
        {
            return ReasonRequired();
        }
        catch (PrivacyProfileValidationException exception)
        {
            return Results.BadRequest(new ErrorResponse(exception.Message));
        }
        catch (PrivacyProfileConflictException exception)
        {
            return Results.Conflict(new ErrorResponse(exception.Message));
        }
    }

    private static IResult ReasonRequired() =>
        Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
                ["reason"] = ["A reason of 1–500 characters is required."]
            });

    private static bool IsVersionId(string? value) =>
        value is { Length: 32 } && ManagementStore.IsLowerHex(value);
}

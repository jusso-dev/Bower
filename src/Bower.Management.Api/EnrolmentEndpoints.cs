using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace Bower.Management.Api;

/// <summary>
/// Token enrolment and credential lifecycle (#109). Administrators create and revoke tokens
/// and revoke credentials; viewers list metadata. Collectors exchange a token anonymously
/// (the token is the credential) and rotate under their current credential.
/// </summary>
public static class EnrolmentEndpoints
{
    public const string RateLimitPolicy = "enrolment";

    private const int MaximumBodyBytes = 16 * 1024;

    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);

        api.MapGet(
                "/enrolment-tokens",
                (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    store.ListEnrolmentTokensAsync(clock.GetUtcNow(), cancellationToken))
            .RequireAuthorization("View");

        api.MapPost(
                "/enrolment-tokens",
                async (
                    EnrolmentTokenRequest request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    try
                    {
                        IssuedEnrolmentToken issued = await store.CreateEnrolmentTokenAsync(
                            request,
                            ManagementApplication.ObjectId(user),
                            ManagementApplication.DisplayName(user),
                            clock.GetUtcNow(),
                            cancellationToken);
                        // Shown once: the API never returns the token again, and stores only its hash.
                        return Results.Created($"/api/enrolment-tokens/{issued.Record.Id}", issued);
                    }
                    catch (ArgumentException)
                    {
                        return Results.ValidationProblem(
                            new Dictionary<string, string[]>
                            {
                                ["enrolmentToken"] =
                                [
                                    "An environment (1–128 characters), a 1–500 character reason, an optional " +
                                    "collector id (up to 128 characters) and a lifetime of 1–168 hours are required."
                                ]
                            });
                    }
                })
            .WithMetadata(new RequestSizeLimitAttribute(MaximumBodyBytes))
            .RequireAuthorization("Administer");

        api.MapPost(
                "/enrolment-tokens/{id}/revoke",
                async (
                    string id,
                    ApprovalRequest request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    try
                    {
                        EnrolmentTokenRecord? record = await store.RevokeEnrolmentTokenAsync(
                            id,
                            request.Reason,
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
                    catch (CollectorStateException)
                    {
                        return Results.Conflict(new ErrorResponse("Enrolment token is already used or revoked."));
                    }
                })
            .RequireAuthorization("Administer");

        api.MapPost(
                "/collectors/enrol",
                async (
                    CollectorEnrolmentRequest request,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!ManagementStore.ValidEnrolment(request)
                        || !CollectorEnrolment.TryReadPublicKey(request.PublicKey, out string publicKey, out string keyId))
                    {
                        return Results.ValidationProblem(
                            new Dictionary<string, string[]>
                            {
                                ["enrolment"] = ["Collector enrolment is invalid."]
                            });
                    }

                    EnrolmentResult result = await store.EnrolAsync(
                        request,
                        publicKey,
                        keyId,
                        clock.GetUtcNow(),
                        cancellationToken);
                    // One message for every token refusal: the reason is in the audit, not the response.
                    return result.Refusal switch
                    {
                        null => Results.Accepted($"/api/collectors/{result.Credential!.CollectorId}", result.Credential),
                        EnrolmentRefusals.IdentityConflict => Results.Conflict(
                            new ErrorResponse("Collector id is bound to a different principal.")),
                        EnrolmentRefusals.CollectorNotEnrollable => Results.Json(
                            new ErrorResponse("Collector is suspended or revoked."),
                            ManagementJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status403Forbidden),
                        EnrolmentRefusals.KeyReused => Results.Conflict(
                            new ErrorResponse("Credential keys cannot be reused.")),
                        _ => Results.Json(
                            new ErrorResponse("Enrolment token refused."),
                            ManagementJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status401Unauthorized)
                    };
                })
            .WithMetadata(new RequestSizeLimitAttribute(MaximumBodyBytes))
            .RequireRateLimiting(RateLimitPolicy)
            .AllowAnonymous();

        api.MapPost(
                "/collectors/{id}/credentials/rotate",
                async (
                    string id,
                    CollectorCredentialRotationRequest request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!CollectorEnrolment.MayActFor(user, id))
                    {
                        return Results.Forbid();
                    }

                    if (!CollectorEnrolment.TryReadPublicKey(request.PublicKey, out string publicKey, out string keyId))
                    {
                        return Results.ValidationProblem(
                            new Dictionary<string, string[]>
                            {
                                ["publicKey"] = ["An ECDSA P-256 public key PEM is required."]
                            });
                    }

                    try
                    {
                        IssuedCollectorCredential issued = await store.RotateCredentialAsync(
                            id,
                            user.FindFirstValue(CollectorEnrolment.CredentialIdClaim)!,
                            publicKey,
                            keyId,
                            clock.GetUtcNow(),
                            cancellationToken);
                        return Results.Ok(issued);
                    }
                    catch (ArgumentException)
                    {
                        return Results.Conflict(new ErrorResponse("Credential keys cannot be reused."));
                    }
                    catch (CollectorStateException)
                    {
                        return Results.Conflict(new ErrorResponse("Collector cannot rotate its credential in this state."));
                    }
                })
            .WithMetadata(new RequestSizeLimitAttribute(MaximumBodyBytes))
            .RequireAuthorization("EnrolledCollector");

        api.MapGet(
                "/collector-credentials",
                (string? collectorId, ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    store.ListCredentialsAsync(
                        string.IsNullOrWhiteSpace(collectorId) ? null : collectorId,
                        clock.GetUtcNow(),
                        cancellationToken))
            .RequireAuthorization("View");

        api.MapPost(
                "/collectors/{id}/credentials/{credentialId}/revoke",
                async (
                    string id,
                    string credentialId,
                    ApprovalRequest request,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    try
                    {
                        CollectorCredentialRecord? record = await store.RevokeCredentialAsync(
                            id,
                            credentialId,
                            request.Reason,
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
                    catch (CollectorStateException)
                    {
                        return Results.Conflict(new ErrorResponse("Credential is not active."));
                    }
                })
            .RequireAuthorization("Administer");
    }

    private static IResult ReasonRequired() =>
        Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
                ["reason"] = ["A reason of 1–500 characters is required."]
            });
}

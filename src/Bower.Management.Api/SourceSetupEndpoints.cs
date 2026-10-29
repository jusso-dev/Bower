using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace Bower.Management.Api;

/// <summary>
/// Guided source setup: source type definitions, plan and redacted preview, requests that a
/// different approver decides, the signed approved configuration and a server-side check of
/// whether the source produces events. Nothing here pushes configuration to a collector.
/// </summary>
internal static class SourceSetupEndpoints
{
    private const long BodyLimit = 64 * 1024;
    private const int MaximumCollectorIdLength = 128;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/sources/types", () => Results.Ok(SourceSetupRegistry.Definitions))
            .RequireAuthorization("View");

        api.MapPost(
                "/sources/plan",
                async (SourceSetupDraft draft, ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                {
                    if (SourceSetupRegistry.Find(draft.Type) is not { } type)
                    {
                        return Results.BadRequest(new ErrorResponse("Unknown source type."));
                    }

                    return Results.Ok(await PlanAsync(type, draft.CollectorId, draft.Values, store, clock.GetUtcNow(), cancellationToken));
                })
            .WithMetadata(new RequestSizeLimitAttribute(BodyLimit))
            .RequireAuthorization("Operate");

        api.MapGet(
                "/sources/requests",
                async (ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                {
                    DateTimeOffset now = clock.GetUtcNow();
                    Dictionary<string, CollectorRecord> collectors = (await store.ListAsync(null, cancellationToken))
                        .ToDictionary(record => record.Id, StringComparer.Ordinal);
                    List<SourceSetupRequestSummary> summaries = [];
                    foreach (SourceSetupRow row in await store.ListSourceSetupsAsync(cancellationToken))
                    {
                        summaries.Add(Summary(row, Check(row, collectors.GetValueOrDefault(row.CollectorId), now)));
                    }

                    return Results.Ok(summaries);
                })
            .RequireAuthorization("View");

        api.MapGet(
                "/sources/requests/{id}",
                async (string id, ManagementStore store, TimeProvider clock, CancellationToken cancellationToken) =>
                    await DetailAsync(id, store, clock.GetUtcNow(), cancellationToken) is { } detail
                        ? Results.Ok(detail)
                        : Results.NotFound())
            .RequireAuthorization("View");

        api.MapPost(
                "/sources/requests",
                SubmitAsync)
            .WithMetadata(new RequestSizeLimitAttribute(BodyLimit))
            .RequireAuthorization("Operate");

        api.MapPost(
                "/sources/requests/{id}/approve",
                (string id, ApprovalRequest request, ClaimsPrincipal user, ManagementStore store,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                    ReviewAsync(id, true, request, user, store, clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapPost(
                "/sources/requests/{id}/reject",
                (string id, ApprovalRequest request, ClaimsPrincipal user, ManagementStore store,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                    ReviewAsync(id, false, request, user, store, clock, cancellationToken))
            .RequireAuthorization("Approve");

        api.MapGet(
                "/sources/requests/{id}/signed",
                async (
                    string id,
                    ClaimsPrincipal user,
                    ManagementStore store,
                    SourceSetupSigner signer,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    DateTimeOffset now = clock.GetUtcNow();
                    if (await DetailAsync(id, store, now, cancellationToken) is not { } detail)
                    {
                        return Results.NotFound();
                    }

                    if (detail.Status != SourceSetupRequestStatus.Approved)
                    {
                        return Results.Conflict(new ErrorResponse("Only an approved source setup request has signed configuration."));
                    }

                    if (!signer.Configured)
                    {
                        return Results.Json(
                            new ErrorResponse("Source setup signing is not configured."),
                            ManagementJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status503ServiceUnavailable);
                    }

                    await store.RecordAuditAsync(
                        "source-setup.signed-config-issued", "source-setup-request", id,
                        ManagementApplication.ObjectId(user), ManagementApplication.DisplayName(user), now, cancellationToken);
                    return Results.Ok(signer.Sign(detail));
                })
            .RequireAuthorization("Operate");
    }

    private static async Task<IResult> SubmitAsync(
        SourceSetupSubmission submission,
        ClaimsPrincipal user,
        ManagementStore store,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (SourceSetupRegistry.Find(submission.Type) is not { } type)
        {
            return Results.BadRequest(new ErrorResponse("Unknown source type."));
        }

        DateTimeOffset now = clock.GetUtcNow();
        SourceSetupPlanResult result = await PlanAsync(type, submission.CollectorId, submission.Values, store, now, cancellationToken);
        if (!result.Valid || result.Plan is null)
        {
            SetupCheck first = result.Checks.First(check => check.State == SetupCheckStates.Fail);
            return Results.BadRequest(new ErrorResponse($"{first.Message} {first.Fix}"));
        }

        (Dictionary<string, string> values, _) = SourceSetupRegistry.Normalise(type, submission.Values);
        try
        {
            SourceSetupRow? row = await store.SubmitSourceSetupAsync(
                type.Id,
                submission.CollectorId!.Trim(),
                values,
                result.Plan,
                submission.Reason,
                ManagementApplication.ObjectId(user),
                ManagementApplication.DisplayName(user),
                now,
                cancellationToken);
            return row is null
                ? Results.BadRequest(new ErrorResponse("Collector was not found."))
                : Results.Created($"/api/sources/requests/{row.Id}", await DetailAsync(row.Id, store, now, cancellationToken));
        }
        catch (ArgumentException)
        {
            return ReasonRequired();
        }
        catch (CollectorStateException)
        {
            return Results.Conflict(new ErrorResponse("The collector must be approved before sources are added to it."));
        }
        catch (SourceSetupConflictException exception)
        {
            return Results.Conflict(new ErrorResponse(exception.Message));
        }
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
        if (!IsRequestId(id))
        {
            return Results.NotFound();
        }

        DateTimeOffset now = clock.GetUtcNow();
        try
        {
            SourceSetupRow? row = await store.ReviewSourceSetupAsync(
                id,
                approve,
                request.Reason,
                ManagementApplication.ObjectId(user),
                ManagementApplication.DisplayName(user),
                now,
                cancellationToken);
            return row is null ? Results.NotFound() : Results.Ok(await DetailAsync(id, store, now, cancellationToken));
        }
        catch (ArgumentException)
        {
            return ReasonRequired();
        }
        catch (SourceSetupConflictException exception)
        {
            return Results.Conflict(new ErrorResponse(exception.Message));
        }
    }

    /// <summary>Field checks, collector checks, the generated plan and the redacted preview.</summary>
    private static async Task<SourceSetupPlanResult> PlanAsync(
        SourceSetupType type,
        string? collectorId,
        Dictionary<string, string>? raw,
        ManagementStore store,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        (Dictionary<string, string> values, List<SetupCheck> checks) = SourceSetupRegistry.Normalise(type, raw);
        CollectorRecord? collector = null;
        string id = collectorId?.Trim() ?? string.Empty;
        if (id.Length is 0 or > MaximumCollectorIdLength)
        {
            checks.Add(SourceSetupRegistry.Fail("collector", "Choose the collector that receives this source.", "Pick an approved collector from the list."));
        }
        else if ((collector = await store.GetAsync(id, cancellationToken)) is null)
        {
            checks.Add(SourceSetupRegistry.Fail("collector", "That collector was not found.", "Pick an approved collector from the list."));
        }
        else if (collector.Status is not (CollectorStatus.Approved or CollectorStatus.Active))
        {
            checks.Add(SourceSetupRegistry.Fail(
                "collector",
                $"The collector is {collector.Status.ToString().ToLowerInvariant()}, so it cannot take a new source.",
                "Approve or reinstate the collector on the Approvals or Collectors page first."));
        }
        else if (CollectorConnectivity.Evaluate(collector, now) is CollectorConnectivity.Offline or CollectorConnectivity.Stale)
        {
            checks.Add(SourceSetupRegistry.Warn(
                "collector",
                "The collector is not reporting right now.",
                "You can still ask for approval, but Bower cannot check the source until the collector reports again."));
        }

        if (checks.Any(check => check.State == SetupCheckStates.Fail))
        {
            return new SourceSetupPlanResult(false, checks, null, null);
        }

        SourceSetupPlan plan = SourceSetupRegistry.Plan(type, id, values);
        if (collector!.Sources.Any(source => source.Id == plan.Verification.ReportId) && plan.Verification.Kind == "source")
        {
            checks.Add(SourceSetupRegistry.Warn(
                "duplicate",
                $"This collector already reports {plan.Verification.ReportId}.",
                "Use a different application or environment name unless you are replacing the existing source."));
        }

        string? profileContent = null;
        string? profileLabel = null;
        if (collector.DesiredPrivacyProfile is { } assigned
            && await store.GetPrivacyProfileVersionAsync(assigned.VersionId, cancellationToken) is { } version)
        {
            profileContent = version.Content;
            profileLabel = $"{version.ProfileId} {version.Version}";
        }

        SourceSetupPreview preview = SourceSetupRegistry.Preview(type, values, profileContent, profileLabel);
        if (!preview.Valid)
        {
            checks.Add(SourceSetupRegistry.Fail("privacy", "The preview could not be safely redacted.",
                "Check the collector's approved privacy profile before requesting this change."));
            return new SourceSetupPlanResult(false, checks, null, null);
        }

        checks.Add(new SetupCheck("values", SetupCheckStates.Pass, "Every setting is valid.", null));
        return new SourceSetupPlanResult(true, checks, plan, preview);
    }

    private static async Task<SourceSetupRequestDetail?> DetailAsync(
        string id,
        ManagementStore store,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!IsRequestId(id) || await store.GetSourceSetupAsync(id, cancellationToken) is not { } row)
        {
            return null;
        }

        CollectorRecord? collector = await store.GetAsync(row.CollectorId, cancellationToken);
        SourceSetupStatusCheck check = Check(row, collector, now);
        return new SourceSetupRequestDetail(
            row.Id, row.Type, Title(row.Type), row.CollectorId, row.Status, row.ContentHash, row.Reason,
            row.RequestedByName, row.RequestedAt, row.ReviewerName, row.ReviewedAt, row.ReviewReason, check,
            row.RequestedByObjectId, row.Values, row.Plan);
    }

    private static SourceSetupRequestSummary Summary(SourceSetupRow row, SourceSetupStatusCheck check) =>
        new(
            row.Id, row.Type, Title(row.Type), row.CollectorId, row.Status, row.ContentHash, row.Reason,
            row.RequestedByName, row.RequestedAt, row.ReviewerName, row.ReviewedAt, row.ReviewReason, check);

    private static string Title(string type) => SourceSetupRegistry.Find(type)?.Title ?? type;

    /// <summary>
    /// Is the source working? Worked out from the request state and the collector's last
    /// heartbeat only: never from anything the browser reports.
    /// </summary>
    internal static SourceSetupStatusCheck Check(SourceSetupRow row, CollectorRecord? collector, DateTimeOffset now)
    {
        if (row.Status == SourceSetupRequestStatus.Rejected)
        {
            return new(
                SetupStepStates.Attention,
                "Rejected",
                [new SetupCheck("approval", SetupCheckStates.Fail, $"{row.ReviewerName ?? "An approver"} rejected this request.",
                    "Read the reason, change the settings and ask for approval again.")],
                null, collector?.LastSeenAt, now);
        }

        if (row.Status != SourceSetupRequestStatus.Approved)
        {
            return new(
                SetupStepStates.InProgress,
                "Waiting for approval",
                [new SetupCheck("approval", SetupCheckStates.Pending,
                    "Waiting for an approver other than the person who asked.",
                    "Ask someone with the Bower.Approver role to review it on the Approvals page.")],
                null, collector?.LastSeenAt, now);
        }

        if (collector is null || collector.Status is CollectorStatus.Suspended or CollectorStatus.Revoked or CollectorStatus.Pending)
        {
            return new(
                SetupStepStates.Attention,
                "Collector unavailable",
                [new SetupCheck("collector", SetupCheckStates.Fail,
                    collector is null ? "The collector no longer exists." : $"The collector is {collector.Status.ToString().ToLowerInvariant()}.",
                    "Reinstate the collector on the Collectors page, or set the source up on another collector.")],
                null, collector?.LastSeenAt, now);
        }

        string connectivity = CollectorConnectivity.Evaluate(collector, now);
        if (connectivity is CollectorConnectivity.Offline or CollectorConnectivity.Stale)
        {
            return new(
                SetupStepStates.Attention,
                "Collector not reporting",
                [new SetupCheck("collector", SetupCheckStates.Fail,
                    $"The collector last reported at {collector.LastSeenAt.ToString("u", CultureInfo.InvariantCulture)}, so Bower cannot check the source.",
                    "Start the collector, or check its network path to the management API.")],
                null, collector.LastSeenAt, now);
        }

        if (collector.LastSeenAt < row.ReviewedAt)
        {
            return new(
                SetupStepStates.InProgress,
                "Waiting for a check-in",
                [new SetupCheck("report", SetupCheckStates.Pending,
                    "The collector has not checked in since this request was approved.",
                    "Install the approved settings and wait for the next check-in.")],
                null, collector.LastSeenAt, now);
        }

        SourceSetupVerification verification = row.Plan.Verification;
        if (verification.Kind == "output")
        {
            OutputReport? output = collector.Outputs.FirstOrDefault(item => item.Id == verification.ReportId);
            return output switch
            {
                null => new(
                    SetupStepStates.InProgress,
                    "Waiting for the collector",
                    [new SetupCheck("report", SetupCheckStates.Pending,
                        $"The collector does not use the {verification.ReportId} output yet.",
                        "Install the approved settings on the collector host and restart the collector.")],
                    null, collector.LastSeenAt, now),
                _ when Healthy(output.Status) => new(
                    SetupStepStates.Complete,
                    "Working",
                    [new SetupCheck("report", SetupCheckStates.Pass, $"The collector reports the {verification.ReportId} output as healthy.", null)],
                    output.LastAcknowledgedAt, collector.LastSeenAt, now),
                _ => new(
                    SetupStepStates.Attention,
                    "Needs attention",
                    [new SetupCheck("report", SetupCheckStates.Fail,
                        $"The collector reports the {verification.ReportId} output as {output.Status}.",
                        "Check the spool directory's permissions and free space on the collector host.")],
                    output.LastAcknowledgedAt, collector.LastSeenAt, now)
            };
        }

        SourceReport? source = collector.Sources.FirstOrDefault(item => item.Id == verification.ReportId);
        if (source is null)
        {
            return new(
                SetupStepStates.InProgress,
                "Waiting for the collector",
                [new SetupCheck("report", SetupCheckStates.Pending,
                    $"The collector does not expect {verification.ReportId} yet.",
                    "Install the approved files, set the variables and restart the collector.")],
                null, collector.LastSeenAt, now);
        }

        if (Healthy(source.Status) && (source.LastEventAt is null || source.LastEventAt < row.ReviewedAt))
        {
            return new(
                SetupStepStates.InProgress,
                "Waiting for a new event",
                [new SetupCheck("report", SetupCheckStates.Pending,
                    "No accepted event after this request was approved has been reported yet.",
                    "Install the approved settings and produce a matching security event, then wait for the next check-in.")],
                source.LastEventAt, collector.LastSeenAt, now);
        }

        if (Healthy(source.Status))
        {
            return new(
                SetupStepStates.Complete,
                "Receiving events",
                [new SetupCheck("report", SetupCheckStates.Pass, $"The collector reports events from {verification.ReportId}.", null)],
                source.LastEventAt, collector.LastSeenAt, now);
        }

        if (string.Equals(source.Status, "pending", StringComparison.OrdinalIgnoreCase))
        {
            return new(
                SetupStepStates.InProgress,
                "Waiting for the first event",
                [new SetupCheck("report", SetupCheckStates.Pending,
                    $"The collector expects {verification.ReportId} but has not seen an event from it yet.",
                    "Make the sender produce one (for example a failed sign-in), then check the sender settings and allowed senders.")],
                source.LastEventAt, collector.LastSeenAt, now);
        }

        return new(
            SetupStepStates.Attention,
            "No events",
            [new SetupCheck("report", SetupCheckStates.Fail,
                $"The collector reports {verification.ReportId} as {source.Status}: no accepted event within its allowance.",
                "Check that the sender runs and can reach the collector, then look at the collector's /v1/status counters for refusals.")],
            source.LastEventAt, collector.LastSeenAt, now);
    }

    private static bool Healthy(string status) => string.Equals(status, "healthy", StringComparison.OrdinalIgnoreCase);

    private static IResult ReasonRequired() =>
        Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
                ["reason"] = ["A reason of 1–500 characters is required."]
            });

    private static bool IsRequestId(string? value) =>
        value is { Length: 32 } && ManagementStore.IsLowerHex(value);
}

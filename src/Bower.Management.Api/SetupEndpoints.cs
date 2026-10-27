using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bower.Dcr;
using Bower.Evidence;

namespace Bower.Management.Api;

/// <summary>What the API itself trusts, for the Entra step. Public values only.</summary>
public sealed record SetupEnvironment(bool DevelopmentAuthentication, string? TenantId, string? Audience);

/// <summary>
/// First-run onboarding wizard (<c>/setup</c>). Progress is computed from server state; only
/// administrators change it and every change is audited. The canary reuses the evidence runner,
/// so only a destination query that returned the exact event shows as proof.
/// </summary>
internal static partial class SetupEndpoints
{
    private const int ListedCollectors = 5;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet(
                "/setup",
                (ClaimsPrincipal user, ManagementStore store, SetupCanaryOptions options, SetupEnvironment environment,
                    CancellationToken cancellationToken) =>
                    StatusAsync(user, store, options, environment, cancellationToken))
            .RequireAuthorization("View");

        api.MapPost(
                "/setup/destination",
                async (SetupDestinationRequest request, ClaimsPrincipal user, ManagementStore store, TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    Dictionary<string, string[]> errors = [];
                    string workspaceId = request.WorkspaceId?.Trim() ?? string.Empty;
                    string? workspaceResourceId = Optional(request.WorkspaceResourceId);
                    string? dcrResourceId = Optional(request.DcrResourceId);
                    string table = Optional(request.Table) ?? SentinelSchema.Default.TableName;
                    if (!Guid.TryParseExact(workspaceId, "D", out _))
                    {
                        errors["workspaceId"] = ["Enter the workspace ID as a GUID, for example 6f1c2b9e-3d4a-4e5f-8a7b-9c0d1e2f3a4b."];
                    }

                    if (workspaceResourceId is not null && !WorkspaceResourceIdPattern().IsMatch(workspaceResourceId))
                    {
                        errors["workspaceResourceId"] = ["Enter the workspace resource ID as /subscriptions/…/resourceGroups/…/providers/Microsoft.OperationalInsights/workspaces/NAME, or leave it empty."];
                    }

                    if (dcrResourceId is not null && !DcrResourceIdPattern().IsMatch(dcrResourceId))
                    {
                        errors["dcrResourceId"] = ["Enter the data collection rule resource ID as /subscriptions/…/resourceGroups/…/providers/Microsoft.Insights/dataCollectionRules/NAME, or leave it empty."];
                    }

                    if (!TablePattern().IsMatch(table))
                    {
                        errors["table"] = ["Enter a Log Analytics table name such as BowerSecurity_CL (letters, digits and underscores)."];
                    }

                    if (errors.Count > 0)
                    {
                        return Results.ValidationProblem(errors);
                    }

                    await store.SetSetupDestinationAsync(
                        workspaceId.ToLowerInvariant(), workspaceResourceId, dcrResourceId, table,
                        ManagementApplication.ObjectId(user), ManagementApplication.DisplayName(user),
                        clock.GetUtcNow(), cancellationToken);
                    return Results.Ok((await store.GetSetupStateAsync(cancellationToken)).Destination);
                })
            .RequireAuthorization("Administer");

        api.MapPost(
                "/setup/destination/check",
                (ClaimsPrincipal user, ManagementStore store, SetupCanaryOptions options, ISetupEvidenceClientFactory factory,
                    TimeProvider clock, ILoggerFactory loggers, CancellationToken cancellationToken) =>
                    CheckDestinationAsync(user, store, options, factory, clock, loggers, cancellationToken))
            .RequireAuthorization("Administer");

        api.MapGet(
                "/setup/dcr-template",
                () => Results.File(
                    Encoding.UTF8.GetBytes(DcrTemplateGenerator.Generate(new DcrTemplateOptions()).ToJsonString()),
                    "application/json",
                    "bower-dcr.json"))
            .RequireAuthorization("View");

        api.MapPost(
                "/setup/probe-profile",
                async (SetupProbeRequest request, ClaimsPrincipal user, ManagementStore store, TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    string? profile = request.Profile?.Trim();
                    if (profile is null || ProbeOptions().All(option => option.Profile != profile))
                    {
                        return Results.BadRequest(new ErrorResponse(
                            $"Choose one of: {string.Join(", ", ProbeOptions().Select(option => option.Profile))}."));
                    }

                    await store.SetSetupProbeProfileAsync(
                        profile, ManagementApplication.ObjectId(user), ManagementApplication.DisplayName(user),
                        clock.GetUtcNow(), cancellationToken);
                    return Results.Ok((await store.GetSetupStateAsync(cancellationToken)).Probe);
                })
            .RequireAuthorization("Administer");

        api.MapPost(
                "/setup/canary",
                async (ClaimsPrincipal user, ManagementStore store, SetupCanaryOptions options, SetupCanaryService canary,
                    TimeProvider clock, CancellationToken cancellationToken) =>
                {
                    (SetupDestination? destination, SetupProbeChoice? probe) = await store.GetSetupStateAsync(cancellationToken);
                    bool collectorReady = (await store.ListAsync(null, cancellationToken)).Any(IsApproved);
                    List<string> missing = [];
                    if (destination is null)
                    {
                        missing.Add("choose where events go (step 3)");
                    }

                    if (!collectorReady)
                    {
                        missing.Add("approve a collector (step 4)");
                    }

                    if (probe is null)
                    {
                        missing.Add("choose what the test proves (step 5)");
                    }

                    if (missing.Count > 0)
                    {
                        return Results.Conflict(new ErrorResponse($"Finish these steps first: {string.Join("; ", missing)}."));
                    }

                    if (!options.Configured)
                    {
                        return Results.Conflict(new ErrorResponse(
                            "Test events are not configured on the management server. Set Bower:Setup:Canary:CollectorUrl and Bower:Setup:Canary:IngestTokenFile."));
                    }

                    try
                    {
                        string actorObjectId = ManagementApplication.ObjectId(user);
                        string actorName = ManagementApplication.DisplayName(user);
                        SetupCanaryRun run = await store.StartSetupCanaryRunAsync(
                            probe!.Profile, destination!.WorkspaceId, destination.Table, actorObjectId, actorName,
                            clock.GetUtcNow(), cancellationToken);
                        canary.Launch(run, destination);
                        return Results.Accepted("/api/setup", run);
                    }
                    catch (SetupCanaryBusyException)
                    {
                        return Results.Conflict(new ErrorResponse("A test event is already in progress. Wait for it to finish."));
                    }
                })
            .RequireAuthorization("Administer");

        api.MapGet(
                "/setup/canary/runs/{id}/bundle",
                async (string id, ManagementStore store, CancellationToken cancellationToken) =>
                    RunIdPattern().IsMatch(id) && await store.GetSetupCanaryBundleAsync(id, cancellationToken) is { } bundle
                        ? Results.File(Encoding.UTF8.GetBytes(bundle), "application/json", $"bower-evidence-{id}.json")
                        : Results.NotFound())
            .RequireAuthorization("View");
    }

    internal static IReadOnlyList<SetupProbeOption> ProbeOptions() =>
    [
        new(
            ProbeProfiles.Generic,
            "Generic test event",
            "Sends Bower's canary event through the collector's event intake. Works without a pack.",
            null,
            "collector_canary"),
        .. ParserProbeFixtures.All.Select(fixture => new SetupProbeOption(
            fixture.Profile,
            $"Pack {fixture.PackId}, parser {fixture.ParserIndex.ToString(CultureInfo.InvariantCulture)}",
            $"Sends a synthetic {fixture.ExpectedEventType} record through the signed {fixture.PackId} parser, so the test also proves that parser works.",
            fixture.PackId,
            fixture.ExpectedEventType))
    ];

    private static async Task<SetupStatus> StatusAsync(
        ClaimsPrincipal user,
        ManagementStore store,
        SetupCanaryOptions options,
        SetupEnvironment environment,
        CancellationToken cancellationToken)
    {
        (SetupDestination? destination, SetupProbeChoice? probe) = await store.GetSetupStateAsync(cancellationToken);
        IReadOnlyList<CollectorRecord> collectors = await store.ListAsync(null, cancellationToken);
        SetupCanaryRun? run = await store.LatestSetupCanaryRunAsync(cancellationToken);
        bool canChange = user.IsInRole(BowerRoles.Administrator);
        CollectorRecord[] approved = collectors.Where(IsApproved).ToArray();
        CollectorRecord[] pending = collectors.Where(item => item.Status == CollectorStatus.Pending).ToArray();

        SetupStep signIn = new(
            SetupStepIds.SignIn,
            SetupStepStates.Complete,
            [
                Pass("signed-in", $"Signed in as {ManagementApplication.DisplayName(user)}."),
                canChange
                    ? Pass("can-change", "You have the Bower.Administrator role, so you can change setup.")
                    : Warn("can-change", "You can see setup progress but not change it.",
                        "Ask a Bower administrator to make changes, or to assign you the Bower.Administrator app role.")
            ],
            null,
            null);

        string[] roles = user.FindAll("roles").Select(claim => claim.Value).Where(BowerRoles.Interactive.Contains).Order().ToArray();
        SetupCheck apiTrust = environment.DevelopmentAuthentication
            ? Warn("api-trust", "Development sign-in is on: every request is treated as a full administrator.",
                "Never use development mode in production. Set BOWER_AUTH_MODE=entra with Bower:Entra:TenantId and Bower:Entra:Audience.")
            : Pass("api-trust", $"The API accepts Entra ID tokens from tenant {environment.TenantId} for {environment.Audience}.");
        SetupCheck collectorRole = collectors.Count > 0
            ? Pass("collector-role", "A collector has signed in with the Bower.Collector app role.")
            : Pending("collector-role", "No collector has signed in yet.",
                "Assign the Bower.Collector app role (deploy/entra/api-app-manifest.json) to each collector's managed identity, then start it with management enrolment.");
        SetupStep entra = new(
            SetupStepIds.Entra,
            environment.DevelopmentAuthentication ? SetupStepStates.Attention
                : collectors.Count > 0 ? SetupStepStates.Complete : SetupStepStates.NotStarted,
            [apiTrust, Pass("roles", $"Your token carries these Bower roles: {string.Join(", ", roles)}."), collectorRole],
            null,
            null);

        SetupStep destinationStep = destination is null
            ? new(
                SetupStepIds.Destination,
                SetupStepStates.NotStarted,
                [Pending("workspace", "No Log Analytics workspace chosen yet.",
                    "Enter the workspace ID from the workspace's Overview page in the Azure portal.")],
                null,
                null)
            : new(
                SetupStepIds.Destination,
                SetupStepStates.Complete,
                [
                    Pass("workspace", $"Events go to workspace {destination.WorkspaceId}, table {destination.Table}."),
                    destination.WorkspaceResourceId is null
                        ? Warn("workspace-resource", "No workspace resource ID: Bower cannot check the table or read its retention.",
                            "Add the workspace resource ID (Azure portal, the workspace, JSON View).")
                        : Pass("workspace-resource", "Workspace resource ID saved: Bower can check the table and read its retention."),
                    destination.DcrResourceId is null
                        ? Warn("dcr", "No data collection rule resource ID: Bower cannot check the rule.",
                            "Add the rule's resource ID, or download the template, deploy it and add the new rule's ID.")
                        : Pass("dcr", "Data collection rule saved: Bower can check it for drift.")
                ],
                destination.UpdatedBy,
                destination.UpdatedAt);

        List<SetupCheck> collectorChecks = [];
        if (approved.Length > 0)
        {
            collectorChecks.Add(Pass("approved", $"{Count(approved.Length, "collector")} approved: {Names(approved)}."));
        }

        if (pending.Length > 0)
        {
            collectorChecks.Add(Warn("pending", $"{Count(pending.Length, "collector")} waiting for approval: {Names(pending)}.",
                "Someone with Bower.Approver or Bower.Administrator records a reasoned decision on the Approvals page. Setup never approves collectors."));
        }

        if (collectors.Count == 0)
        {
            collectorChecks.Add(Pending("none", "No collector has asked to enrol yet.",
                "Install a collector with management enrolment. It appears on the Approvals page when it registers."));
        }
        else if (approved.Length == 0 && pending.Length == 0)
        {
            collectorChecks.Add(Warn("none-approved", "No collector is approved: every registered collector is suspended or revoked.",
                "Reinstate a collector or enrol a new one, then approve it on the Approvals page."));
        }

        SetupStep collectorStep = new(
            SetupStepIds.Collector,
            approved.Length > 0 ? SetupStepStates.Complete
                : collectors.Count > 0 ? SetupStepStates.Attention : SetupStepStates.NotStarted,
            collectorChecks,
            null,
            null);

        SetupProbeOption? chosen = ProbeOptions().FirstOrDefault(option => option.Profile == probe?.Profile);
        SetupStep probeStep = chosen is null
            ? new(
                SetupStepIds.Probe,
                SetupStepStates.NotStarted,
                [Pending("profile", "No test chosen yet.", "Choose the generic test, or a pack parser installed on your collector.")],
                null,
                null)
            : new(SetupStepIds.Probe, SetupStepStates.Complete, [Pass("profile", $"The test uses: {chosen.Title}.")], probe!.UpdatedBy, probe.UpdatedAt);

        return new SetupStatus(
            canChange,
            [
                signIn,
                entra,
                destinationStep,
                collectorStep,
                probeStep,
                CanaryStep(options, run, destination is not null, approved.Length > 0, chosen is not null),
                ProofStep(options, run)
            ],
            destination,
            probe,
            ProbeOptions(),
            new SetupCanaryConfiguration(
                options.Configured,
                options.VerifierConfigured,
                options.SigningKeyFile is not null,
                options.CollectorUrl?.Host,
                options.TimeoutMinutes),
            run);
    }

    private static SetupStep CanaryStep(
        SetupCanaryOptions options, SetupCanaryRun? run, bool destination, bool collector, bool probe)
    {
        List<SetupCheck> checks = [];
        if (!destination)
        {
            checks.Add(Pending("needs-destination", "Choose where events go first.", "Complete step 3."));
        }

        if (!collector)
        {
            checks.Add(Pending("needs-collector", "Approve a collector first.", "Complete step 4."));
        }

        if (!probe)
        {
            checks.Add(Pending("needs-probe", "Choose what the test proves first.", "Complete step 5."));
        }

        checks.Add(options.Configured
            ? Pass("server", $"The management server sends test events to the collector at {options.CollectorUrl!.Host}.")
            : Pending("server", "The management server is not set up to send test events.",
                "Set Bower:Setup:Canary:CollectorUrl and Bower:Setup:Canary:IngestTokenFile on the management host (docs/operations/console-onboarding.md)."));
        checks.Add(options.VerifierConfigured
            ? Pass("verifier", "A read-only verifier identity is configured, so Bower can look for the test event in Sentinel.")
            : Warn("verifier", "No read-only verifier identity: test runs are simulated and never count as proof.",
                "Set Bower:Setup:Canary:Credential (for example managed-identity) with Log Analytics Reader on the workspace."));
        bool blocked = !destination || !collector || !probe || !options.Configured;

        string state;
        if (run?.State == SetupCanaryRunStates.Running)
        {
            state = SetupStepStates.InProgress;
            checks.Add(Pending("run", "Sending the test event.", "No action needed. This page updates by itself."));
        }
        else if (blocked)
        {
            state = SetupStepStates.Blocked;
        }
        else if (run is null)
        {
            state = SetupStepStates.NotStarted;
            checks.Add(Pending("run", "Ready to send a test event.", "Choose Send test event."));
        }
        else if (run.CollectorAccepted && run.EventId is not null)
        {
            state = SetupStepStates.Complete;
            checks.Add(Pass("run", $"The collector accepted test event {run.EventId}. Acceptance alone does not prove delivery; see step 7."));
        }
        else
        {
            state = SetupStepStates.Attention;
            checks.Add(Fail("run", run.Message ?? SetupOutcomes.Describe(run.Outcome).Message, run.Fix ?? SetupOutcomes.Describe(run.Outcome).Fix));
        }

        return new SetupStep(SetupStepIds.Canary, state, checks, run?.RequestedBy, run?.RequestedAt);
    }

    private static SetupStep ProofStep(SetupCanaryOptions options, SetupCanaryRun? run)
    {
        if (run is null)
        {
            return new SetupStep(
                SetupStepIds.Proof,
                SetupStepStates.NotStarted,
                [Pending("proof", "No test event has been sent yet.", "Send a test event in step 6.")],
                null,
                null);
        }

        if (run.State == SetupCanaryRunStates.Running)
        {
            return new SetupStep(
                SetupStepIds.Proof,
                SetupStepStates.InProgress,
                [Pending("proof", $"Looking for the test event in Sentinel (up to {Count(options.TimeoutMinutes, "minute")}).",
                    "No action needed. This page updates by itself.")],
                run.RequestedBy,
                run.RequestedAt);
        }

        if (run.Mode == EvidenceModes.Verified)
        {
            string latency = run.LatencySeconds is { } seconds
                ? $" {seconds.ToString("0.#", CultureInfo.InvariantCulture)} seconds after it was sent"
                : string.Empty;
            return new SetupStep(
                SetupStepIds.Proof,
                SetupStepStates.Complete,
                [
                    Pass("proof", $"Verified: Bower queried {run.Table} and found test event {run.EventId}{latency}."),
                    run.HasSignature
                        ? Pass("bundle", "A signed evidence bundle is ready to download.")
                        : Warn("bundle", "The evidence bundle is unsigned.",
                            "Set Bower:Setup:Canary:SigningKeyFile on the management host to sign future bundles.")
                ],
                run.RequestedBy,
                run.CompletedAt);
        }

        if (!run.CollectorAccepted && run.State == SetupCanaryRunStates.Completed)
        {
            return new SetupStep(
                SetupStepIds.Proof,
                SetupStepStates.Blocked,
                [Pending("proof", "Nothing to prove yet: the collector did not accept the test event.", "Fix step 6, then send the test event again.")],
                run.RequestedBy,
                run.CompletedAt);
        }

        SetupCheck check = run.Mode == EvidenceModes.Simulated
            ? Warn("proof", run.Message!, run.Fix!)
            : Fail("proof", run.Message!, run.Fix!);
        return new SetupStep(SetupStepIds.Proof, SetupStepStates.Attention, [check], run.RequestedBy, run.CompletedAt);
    }

    /// <summary>Read-only DCR and table drift checks, the same comparisons <c>bower doctor</c> runs.</summary>
    private static async Task<IResult> CheckDestinationAsync(
        ClaimsPrincipal user,
        ManagementStore store,
        SetupCanaryOptions options,
        ISetupEvidenceClientFactory factory,
        TimeProvider clock,
        ILoggerFactory loggers,
        CancellationToken cancellationToken)
    {
        SetupDestination? destination = (await store.GetSetupStateAsync(cancellationToken)).Destination;
        if (destination is null || (destination.DcrResourceId is null && destination.WorkspaceResourceId is null))
        {
            return Results.Conflict(new ErrorResponse(
                "Save a workspace resource ID or data collection rule resource ID first."));
        }

        if (!options.VerifierConfigured)
        {
            return Results.Conflict(new ErrorResponse(
                "Bower has no read-only Azure identity for checks. Set Bower:Setup:Canary:Credential on the management host."));
        }

        IArmReader arm = factory.Create(options).Arm
            ?? throw new InvalidOperationException("Verifier clients have no ARM reader.");
        List<SetupCheck> checks = [];
        try
        {
            if (destination.DcrResourceId is { } ruleId)
            {
                JsonObject? rule = await arm.GetAsync(ruleId, AzureApiVersions.DataCollectionRules, cancellationToken);
                checks.AddRange(rule is null
                    ? [Fail("dcr", "Bower could not read the data collection rule.",
                        "Check the rule resource ID, and give the verifier identity Reader on the rule.")]
                    : Findings("dcr", "The data collection rule matches what Bower sends.", DcrDrift.CompareRule(rule.ToJsonString(), SentinelSchema.Default)));
            }

            if (destination.WorkspaceResourceId is { } workspaceId)
            {
                JsonObject? table = await arm.GetAsync(
                    $"{workspaceId}/tables/{destination.Table}", AzureApiVersions.LogAnalytics, cancellationToken);
                checks.AddRange(table is null
                    ? [Fail("table", $"Bower could not read table {destination.Table}.",
                        "Deploy the table with the DCR template, and give the verifier identity Reader on the workspace.")]
                    : Findings("table", $"Table {destination.Table} matches Bower's schema.", DcrDrift.CompareTable(table.ToJsonString(), SentinelSchema.Default)));
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Type only: Azure messages stay server side.
            LogCheckFailed(loggers.CreateLogger("Bower.Management.Setup"), exception.GetType().Name);
            checks.Add(Fail("azure", "Bower could not reach Azure with its read-only identity.",
                "Check Bower:Setup:Canary:Credential on the management host and its network access to management.azure.com."));
        }

        DateTimeOffset now = clock.GetUtcNow();
        await store.RecordAuditAsync(
            "setup.destination-checked", "setup", "destination",
            ManagementApplication.ObjectId(user), ManagementApplication.DisplayName(user), now, cancellationToken);
        return Results.Ok(new SetupCheckResult(checks, now));
    }

    private static IEnumerable<SetupCheck> Findings(string id, string healthy, IReadOnlyList<DcrFinding> findings)
    {
        DcrFinding[] problems = findings.Where(finding => finding.Level != FindingLevel.Info).ToArray();
        if (problems.Length == 0)
        {
            return [Pass(id, healthy)];
        }

        // Finding details are Bower-authored comparisons of deployed metadata, never Azure error text.
        return problems.Select(finding => finding.Level == FindingLevel.Error
            ? Fail($"{id}-{finding.Code}", finding.Detail,
                "Download the DCR template from this step (or run bower dcr generate) and redeploy it.")
            : Warn($"{id}-{finding.Code}", finding.Detail,
                "Review the change. If it was not intended, redeploy the DCR template from this step."));
    }

    private static bool IsApproved(CollectorRecord collector) =>
        collector.Status is CollectorStatus.Approved or CollectorStatus.Active;

    private static string Names(IEnumerable<CollectorRecord> collectors)
    {
        CollectorRecord[] all = collectors.ToArray();
        string listed = string.Join(", ", all.Take(ListedCollectors).Select(item => item.MachineName));
        return all.Length > ListedCollectors
            ? $"{listed} and {(all.Length - ListedCollectors).ToString(CultureInfo.InvariantCulture)} more"
            : listed;
    }

    private static string Count(int value, string noun) =>
        $"{value.ToString(CultureInfo.InvariantCulture)} {noun}{(value == 1 ? string.Empty : "s")}";

    private static string? Optional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static SetupCheck Pass(string id, string message) => new(id, SetupCheckStates.Pass, message, null);

    private static SetupCheck Warn(string id, string message, string fix) => new(id, SetupCheckStates.Warn, message, fix);

    private static SetupCheck Fail(string id, string message, string fix) => new(id, SetupCheckStates.Fail, message, fix);

    private static SetupCheck Pending(string id, string message, string fix) => new(id, SetupCheckStates.Pending, message, fix);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Setup destination check failed with {ExceptionType}.")]
    private static partial void LogCheckFailed(ILogger logger, string exceptionType);

    // Resource group names cannot start with '.', so no path segment can be '.' or '..'.
    [GeneratedRegex(
        @"^/subscriptions/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/resourceGroups/[A-Za-z0-9_()-][A-Za-z0-9._()-]{0,89}/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9][A-Za-z0-9-]{2,62}$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex WorkspaceResourceIdPattern();

    [GeneratedRegex(
        @"^/subscriptions/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/resourceGroups/[A-Za-z0-9_()-][A-Za-z0-9._()-]{0,89}/providers/Microsoft\.Insights/dataCollectionRules/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex DcrResourceIdPattern();

    // The same rule EvidenceRunner applies to --table.
    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex TablePattern();

    [GeneratedRegex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex RunIdPattern();
}

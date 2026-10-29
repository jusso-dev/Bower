using Bower.Evidence;
using Bower.Management.Api.Jobs;

namespace Bower.Management.Api;

/// <summary>
/// Builds the plain-English home view from collector records, setup canary runs and redaction
/// counts. Deterministic for a given input and time: every sentence and fix is fixed Bower
/// text, so nothing a collector reports reaches the page except counts and group names.
/// </summary>
public static class HomeStatus
{
    /// <summary>Most groups returned; the rest are counted in <see cref="HomeRecord.GroupsTotal"/>.</summary>
    public const int MaximumGroups = 50;

    /// <summary>An undelivered event older than this is a backlog worth a look.</summary>
    public static readonly TimeSpan BacklogAfter = TimeSpan.FromMinutes(15);

    /// <summary>The redaction week: today (UTC) and the six days before it.</summary>
    public const int WeekDays = 7;

    private const string Collectors = "/collectors";

    private sealed record Condition(
        string Id,
        string State,
        string Has,
        HomeFix Fix,
        Func<CollectorRecord, DateTimeOffset, bool> Applies);

    // Worst first: the first matching condition gives a group its state and reason.
    private static readonly Condition[] Conditions =
    [
        new("offline", HomeStates.Red, "not checked in for more than 15 minutes",
            new("Check that the machine is switched on and can reach Bower.", Collectors),
            (item, now) => Running(item) && CollectorConnectivity.Evaluate(item, now) == CollectorConnectivity.Offline),
        new("history-changed", HomeStates.Red, "reported an event history that changed unexpectedly",
            new("Treat this as a possible tampering sign: check the machine and the Audit page.", "/audit"),
            (item, now) => Fresh(item, now) && Is(item.DeliveryStatus, "ledger-regression")),
        new("not-sending", HomeStates.Red, "not been able to send events for more than 15 minutes",
            new("Open Collectors to see which machine is affected and check its connection to Azure.", Collectors),
            (item, now) => Fresh(item, now) && CollectorConnectivity.Evaluate(item, now) == CollectorConnectivity.Unhealthy),
        new("stale", HomeStates.Amber, "not checked in for a few minutes",
            new("This usually clears by itself. If it lasts, check the machine.", Collectors),
            (item, now) => Running(item) && CollectorConnectivity.Evaluate(item, now) == CollectorConnectivity.Stale),
        new("send-trouble", HomeStates.Amber, "had trouble sending events",
            new("Bower keeps trying. If it lasts more than 15 minutes, check the machine's connection to Azure.", Collectors),
            (item, now) => Fresh(item, now) && !DeliveryOperational(item.DeliveryStatus)),
        new("pending", HomeStates.Amber, "asked to join",
            new("Review the request on the Approvals page.", "/approvals"),
            (item, _) => item.Status == CollectorStatus.Pending),
        new("suspended", HomeStates.Amber, "been paused",
            new("Ask a Bower administrator to check why and reinstate it if it is still needed.", Collectors),
            (item, _) => item.Status == CollectorStatus.Suspended),
        new("set-aside", HomeStates.Amber, "events that could not be sent and were set aside",
            new("Open Collectors to see which machine has them.", Collectors),
            (item, now) => Fresh(item, now) && item.DeadLettered > 0),
        new("backlog", HomeStates.Amber, "events waiting more than 15 minutes to be sent",
            new("Check the machine's connection to Azure.", Collectors),
            (item, now) => Fresh(item, now) && item.OldestUndeliveredAgeSeconds > BacklogAfter.TotalSeconds),
        new("quiet-source", HomeStates.Amber, "an expected app that has gone quiet",
            new("Check that the app is running and still sends events to Bower.", Collectors),
            (item, now) => Fresh(item, now) && item.SourceSummary.Degraded > 0),
        new("policy-not-applied", HomeStates.Amber, "not switched to the assigned event rules yet",
            new("Open Collectors to see which rules it is using.", Collectors),
            (item, now) => Fresh(item, now) && item.PolicyInSync == false),
        new("privacy-not-applied", HomeStates.Amber, "not applied its assigned privacy profile yet",
            new("Open Privacy profiles to check the rollout.", "/privacy-profiles"),
            (item, now) => Fresh(item, now) && item.PrivacyProfileInSync == false)
    ];

    private static readonly HomeFix SetupFix = new("Send a test event from the Setup page.", "/setup");

    /// <summary>
    /// The ids of the conditions that apply to one collector, worst first. The fleet view
    /// (<see cref="FleetStatus"/>) maps these to one plain state per collector, so the home
    /// view and the fleet view always agree on what is wrong.
    /// </summary>
    internal static IReadOnlyList<string> ConditionIds(CollectorRecord item, DateTimeOffset now) =>
        [.. Conditions.Where(condition => condition.Applies(item, now)).Select(condition => condition.Id)];

    public static HomeRecord Evaluate(
        IReadOnlyList<CollectorRecord> collectors,
        SetupCanaryRun? latestRun,
        SetupCanaryRun? latestVerified,
        IReadOnlyList<RedactionReportCount> redactions,
        ISet<string> reportingRedactions,
        DateTimeOffset since,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(collectors);
        ArgumentNullException.ThrowIfNull(redactions);
        ArgumentNullException.ThrowIfNull(reportingRedactions);
        // A revoked identity was removed on purpose; it is history, not a current problem.
        CollectorRecord[] fleet = collectors.Where(item => item.Status != CollectorStatus.Revoked).ToArray();
        Dictionary<string, Condition[]> issues = fleet.ToDictionary(
            item => item.Id,
            item => Conditions.Where(condition => condition.Applies(item, now)).ToArray());

        HomeFlow flow = Flow(fleet, latestRun, latestVerified, now);
        List<HomeAttention> attention = Conditions
            .Select(condition => (condition, count: fleet.Count(item => issues[item.Id].Contains(condition))))
            .Where(item => item.count > 0)
            .Select(item => new HomeAttention(
                item.condition.Id,
                item.condition.State,
                Sentence(item.count, null, item.condition.Has),
                item.condition.Fix,
                item.count))
            .ToList();
        if (fleet.Length == 0)
        {
            attention.Add(new HomeAttention(
                "no-collectors", HomeStates.Amber, "No collectors are connected yet.",
                new HomeFix("Follow the Setup page to connect your first collector.", "/setup"), 0));
        }

        if (flow.Proof.State is HomeProofStates.NotProven or HomeProofStates.Simulated)
        {
            attention.Add(new HomeAttention(
                flow.Proof.State, HomeStates.Amber, flow.Proof.Message, flow.Proof.Fix ?? SetupFix, 0));
        }

        HomeGroup[] groups = fleet
            .GroupBy(item => item.Environment, StringComparer.Ordinal)
            .Select(group => Group(group.Key, group.ToArray(), issues))
            .OrderBy(group => Rank(group.State))
            .ThenBy(group => group.Name, StringComparer.Ordinal)
            .ToArray();
        string state = attention.Select(item => item.State).Append(flow.State).MinBy(Rank)!;
        return new HomeRecord(
            now,
            state,
            flow,
            Protection(fleet, redactions, reportingRedactions, since, now),
            attention,
            groups.Take(MaximumGroups).ToArray(),
            groups.Length);
    }

    private static HomeGroup Group(
        string name,
        CollectorRecord[] members,
        Dictionary<string, Condition[]> issues)
    {
        int healthy = members.Count(item => issues[item.Id].Length == 0);
        Condition? worst = Conditions.FirstOrDefault(condition => members.Any(item => issues[item.Id].Contains(condition)));
        if (worst is null)
        {
            string all = members.Length == 1
                ? "The collector is checking in and sending events."
                : $"All {members.Length} collectors are checking in and sending events.";
            return new HomeGroup(name, HomeStates.Green, members.Length, healthy, all, null, 0);
        }

        int affected = members.Count(item => issues[item.Id].Contains(worst));
        int others = Conditions.Count(condition =>
            condition != worst && members.Any(item => issues[item.Id].Contains(condition)));
        return new HomeGroup(
            name, worst.State, members.Length, healthy, Sentence(affected, members.Length, worst.Has), worst.Fix, others);
    }

    private static HomeFlow Flow(
        CollectorRecord[] fleet,
        SetupCanaryRun? latestRun,
        SetupCanaryRun? latestVerified,
        DateTimeOffset now)
    {
        CollectorRecord[] running = fleet.Where(Running).ToArray();
        int sending = running.Count(item =>
            CollectorConnectivity.Evaluate(item, now) == CollectorConnectivity.Online
            && DeliveryOperational(item.DeliveryStatus));
        int enrolled = fleet.Count(item => item.Status != CollectorStatus.Pending);
        (string state, string summary) = running.Length switch
        {
            0 when enrolled > 0 => (HomeStates.Red, "No. Every collector is paused, so no events are being sent."),
            0 when fleet.Length > 0 => (HomeStates.Amber, "Not yet. A new collector is waiting for approval."),
            0 => (HomeStates.Amber, "Not yet. No collectors are connected."),
            _ when sending == running.Length => (HomeStates.Green, running.Length == 1
                ? "Yes. Your collector is checking in and sending events."
                : $"Yes. All {running.Length} collectors are checking in and sending events."),
            _ when sending == 0 => (HomeStates.Red, running.Length == 1
                ? "No. Your collector is not sending events right now."
                : $"No. None of your {running.Length} collectors are sending events right now."),
            _ => (HomeStates.Amber, Partly(sending, running.Length))
        };
        DateTimeOffset? lastAccepted = fleet.Max(item => item.LastSuccessfulDeliveryAt);
        return new HomeFlow(state, summary, sending, enrolled, lastAccepted, Proof(latestRun, latestVerified));
    }

    /// <summary>Only a run Bower verified by querying the destination is proof; simulated always says so.</summary>
    private static HomeSentinelProof Proof(SetupCanaryRun? latestRun, SetupCanaryRun? latestVerified)
    {
        if (latestRun?.State == SetupCanaryRunStates.Running)
        {
            return new HomeSentinelProof(
                HomeProofStates.InProgress, "Bower is looking for a test event in Microsoft Sentinel now.",
                latestRun.RequestedAt, null);
        }

        if (latestVerified is not null)
        {
            return new HomeSentinelProof(
                HomeProofStates.Verified, "Proven: Bower found a test event in Microsoft Sentinel.",
                latestVerified.CompletedAt, null);
        }

        if (latestRun?.Mode == EvidenceModes.Simulated)
        {
            return new HomeSentinelProof(
                HomeProofStates.Simulated,
                "Simulated only: the last test event was not checked in Microsoft Sentinel, so it is not proof.",
                latestRun.CompletedAt, SetupFix);
        }

        return latestRun is null
            ? new HomeSentinelProof(
                HomeProofStates.NotProven, "Not proven yet: no test event has been checked in Microsoft Sentinel.", null, SetupFix)
            : new HomeSentinelProof(
                HomeProofStates.NotProven, "Not proven: the last test event was not found in Microsoft Sentinel.",
                latestRun.CompletedAt, new HomeFix("Open the Setup page to see why, then send the test event again.", "/setup"));
    }

    private static HomeProtection Protection(
        CollectorRecord[] fleet,
        IReadOnlyList<RedactionReportCount> redactions,
        ISet<string> reportingRedactions,
        DateTimeOffset since,
        DateTimeOffset now)
    {
        HomeRedaction[] byType = redactions
            .Where(item => item.Events > 0)
            .GroupBy(item => RedactionLabels.Group(item.Type), StringComparer.Ordinal)
            .Select(group => new HomeRedaction(
                group.Key,
                RedactionLabels.Label(group.Key),
                group.Aggregate(0L, (total, item) => SaturatingAdd(total, item.Events))))
            .OrderByDescending(item => item.Events)
            .ThenBy(item => item.Label, StringComparer.Ordinal)
            .ToArray();
        CollectorRecord[] working = fleet.Where(item => Fresh(item, now)).ToArray();
        int reporting = working.Count(item => reportingRedactions.Contains(item.Id));
        string summary = byType.Length > 0
            ? "Bower removed these kinds of sensitive details before storing or sending events."
            : reportingRedactions.Count == 0
                ? "No collector has reported privacy counts yet."
                : "No sensitive details were found in events this week.";
        return new HomeProtection(since, summary, byType, reporting, working.Length - reporting);
    }

    private static string Partly(int sending, int running)
    {
        int others = running - sending;
        return $"Partly. {sending} of {running} collectors {(sending == 1 ? "is" : "are")} sending events; "
            + $"{others} {(others == 1 ? "needs" : "need")} a look.";
    }

    /// <summary>"2 of 5 collectors have not checked in…", "The collector has…", "3 collectors have…".</summary>
    private static string Sentence(int count, int? total, string has)
    {
        string subject = (count, total) switch
        {
            (1, 1) => "The collector has",
            _ when count == total => $"All {count} collectors have",
            (1, null) => "1 collector has",
            (_, null) => $"{count} collectors have",
            (1, _) => $"1 of {total} collectors has",
            _ => $"{count} of {total} collectors have"
        };
        return $"{subject} {has}.";
    }

    private static int Rank(string state) => state switch
    {
        HomeStates.Red => 0,
        HomeStates.Amber => 1,
        _ => 2
    };

    /// <summary>Approved to collect and not paused.</summary>
    internal static bool Running(CollectorRecord item) =>
        item.Status is CollectorStatus.Active or CollectorStatus.Approved;

    /// <summary>Running with a heartbeat inside the offline threshold: its report is current evidence.</summary>
    internal static bool Fresh(CollectorRecord item, DateTimeOffset now) =>
        Running(item) && now - item.LastSeenAt <= CollectorStalenessJob.StaleAfter;

    private static bool Is(string? value, string expected) =>
        string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

    // The same operational set the fleet overview uses.
    private static bool DeliveryOperational(string? status) => status?.ToLowerInvariant()
        is "healthy" or "waiting" or "pending" or "idle" or "api-accepted" or "spooled";

    private static long SaturatingAdd(long total, long value) =>
        value <= 0 ? total : value > long.MaxValue - total ? long.MaxValue : total + value;
}

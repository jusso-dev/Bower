namespace Bower.Management.Api;

/// <summary>
/// Deterministic mapping from internal health condition IDs and collector EventIds to plain
/// wording and suggested fixes. Single source of truth for alert validation and catalogue reads.
/// </summary>
public static class AlertCatalogue
{
    public static readonly IReadOnlyList<AlertCatalogueEntry> Entries =
    [
        new("offline", HomeStates.Red, "Collector offline",
            "A collector has not checked in for more than 15 minutes.",
            "Check that the machine is switched on and can reach Bower.", "/collectors", ["2101"]),
        new("history-changed", HomeStates.Red, "Event history changed unexpectedly",
            "A collector reported a queue ledger sequence or hash that regressed.",
            "Treat this as a possible tampering sign: check the machine and the Audit page.", "/audit", ["1600"]),
        new("not-sending", HomeStates.Red, "Delivery stopped",
            "A collector has not been able to send events for more than 15 minutes.",
            "Open Collectors to see which machine is affected and check its connection to Azure.", "/collectors", ["1008"]),
        new("stale", HomeStates.Amber, "Collector check-in delayed",
            "A collector has not checked in for a few minutes.",
            "This usually clears by itself. If it lasts, check the machine.", "/collectors", ["2101"]),
        new("queue-full", HomeStates.Amber, "Queue or disk capacity reached",
            "A collector has a full queue or critically low free disk space and is refusing new events.",
            "Free disk space on the machine, or let it catch up once its connection to Azure works.", "/collectors", ["1500", "1501"]),
        new("send-trouble", HomeStates.Amber, "Delivery trouble",
            "A collector had trouble sending events to its destination.",
            "Bower keeps trying. If it lasts more than 15 minutes, check the machine's connection to Azure.", "/collectors", ["1008"]),
        new("pending", HomeStates.Amber, "Collector awaiting approval",
            "A new collector has asked to join the fleet.",
            "Review the request on the Approvals page.", "/approvals", []),
        new("suspended", HomeStates.Amber, "Collector paused",
            "A collector has been suspended by an administrator or inactivity policy.",
            "Ask a Bower administrator to check why and reinstate it if it is still needed.", "/collectors", []),
        new("set-aside", HomeStates.Amber, "Events set aside in dead-letter queue",
            "Events could not be delivered after retries and were set aside.",
            "Open Collectors to see which machine has them.", "/collectors", ["1510", "1511"]),
        new("backlog", HomeStates.Amber, "Delivery backlog",
            "Queued events have been waiting more than 15 minutes to be sent.",
            "Check the machine's connection to Azure.", "/collectors", ["1008"]),
        new("quiet-source", HomeStates.Amber, "Expected source went quiet",
            "An expected application or event source stopped sending events within its allowance.",
            "Check that the app is running and still sends events to Bower.", "/collectors", ["1110", "1120"]),
        new("policy-not-applied", HomeStates.Amber, "Policy rules out of sync",
            "A collector has not switched to its assigned event rules yet.",
            "Open Collectors to see which rules it is using.", "/collectors", ["1702"]),
        new("privacy-not-applied", HomeStates.Amber, "Privacy profile out of sync",
            "A collector has not applied its assigned privacy profile yet.",
            "Open Privacy profiles to check the rollout.", "/privacy-profiles", ["1702"]),
        new("job-failed", HomeStates.Amber, "Maintenance job failed",
            "A collector maintenance job failed on its last run.",
            "Open the collector's details to see which job; it runs again on its schedule.", "/collectors", ["1302"]),
        new("no-collectors", HomeStates.Amber, "No collectors connected",
            "No collectors are connected to management yet.",
            "Follow the Setup page to connect your first collector.", "/setup", []),
        new(HomeProofStates.NotProven, HomeStates.Amber, "Sentinel delivery not yet proven",
            "No recent test event has been verified in Microsoft Sentinel by query.",
            "Send a test event from the Setup page.", "/setup", []),
        new(HomeProofStates.Simulated, HomeStates.Amber, "Simulated delivery only",
            "The last test event ran in simulated mode and was not verified in Microsoft Sentinel.",
            "Send a real test event from the Setup page once Sentinel credentials are configured.", "/setup", [])
    ];

    private static readonly HashSet<string> KnownIds =
        Entries.Select(entry => entry.ConditionId).ToHashSet(StringComparer.Ordinal);

    public static bool IsKnownCondition(string? conditionId) =>
        !string.IsNullOrWhiteSpace(conditionId) && KnownIds.Contains(conditionId);
}

using System.Globalization;

namespace Bower.Management.Api;

/// <summary>
/// Builds the plain-English fleet view: one state, reason and fix per collector. It reuses the
/// home view's condition catalogue (<see cref="HomeStatus.ConditionIds"/>), so both pages agree
/// on what is wrong, and adds what only a per-machine view needs: a lost sign-in credential, an
/// older Bower version and whether events leave through a relay. Deterministic for a given input
/// and time, and every sentence is fixed Bower text: nothing a collector reports reaches the
/// reason or fix.
/// </summary>
public static class FleetStatus
{
    private const string Approvals = "/approvals";
    private const string Audit = "/audit";
    private const string Enrolment = "/enrolment";
    private const string PrivacyProfiles = "/privacy-profiles";

    private sealed record Entry(string State, string Light, string Reason, FleetFix? Fix);

    // Catalogue order: worst first. It orders the state counts and breaks ties when sorting.
    private static readonly (string Id, string Label)[] Catalogue =
    [
        (FleetStates.NotHeardFrom, "Not heard from recently"),
        (FleetStates.CannotDeliver, "Can't deliver to Sentinel"),
        (FleetStates.NeedsCheck, "Needs a check"),
        (FleetStates.WaitingForApproval, "Waiting for approval"),
        (FleetStates.Paused, "Paused"),
        (FleetStates.OldVersion, "Running old version"),
        (FleetStates.OfflineSite, "Offline site"),
        (FleetStates.BehindRelay, "Behind a relay"),
        (FleetStates.Healthy, "Healthy"),
        (FleetStates.Removed, "Removed")
    ];

    private static readonly Dictionary<string, string> Labels =
        Catalogue.ToDictionary(item => item.Id, item => item.Label, StringComparer.Ordinal);

    public static FleetRecord Evaluate(
        IReadOnlyList<CollectorRecord> collectors,
        IReadOnlySet<string> signedOut,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(collectors);
        ArgumentNullException.ThrowIfNull(signedOut);
        string? newest = collectors
            .Where(item => HomeStatus.Fresh(item, now))
            .Select(item => item.Version)
            .Where(version => ParseVersion(version) is { PreRelease: false })
            .Order(Comparer<string>.Create(CompareVersions))
            .LastOrDefault();

        FleetCollector[] fleet = collectors
            .Select(item => Collector(item, newest, signedOut.Contains(item.Id), now))
            .OrderBy(item => Rank(item.Light))
            .ThenBy(item => Array.FindIndex(Catalogue, entry => entry.Id == item.State))
            .ThenBy(item => item.Site, StringComparer.Ordinal)
            .ThenBy(item => item.MachineName, StringComparer.Ordinal)
            .ThenBy(item => item.Id, StringComparer.Ordinal)
            .ToArray();

        FleetStateCount[] states = Catalogue
            .Select(entry => (entry, members: fleet.Where(item => item.State == entry.Id).ToArray()))
            .Where(item => item.members.Length > 0)
            .Select(item => new FleetStateCount(
                item.entry.Id,
                item.entry.Label,
                item.members.Select(member => member.Light).MinBy(Rank)!,
                item.members.Length))
            .ToArray();
        FleetSiteCount[] sites = fleet
            .GroupBy(item => item.Site, StringComparer.Ordinal)
            .Select(group => new FleetSiteCount(group.Key, group.Count()))
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ToArray();
        return new FleetRecord(now, fleet, states, sites, newest);
    }

    private static FleetCollector Collector(CollectorRecord item, string? newest, bool signedOut, DateTimeOffset now)
    {
        string connectivity = CollectorConnectivity.Evaluate(item, now);
        string? path = item.Outputs.Count == 0
            ? null
            : item.Outputs.Any(output => Is(output.Type, FleetPaths.Relay)) ? FleetPaths.Relay : FleetPaths.Direct;
        bool viaRelay = path == FleetPaths.Relay;

        List<Entry> entries = [];
        if (item.Status == CollectorStatus.Revoked)
        {
            entries.Add(new Entry(
                FleetStates.Removed, FleetLights.None, "Was removed from Bower and can no longer connect.", null));
        }
        else
        {
            entries.AddRange(HomeStatus.ConditionIds(item, now).Select(id => Map(id, viaRelay, signedOut)));
            if (HomeStatus.Fresh(item, now) && Older(item, newest))
            {
                entries.Add(new Entry(
                    FleetStates.OldVersion,
                    HomeStates.Amber,
                    item.HeartbeatSchemaVersion < 2
                        ? "Runs an older Bower version that cannot receive Bower's signed commands."
                        : "Runs an older Bower version than the newest one in your fleet.",
                    new FleetFix("Update Bower on this machine to the latest release.", null)));
            }
        }

        Entry shown = entries.Count > 0
            ? entries[0]
            : viaRelay
                ? new Entry(FleetStates.BehindRelay, HomeStates.Green, "Checking in and configured to send through a relay.", null)
                : new Entry(FleetStates.Healthy, HomeStates.Green, "Checking in with no reported problems.", null);
        return new FleetCollector(
            item.Id,
            item.MachineName,
            item.Environment,
            item.Version,
            shown.State,
            Labels[shown.State],
            shown.Light,
            shown.Reason,
            shown.Fix,
            Math.Max(0, entries.Count - 1),
            connectivity,
            path,
            item.LastSeenAt);
    }

    /// <summary>One home condition as this collector's plain state, reason and fix.</summary>
    private static Entry Map(string condition, bool viaRelay, bool signedOut)
    {
        string connection = viaRelay
            ? "Check the machine's connection to its relay, and the relay's own state on this page."
            : "Check the machine's connection to Azure.";
        FleetFix enrolAgain = new("Create an enrolment token and enrol the machine again.", Enrolment);
        return condition switch
        {
            "offline" when signedOut => new(
                FleetStates.NotHeardFrom, HomeStates.Red,
                "Has not checked in for more than 15 minutes, and its sign-in credential was revoked or has expired.",
                enrolAgain),
            "offline" => new(
                FleetStates.NotHeardFrom, HomeStates.Red, "Has not checked in for more than 15 minutes.",
                new("Check that the machine is switched on and can reach Bower.", null)),
            "stale" when signedOut => new(
                FleetStates.NotHeardFrom, HomeStates.Amber,
                "Has not checked in for a few minutes, and its sign-in credential was revoked or has expired.",
                enrolAgain),
            "stale" => new(
                FleetStates.NotHeardFrom, HomeStates.Amber, "Has not checked in for a few minutes.",
                new("This usually clears by itself. If it lasts, check the machine.", null)),
            "history-changed" => new(
                FleetStates.NeedsCheck, HomeStates.Red, "Reported an event history that changed unexpectedly.",
                new("Treat this as a possible tampering sign: check the machine and the Audit page.", Audit)),
            "not-sending" => new(
                FleetStates.CannotDeliver, HomeStates.Red, "Has not been able to send events for more than 15 minutes.",
                new(connection, null)),
            "send-trouble" => new(
                FleetStates.CannotDeliver, HomeStates.Amber, "Has had trouble sending events.",
                new($"Bower keeps trying. If it lasts more than 15 minutes: {Lower(connection)}", null)),
            "pending" => new(
                FleetStates.WaitingForApproval, HomeStates.Amber, "Has asked to join and is waiting for approval.",
                new("Review the request on the Approvals page.", Approvals)),
            "suspended" => new(
                FleetStates.Paused, HomeStates.Amber, "Access to management is paused. Local collection and delivery may continue.",
                new("Ask a Bower administrator to check why and reinstate it if it is still needed.", null)),
            "set-aside" => new(
                FleetStates.CannotDeliver, HomeStates.Amber, "Has events that could not be sent and were set aside.",
                new("Ask a Bower operator to review the set-aside events on this machine.", null)),
            "backlog" => new(
                FleetStates.CannotDeliver, HomeStates.Amber, "Has events waiting more than 15 minutes to be sent.",
                new(connection, null)),
            "quiet-source" => new(
                FleetStates.NeedsCheck, HomeStates.Amber, "An expected app on this machine has gone quiet.",
                new("Check that the app is running and still sends events to Bower.", null)),
            "policy-not-applied" => new(
                FleetStates.NeedsCheck, HomeStates.Amber, "Has not switched to its assigned event rules yet.",
                new("This usually clears within a few minutes. If it lasts, check the machine can reach Bower.", null)),
            "privacy-not-applied" => new(
                FleetStates.NeedsCheck, HomeStates.Amber, "Has not applied its assigned privacy profile yet.",
                new("Open Privacy profiles to check the rollout.", PrivacyProfiles)),
            _ => throw new InvalidOperationException($"Home condition '{condition}' has no fleet state.")
        };
    }

    /// <summary>
    /// An active collector still on a v1 heartbeat, or a version below the newest the fleet
    /// reports. Versions that are not semantic versions are never called old.
    /// </summary>
    private static bool Older(CollectorRecord item, string? newest) =>
        (item.Status == CollectorStatus.Active && item.HeartbeatSchemaVersion < 2)
        || (newest is not null && ParseVersion(item.Version) is not null && CompareVersions(item.Version, newest) < 0);

    /// <summary>
    /// Major, minor and patch numbers, and whether a pre-release tag follows. Build metadata
    /// (after <c>+</c>) is ignored. Null for anything that is not <c>N.N.N[-tag][+build]</c>.
    /// </summary>
    internal static (int Major, int Minor, int Patch, bool PreRelease)? ParseVersion(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64)
        {
            return null;
        }

        string[] build = value.Split('+');
        if (build.Length > 2 || (build.Length == 2 && !ValidIdentifiers(build[1], false)))
        {
            return null;
        }

        string core = build[0];
        string[] parts = core.Split('-', 2);
        string[] numbers = parts[0].Split('.');
        if (numbers.Length != 3 || (parts.Length == 2 && !ValidIdentifiers(parts[1], true)))
        {
            return null;
        }

        int[] parsed = new int[3];
        for (int index = 0; index < 3; index++)
        {
            if (numbers[index].Length == 0
                || (numbers[index].Length > 1 && numbers[index][0] == '0')
                || !numbers[index].All(char.IsAsciiDigit)
                || !int.TryParse(numbers[index], NumberStyles.None, CultureInfo.InvariantCulture, out parsed[index]))
            {
                return null;
            }
        }

        return (parsed[0], parsed[1], parsed[2], parts.Length == 2);
    }

    private static bool ValidIdentifiers(string value, bool preRelease) =>
        value.Split('.').All(part => part.Length > 0
            && part.All(character => char.IsAsciiLetterOrDigit(character) || character == '-')
            && (!preRelease || part.Length == 1 || part[0] != '0' || !part.All(char.IsAsciiDigit)));

    /// <summary>Numeric core first; a release outranks a pre-release of the same core, and two pre-releases tie.</summary>
    internal static int CompareVersions(string? left, string? right)
    {
        (int Major, int Minor, int Patch, bool PreRelease) a = ParseVersion(left) ?? default;
        (int Major, int Minor, int Patch, bool PreRelease) b = ParseVersion(right) ?? default;
        int result = a.Major.CompareTo(b.Major);
        result = result != 0 ? result : a.Minor.CompareTo(b.Minor);
        result = result != 0 ? result : a.Patch.CompareTo(b.Patch);
        return result != 0 ? result : b.PreRelease.CompareTo(a.PreRelease);
    }

    private static int Rank(string light) => light switch
    {
        HomeStates.Red => 0,
        HomeStates.Amber => 1,
        HomeStates.Green => 2,
        _ => 3
    };

    private static string Lower(string sentence) =>
        sentence.Length == 0 ? sentence : char.ToLowerInvariant(sentence[0]) + sentence[1..];

    private static bool Is(string? value, string expected) =>
        string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
}

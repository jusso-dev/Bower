using Bower.Core;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction;

namespace Bower.Cli.Commands;

/// <summary>
/// <c>bower policy test</c>: runs sample events through the collector's intake (redaction,
/// schema validation, default-deny policy, privacy alerts) offline and prints a
/// metadata-only decision per event. Nothing is queued, sent or written.
/// </summary>
internal static class PolicyCommands
{
    public const int MaximumEventFiles = 1_000;

    private const string FailOnChange = "--fail-on-change";

    private static readonly CollectorIdentity Identity = new("bower-cli", "0.1.0", "policy-test", "policy-test");

    /// <summary>
    /// Loads the bundle exactly as the collector does (policy directory, signed packs,
    /// privacy profile). Exit 1 when the bundle or an event file cannot be read, 3 when
    /// <c>--expect DECISION</c> is given and any event's decision differs.
    /// </summary>
    public static async Task<int> TestAsync(string[] args)
    {
        List<string> files = Positionals(args);
        if (files.Count == 0 || files.Count > MaximumEventFiles)
        {
            Console.Error.WriteLine(
                $"Provide 1-{MaximumEventFiles} event files: bower policy test EVENT.json [EVENT.json ...].");
            return 1;
        }

        string? expect = null;
        if (CliOptions.Get(args, "--expect") is { } expected)
        {
            string name = expected.Replace("-", string.Empty, StringComparison.Ordinal);
            if (!name.All(char.IsAsciiLetter) || !Enum.TryParse(name, true, out Contracts.DecisionAction action))
            {
                Console.Error.WriteLine(
                    "--expect must be a decision: accept, redact-and-accept, reject, quarantine, sample, aggregate or dead-letter.");
                return 1;
            }

            expect = action.ToString().ToLowerInvariant();
        }

        PolicyBundle bundle = PolicyBundle.Load(new PolicyBundleSources
        {
            PolicyDirectory = CliOptions.Get(args, "--policy-directory") ?? Path.Combine("policies", "default"),
            Packs = CliOptions.All(args, "--pack"),
            PackTrustedKeyFiles = CliOptions.All(args, "--trusted-key"),
            PrivacyProfilePath = CliOptions.Get(args, "--privacy-profile"),
            PrivacyHmacKeyFile = CliOptions.Get(args, "--hmac-key-file"),
            PrivacyHmacKeyId = CliOptions.Get(args, "--hmac-key-id") ?? "k1"
        });

        List<(string File, string Json)> events = [];
        foreach (string file in files)
        {
            FileInfo info = new(file);
            if (!info.Exists)
            {
                Console.Error.WriteLine($"Event file not found: {file}");
                return 1;
            }

            if (info.Length > JsonEventRedactor.MaximumPayloadBytes)
            {
                Console.Error.WriteLine($"Event file exceeds {JsonEventRedactor.MaximumPayloadBytes} bytes: {file}");
                return 1;
            }

            events.Add((file, await File.ReadAllTextAsync(file)));
        }

        PolicyTestOutput output = await EvaluateAsync(bundle, events, TimeProvider.System);
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(output, CliJsonContext.Default.PolicyTestOutput));
        return expect is not null && output.Results.Any(result => result.Decision != expect) ? 3 : 0;
    }

    /// <summary>
    /// <c>bower policy diff --baseline DIR --candidate DIR EVENT.json...</c>: population diff.
    /// Runs every sample through both policy directories and lists each event whose decision
    /// or deciding policy changes. Exit 3 with <c>--fail-on-change</c> when any changes.
    /// </summary>
    public static async Task<int> DiffAsync(string[] args)
    {
        List<string> files = DiffFiles(args);
        if (files.Count == 0 || files.Count > MaximumEventFiles)
        {
            Console.Error.WriteLine(
                $"Provide 1-{MaximumEventFiles} event files: bower policy diff --baseline DIR --candidate DIR EVENT.json [EVENT.json ...].");
            return 1;
        }

        List<(string File, string Json)> events = [];
        foreach (string file in files)
        {
            FileInfo info = new(file);
            if (!info.Exists)
            {
                Console.Error.WriteLine($"Event file not found: {file}");
                return 1;
            }

            if (info.Length > JsonEventRedactor.MaximumPayloadBytes)
            {
                Console.Error.WriteLine($"Event file exceeds {JsonEventRedactor.MaximumPayloadBytes} bytes: {file}");
                return 1;
            }

            events.Add((file, await File.ReadAllTextAsync(file)));
        }

        PolicyBundle baseline = PolicyBundle.Load(new PolicyBundleSources
        {
            PolicyDirectory = CliOptions.Required(args, "--baseline")
        });
        PolicyBundle candidate = PolicyBundle.Load(new PolicyBundleSources
        {
            PolicyDirectory = CliOptions.Required(args, "--candidate")
        });
        PolicyDiffOutput output = await ComputeDiffAsync(baseline, candidate, events, TimeProvider.System);
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(output, CliJsonContext.Default.PolicyDiffOutput));
        return output.Changed > 0 && CliOptions.Has(args, FailOnChange) ? 3 : 0;
    }

    /// <summary>Population diff of <paramref name="events"/> between two loaded bundles.</summary>
    public static async Task<PolicyDiffOutput> ComputeDiffAsync(
        PolicyBundle baseline,
        PolicyBundle candidate,
        IReadOnlyList<(string File, string Json)> events,
        TimeProvider clock)
    {
        PolicyTestOutput before = await EvaluateAsync(baseline, events, clock);
        PolicyTestOutput after = await EvaluateAsync(candidate, events, clock);

        List<PolicyDiffChange> changes = [];
        for (int index = 0; index < events.Count; index++)
        {
            PolicyDiffOutcome old = Outcome(before.Results[index]);
            PolicyDiffOutcome updated = Outcome(after.Results[index]);
            if (old != updated)
            {
                changes.Add(new PolicyDiffChange(
                    events[index].File,
                    after.Results[index].EventId ?? before.Results[index].EventId,
                    old,
                    updated));
            }
        }

        return new PolicyDiffOutput(baseline.Hash, candidate.Hash, events.Count, changes.Count, changes);
    }

    /// <summary>Event files of <c>policy diff</c>. <c>--fail-on-change</c> takes no value, so it never swallows a file.</summary>
    internal static List<string> DiffFiles(string[] args) =>
        Positionals([.. args.Where(arg => arg != FailOnChange)]);

    private static PolicyDiffOutcome Outcome(PolicyTestResult result) =>
        new(result.Decision, result.Policy?.PolicyId);

    /// <summary>
    /// Each event runs alone (its own buffer), as its own <c>/v1/events</c> request would, so
    /// one sample never deduplicates against another.
    /// </summary>
    public static async Task<PolicyTestOutput> EvaluateAsync(
        PolicyBundle bundle,
        IReadOnlyList<(string File, string Json)> events,
        TimeProvider clock)
    {
        DeterministicPolicyEvaluator evaluator = new(bundle.Policies);
        // Same redaction path as the collector and serverless hosts.
        PackDetectionRedactor redactor = new(
            new JsonEventRedactor(bundle.Privacy), evaluator,
            bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray());
        List<PolicyTestResult> results = [];
        foreach ((string file, string json) in events)
        {
            RequestEventBuffer buffer = new();
            ProcessingResult result = await new SecurityEventProcessor(redactor, evaluator, buffer, clock)
                .ProcessAsync(json, Identity);
            results.Add(new PolicyTestResult(
                file,
                result.EventId,
                result.Action.ToString().ToLowerInvariant(),
                result.Queued,
                result.PrivacyAlertEventId is not null,
                result.Reasons,
                result.PolicyDecision is null
                    ? null
                    : new PolicyTestPolicy(
                        result.PolicyDecision.PolicyId,
                        result.PolicyDecision.PolicyVersion,
                        result.PolicyDecision.PolicyHash,
                        result.PolicyDecision.Score)));
        }

        return new PolicyTestOutput(bundle.Hash, bundle.Policies.Count, results);
    }

    /// <summary>Every argument that is not an option or an option's value.</summary>
    private static List<string> Positionals(string[] args)
    {
        List<string> values = [];
        for (int index = 0; index < args.Length; index++)
        {
            if (args[index].StartsWith("--", StringComparison.Ordinal))
            {
                index++;
                continue;
            }

            values.Add(args[index]);
        }

        return values;
    }
}

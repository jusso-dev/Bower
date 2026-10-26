using Bower.Abstractions;
using Bower.Core;
using Bower.Detection;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction;
using Bower.Redaction.Privacy;

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
    /// Any <see cref="BundleOptions"/> option (or <c>--at</c>) selects the bundle comparison:
    /// each side is a full trusted bundle (directory, signed packs, privacy profile) and every
    /// sample runs at one fixed time. Both bundles load, and every pack's signature is checked,
    /// before any sample is evaluated; a load failure is exit 1 with nothing printed.
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

        if (IsBundleComparison(args))
        {
            DateTimeOffset at = ParseAt(args) ?? TimeProvider.System.GetUtcNow();
            PolicyBundle baselineBundle = PolicyBundle.Load(BundleSources(args, "baseline"));
            PolicyBundle candidateBundle = PolicyBundle.Load(BundleSources(args, "candidate"));
            PolicyBundleDiffOutput compared = await ComputeBundleDiffAsync(baselineBundle, candidateBundle, events, at);
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(compared, CliJsonContext.Default.PolicyBundleDiffOutput));
            return compared.Changed > 0 && CliOptions.Has(args, FailOnChange) ? 3 : 0;
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

    /// <summary>Per-side suffixes of the <c>policy test</c> bundle options (<c>--baseline-pack</c>, ...).</summary>
    internal static readonly string[] BundleOptions = ["pack", "trusted-key", "privacy-profile", "hmac-key-file", "hmac-key-id"];

    /// <summary>Stateful behaviour a single offline request per sample cannot show.</summary>
    internal static readonly string[] NotExercisedOffline =
    [
        "suppression-windows",
        "source-silence",
        "cross-event-deduplication",
        "queue-capacity-and-backpressure",
        "delivery-and-destination-validation",
        "pack-parsers",
        "management-privacy-assignment"
    ];

    internal static bool IsBundleComparison(string[] args) =>
        CliOptions.Has(args, "--at")
        || BundleOptions.Any(option =>
            CliOptions.Has(args, $"--baseline-{option}") || CliOptions.Has(args, $"--candidate-{option}"));

    /// <summary>
    /// <c>--at</c> as UTC (<see cref="CliOptions.Timestamp"/>); null when absent. Exit 1 (before
    /// loading) when given without a strict ISO 8601 value.
    /// </summary>
    internal static DateTimeOffset? ParseAt(string[] args) =>
        CliOptions.Has(args, "--at")
            ? CliOptions.Timestamp(CliOptions.Get(args, "--at") ?? string.Empty, "--at")
            : null;

    /// <summary>
    /// One side of the bundle comparison, read like <c>policy test</c> reads its bundle:
    /// <c>--{side} DIR</c>, <c>--{side}-pack FILE</c> (repeatable) with <c>--{side}-trusted-key</c>,
    /// <c>--{side}-privacy-profile</c>, <c>--{side}-hmac-key-file</c> and <c>--{side}-hmac-key-id</c>.
    /// </summary>
    internal static PolicyBundleSources BundleSources(string[] args, string side)
    {
        string? directory = CliOptions.Get(args, $"--{side}");
        IReadOnlyList<string> packs = CliOptions.All(args, $"--{side}-pack");
        if (directory is null && packs.Count == 0)
        {
            throw new ArgumentException($"--{side} or --{side}-pack is required.");
        }

        // PolicyBundle.Load skips a missing directory when packs are given; a directory the
        // operator names must exist, so a typo never silently drops that side's policies.
        if (directory is not null && !Directory.Exists(directory))
        {
            throw new ArgumentException($"Policy directory does not exist: {directory}");
        }

        return new PolicyBundleSources
        {
            // No directory: the bundle is the packs alone.
            PolicyDirectory = directory ?? string.Empty,
            Packs = packs,
            PackTrustedKeyFiles = CliOptions.All(args, $"--{side}-trusted-key"),
            PrivacyProfilePath = CliOptions.Get(args, $"--{side}-privacy-profile"),
            PrivacyHmacKeyFile = CliOptions.Get(args, $"--{side}-hmac-key-file"),
            PrivacyHmacKeyId = CliOptions.Get(args, $"--{side}-hmac-key-id") ?? "k1"
        };
    }

    /// <summary>
    /// Bundle comparison of <paramref name="events"/> at one fixed time: lists each sample whose
    /// decision, deciding policy, acceptance, failure stage or reasons, privacy actions or
    /// findings, removed or masked counts, privacy alert or detection rules change.
    /// </summary>
    public static async Task<PolicyBundleDiffOutput> ComputeBundleDiffAsync(
        PolicyBundle baseline,
        PolicyBundle candidate,
        IReadOnlyList<(string File, string Json)> events,
        DateTimeOffset at)
    {
        TimeProvider clock = new FixedClock(at);
        IReadOnlyList<(string? EventId, PolicyBundleOutcome Outcome)> before = await ProcessEachAsync(baseline, events, clock, Reduce);
        IReadOnlyList<(string? EventId, PolicyBundleOutcome Outcome)> after = await ProcessEachAsync(candidate, events, clock, Reduce);

        List<PolicyBundleDiffChange> changes = [];
        for (int index = 0; index < events.Count; index++)
        {
            PolicyBundleOutcome old = before[index].Outcome;
            PolicyBundleOutcome updated = after[index].Outcome;
            List<string> changed = ChangedFields(old, updated);
            if (changed.Count > 0)
            {
                changes.Add(new PolicyBundleDiffChange(
                    events[index].File,
                    after[index].EventId ?? before[index].EventId,
                    old,
                    updated,
                    changed));
            }
        }

        return new PolicyBundleDiffOutput(
            baseline.Hash, candidate.Hash, events.Count, changes.Count, changes, at,
            Provenance(baseline), Provenance(candidate), NotExercisedOffline);

        // Each sample is reduced to metadata as soon as it is processed; no redacted payload is kept.
        static (string?, PolicyBundleOutcome) Reduce(
            ProcessingResult result, RedactionResult? redaction, IReadOnlyList<AppliedFinding> findings) =>
            (result.EventId, BundleOutcome(result, redaction, findings));
    }

    private static PolicyBundleOutcome BundleOutcome(
        ProcessingResult result,
        RedactionResult? redaction,
        IReadOnlyList<AppliedFinding> findings)
    {
        bool accepted = result.Action is Contracts.DecisionAction.Accept or Contracts.DecisionAction.RedactAndAccept;
        return new PolicyBundleOutcome(
            result.Action.ToString().ToLowerInvariant(),
            result.PolicyDecision?.PolicyId,
            accepted,
            accepted ? null : result.Stage.ToString().ToLowerInvariant(),
            accepted ? [] : result.Reasons,
            (redaction?.PrivacyActions ?? new Dictionary<string, string>())
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new PolicyBundlePrivacyAction(pair.Key, pair.Value))
                .ToArray(),
            findings
                .Select(finding => new PolicyBundlePrivacyFinding(
                    finding.SubKind is null ? finding.DetectorId : $"{finding.DetectorId}:{finding.SubKind}",
                    finding.Path,
                    PolicyApplicator.ActionLabel(finding.Action)))
                .Distinct()
                .OrderBy(finding => finding.Detector, StringComparer.Ordinal)
                .ThenBy(finding => finding.Path, StringComparer.Ordinal)
                .ThenBy(finding => finding.Action, StringComparer.Ordinal)
                .ToArray(),
            redaction?.RemovedPaths.Count ?? 0,
            redaction?.MaskedPaths.Count ?? 0,
            result.PrivacyAlertEventId is not null,
            // Detection evidence only travels with an accepted event.
            accepted ? Detections(redaction) : []);
    }

    /// <summary>Rule id, version and hash of the evidence the pack detection redactor attached (never matched values).</summary>
    private static PolicyBundleDetection[] Detections(RedactionResult? redaction)
    {
        if (redaction is not { Succeeded: true, RedactedJson: { } json })
        {
            return [];
        }

        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(json);
        static string Text(System.Text.Json.JsonElement item, string name) =>
            item.TryGetProperty(name, out System.Text.Json.JsonElement value) ? value.GetString() ?? string.Empty : string.Empty;
        return document.RootElement.TryGetProperty("attributes", out System.Text.Json.JsonElement attributes)
            && attributes.ValueKind == System.Text.Json.JsonValueKind.Object
            && attributes.TryGetProperty(PackDetectionRedactor.EvidenceAttribute, out System.Text.Json.JsonElement evidence)
            && evidence.ValueKind == System.Text.Json.JsonValueKind.Array
            ? evidence.EnumerateArray()
                .Select(item => new PolicyBundleDetection(Text(item, "ruleId"), Text(item, "ruleVersion"), Text(item, "ruleHash")))
                .ToArray()
            : [];
    }

    private static List<string> ChangedFields(PolicyBundleOutcome old, PolicyBundleOutcome updated)
    {
        List<string> changed = [];
        void Check(string name, bool same)
        {
            if (!same)
            {
                changed.Add(name);
            }
        }

        Check("decision", old.Decision == updated.Decision);
        Check("policyId", old.PolicyId == updated.PolicyId);
        Check("accepted", old.Accepted == updated.Accepted);
        Check("failureStage", old.FailureStage == updated.FailureStage);
        Check("failureReasons", old.FailureReasons.SequenceEqual(updated.FailureReasons, StringComparer.Ordinal));
        Check("privacyActions", old.PrivacyActions.SequenceEqual(updated.PrivacyActions));
        Check("privacyFindings", old.PrivacyFindings.SequenceEqual(updated.PrivacyFindings));
        Check("removedCount", old.RemovedCount == updated.RemovedCount);
        Check("maskedCount", old.MaskedCount == updated.MaskedCount);
        Check("privacyAlert", old.PrivacyAlert == updated.PrivacyAlert);
        Check("detections", old.Detections.SequenceEqual(updated.Detections));
        return changed;
    }

    private static PolicyBundleProvenance Provenance(PolicyBundle bundle) =>
        new(
            bundle.Hash,
            bundle.Policies.Count,
            [.. bundle.Packs.Select(pack => new PolicyBundlePack(pack.Id, pack.Version, pack.PackHash))],
            bundle.PrivacyProfile is null
                ? null
                : new PolicyBundlePrivacyProfile(bundle.PrivacyProfile, bundle.PrivacyProfileVersion, bundle.PrivacyProfileHash),
            bundle.LoadedPacks.Sum(pack => pack.Detections.Count));

    /// <summary>
    /// Each event runs alone (its own buffer), as its own <c>/v1/events</c> request would, so
    /// one sample never deduplicates against another.
    /// </summary>
    public static async Task<PolicyTestOutput> EvaluateAsync(
        PolicyBundle bundle,
        IReadOnlyList<(string File, string Json)> events,
        TimeProvider clock)
    {
        IReadOnlyList<ProcessingResult> processed = await ProcessEachAsync(bundle, events, clock, (result, _, _) => result);
        List<PolicyTestResult> results = [];
        for (int index = 0; index < events.Count; index++)
        {
            string file = events[index].File;
            ProcessingResult result = processed[index];
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

    /// <summary>
    /// Runs each event through the collector's intake alone and reduces it with
    /// <paramref name="reduce"/> straight away: the processing result, the one redaction the
    /// processor ran (null when the redactor threw) and the privacy engine's findings.
    /// </summary>
    private static async Task<IReadOnlyList<T>> ProcessEachAsync<T>(
        PolicyBundle bundle,
        IReadOnlyList<(string File, string Json)> events,
        TimeProvider clock,
        Func<ProcessingResult, RedactionResult?, IReadOnlyList<AppliedFinding>, T> reduce)
    {
        DeterministicPolicyEvaluator evaluator = new(bundle.Policies);
        // Same redaction path as the collector and serverless hosts: JsonEventRedactor is
        // PrivacyEngine.RedactJson(json).ToRedactionResult(), under the pack detection redactor.
        PrivacyEngine privacy = new(bundle.Privacy);
        DetectionRule[] rules = bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray();
        List<T> results = [];
        foreach ((_, string json) in events)
        {
            RequestEventBuffer buffer = new();
            FindingsRedactor findings = new(privacy);
            RecordingRedactor recording = new(new PackDetectionRedactor(findings, evaluator, rules));
            ProcessingResult result = await new SecurityEventProcessor(recording, evaluator, buffer, clock)
                .ProcessAsync(json, Identity);
            results.Add(reduce(result, recording.Result, findings.Findings));
        }

        return results;
    }

    /// <summary>Observes the redaction the processor runs; never alters it.</summary>
    private sealed class RecordingRedactor(IEventRedactor inner) : IEventRedactor
    {
        public RedactionResult? Result { get; private set; }

        public RedactionResult Redact(string json) => Result = inner.Redact(json);
    }

    /// <summary><see cref="JsonEventRedactor"/> that also keeps the per-finding metadata (never values).</summary>
    private sealed class FindingsRedactor(PrivacyEngine engine) : IEventRedactor
    {
        public IReadOnlyList<AppliedFinding> Findings { get; private set; } = [];

        public RedactionResult Redact(string json)
        {
            PrivacyScanResult scan = engine.RedactJson(json);
            Findings = scan.Findings;
            return scan.ToRedactionResult();
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
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

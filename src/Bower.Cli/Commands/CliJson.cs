using System.Text.Json.Serialization;
using Bower.Abstractions;
using Bower.Evidence;
using Bower.Packs;
using Bower.Persistence;
using Bower.Pipeline;

namespace Bower.Cli.Commands;

// CLI output documents. Named records replace the former anonymous types so serialization
// is source generated (Native AOT). The JSON names and declaration order reproduce the
// former output exactly: anonymous members named after a source property kept that
// property's PascalCase name, members written in camelCase kept camelCase.

internal sealed record PolicyValidationOutput(
    [property: JsonPropertyName("valid")] bool Valid,
    [property: JsonPropertyName("policyCount")] int PolicyCount,
    [property: JsonPropertyName("policies")] IReadOnlyList<PolicyValidationItem> Policies);

internal sealed record PolicyValidationItem(string Id, string Version, string Hash);

internal sealed record PipelineValidationOutput(
    [property: JsonPropertyName("valid")] bool Valid,
    string Id,
    string Name,
    string Version,
    [property: JsonPropertyName("order")] IReadOnlyList<string> Order,
    [property: JsonPropertyName("estimate")] PipelinePerformanceEstimate? Estimate,
    [property: JsonPropertyName("issues")] IReadOnlyList<PipelineValidationIssue> Issues);

internal sealed record InitOutput(
    [property: JsonPropertyName("initialized")] bool Initialized,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("framework")] string Framework,
    [property: JsonPropertyName("note")] string Note);

internal sealed record PackInspectOutput(
    string Id,
    string Version,
    string Name,
    string Owner,
    [property: JsonPropertyName("signedBy")] string SignedBy,
    string PackHash,
    [property: JsonPropertyName("policies")] IReadOnlyList<PackPolicyEntry> Policies,
    [property: JsonPropertyName("files")] IReadOnlyList<PackInspectFile> Files,
    [property: JsonPropertyName("detections")] int Detections,
    [property: JsonPropertyName("parsers")] int Parsers,
    [property: JsonPropertyName("samples")] int Samples,
    [property: JsonPropertyName("privacyProfile")] bool PrivacyProfile,
    [property: JsonPropertyName("dcrTemplate")] bool DcrTemplate);

internal sealed record PackInspectFile(string Path, string Role, long Bytes);

internal sealed record PackTestReportOutput(
    [property: JsonPropertyName("pack")] string Pack,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("parser")] string? Parser,
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("passed")] int Passed,
    [property: JsonPropertyName("failed")] int Failed,
    [property: JsonPropertyName("samples")] IReadOnlyList<PackTestReportSample> Samples);

internal sealed record PackTestReportSample(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("passed")] bool Passed,
    [property: JsonPropertyName("expected")] string Expected,
    [property: JsonPropertyName("actual")] string Actual,
    [property: JsonPropertyName("problems")] IReadOnlyList<string> Problems);

/// <summary><c>bower privacy validate</c> output: metadata only, never patterns or samples.</summary>
internal sealed record PrivacyValidationOutput(
    [property: JsonPropertyName("valid")] bool Valid,
    [property: JsonPropertyName("profileId")] string? ProfileId,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("hash")] string Hash,
    [property: JsonPropertyName("customDetectors")] IReadOnlyList<PrivacyValidationDetector> CustomDetectors,
    [property: JsonPropertyName("secretFieldNames")] int SecretFieldNames,
    [property: JsonPropertyName("testsPassed")] int TestsPassed,
    [property: JsonPropertyName("sample"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] PrivacyValidationSample? Sample);

internal sealed record PrivacyValidationDetector(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("action")] string Action);

/// <summary>The sample after redaction (never the original).</summary>
internal sealed record PrivacyValidationSample(
    [property: JsonPropertyName("succeeded")] bool Succeeded,
    [property: JsonPropertyName("failureCode")] string? FailureCode,
    [property: JsonPropertyName("redacted")] string? Redacted);

/// <summary><c>bower policy test</c> output: decisions and reasons only, never event content.</summary>
internal sealed record PolicyTestOutput(
    [property: JsonPropertyName("bundleHash")] string BundleHash,
    [property: JsonPropertyName("policyCount")] int PolicyCount,
    [property: JsonPropertyName("results")] IReadOnlyList<PolicyTestResult> Results);

internal sealed record PolicyTestResult(
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("wouldQueue")] bool WouldQueue,
    [property: JsonPropertyName("privacyAlert")] bool PrivacyAlert,
    [property: JsonPropertyName("reasons")] IReadOnlyList<string> Reasons,
    [property: JsonPropertyName("policy")] PolicyTestPolicy? Policy);

internal sealed record PolicyTestPolicy(
    [property: JsonPropertyName("policyId")] string PolicyId,
    [property: JsonPropertyName("policyVersion")] string PolicyVersion,
    [property: JsonPropertyName("policyHash")] string PolicyHash,
    [property: JsonPropertyName("score")] int Score);

/// <summary><c>bower policy diff</c> output: decisions only, never event content.</summary>
internal sealed record PolicyDiffOutput(
    [property: JsonPropertyName("baselineBundleHash")] string BaselineBundleHash,
    [property: JsonPropertyName("candidateBundleHash")] string CandidateBundleHash,
    [property: JsonPropertyName("events")] int Events,
    [property: JsonPropertyName("changed")] int Changed,
    [property: JsonPropertyName("changes")] IReadOnlyList<PolicyDiffChange> Changes);

internal sealed record PolicyDiffChange(
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("baseline")] PolicyDiffOutcome Baseline,
    [property: JsonPropertyName("candidate")] PolicyDiffOutcome Candidate);

internal sealed record PolicyDiffOutcome(
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("policyId")] string? PolicyId);

/// <summary>
/// <c>bower policy diff</c> bundle comparison: the directory-mode fields first (same names),
/// then provenance and offline limits. Metadata only: no event content or matched values.
/// </summary>
internal sealed record PolicyBundleDiffOutput(
    [property: JsonPropertyName("baselineBundleHash")] string BaselineBundleHash,
    [property: JsonPropertyName("candidateBundleHash")] string CandidateBundleHash,
    [property: JsonPropertyName("events")] int Events,
    [property: JsonPropertyName("changed")] int Changed,
    [property: JsonPropertyName("changes")] IReadOnlyList<PolicyBundleDiffChange> Changes,
    [property: JsonPropertyName("evaluatedAt")] DateTimeOffset EvaluatedAt,
    [property: JsonPropertyName("baselineBundle")] PolicyBundleProvenance BaselineBundle,
    [property: JsonPropertyName("candidateBundle")] PolicyBundleProvenance CandidateBundle,
    [property: JsonPropertyName("notExercisedOffline")] IReadOnlyList<string> NotExercisedOffline);

internal sealed record PolicyBundleDiffChange(
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("baseline")] PolicyBundleOutcome Baseline,
    [property: JsonPropertyName("candidate")] PolicyBundleOutcome Candidate,
    [property: JsonPropertyName("changedFields")] IReadOnlyList<string> ChangedFields);

/// <summary>One fixture's intake outcome under one bundle. Detector and rule ids only.</summary>
internal sealed record PolicyBundleOutcome(
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("policyId")] string? PolicyId,
    [property: JsonPropertyName("accepted")] bool Accepted,
    [property: JsonPropertyName("failureStage")] string? FailureStage,
    [property: JsonPropertyName("failureReasons")] IReadOnlyList<string> FailureReasons,
    [property: JsonPropertyName("privacyActions")] IReadOnlyList<PolicyBundlePrivacyAction> PrivacyActions,
    [property: JsonPropertyName("privacyFindings")] IReadOnlyList<PolicyBundlePrivacyFinding> PrivacyFindings,
    [property: JsonPropertyName("removedCount")] int RemovedCount,
    [property: JsonPropertyName("maskedCount")] int MaskedCount,
    [property: JsonPropertyName("privacyAlert")] bool PrivacyAlert,
    [property: JsonPropertyName("detections")] IReadOnlyList<PolicyBundleDetection> Detections);

/// <summary>First action per detector, as the privacy metadata on the event records it.</summary>
internal sealed record PolicyBundlePrivacyAction(
    [property: JsonPropertyName("detector")] string Detector,
    [property: JsonPropertyName("action")] string Action);

/// <summary>One privacy finding: detector (with sub-kind), field path and action label. Never the value.</summary>
internal sealed record PolicyBundlePrivacyFinding(
    [property: JsonPropertyName("detector")] string Detector,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("action")] string Action);

internal sealed record PolicyBundleDetection(
    [property: JsonPropertyName("ruleId")] string RuleId,
    [property: JsonPropertyName("ruleVersion")] string RuleVersion,
    [property: JsonPropertyName("ruleHash")] string RuleHash);

internal sealed record PolicyBundleProvenance(
    [property: JsonPropertyName("bundleHash")] string BundleHash,
    [property: JsonPropertyName("policyCount")] int PolicyCount,
    [property: JsonPropertyName("packs")] IReadOnlyList<PolicyBundlePack> Packs,
    [property: JsonPropertyName("privacyProfile")] PolicyBundlePrivacyProfile? PrivacyProfile,
    [property: JsonPropertyName("detectionRules")] int DetectionRules);

internal sealed record PolicyBundlePack(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("packHash")] string PackHash);

internal sealed record PolicyBundlePrivacyProfile(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("hash")] string? Hash);

/// <summary><c>bower archive create</c> output.</summary>
internal sealed record ArchiveCreateOutput(
    [property: JsonPropertyName("segments")] int Segments,
    [property: JsonPropertyName("events")] long Events,
    [property: JsonPropertyName("headSequence")] long HeadSequence,
    [property: JsonPropertyName("headHash")] string? HeadHash);

/// <summary><c>bower archive verify</c> output (also printed when replay refuses a broken archive).</summary>
internal sealed record ArchiveVerifyOutput(
    [property: JsonPropertyName("intact")] bool Intact,
    [property: JsonPropertyName("segments")] int Segments,
    [property: JsonPropertyName("verifiedEvents")] long VerifiedEvents,
    [property: JsonPropertyName("firstSequence")] long FirstSequence,
    [property: JsonPropertyName("headSequence")] long HeadSequence,
    [property: JsonPropertyName("headHash")] string? HeadHash,
    [property: JsonPropertyName("anchorVerified")] bool AnchorVerified,
    [property: JsonPropertyName("breakSegment")] string? BreakSegment,
    [property: JsonPropertyName("breakReason")] string? BreakReason)
{
    public static ArchiveVerifyOutput From(Bower.Persistence.ArchiveVerification value) =>
        new(value.Intact, value.Segments, value.VerifiedEvents, value.FirstSequence, value.HeadSequence,
            value.HeadHash, value.AnchorVerified, value.BreakSegment, value.BreakReason);
}

/// <summary><c>bower archive replay</c> output: counts per collector response, never payloads.</summary>
internal sealed record ArchiveReplayOutput(
    [property: JsonPropertyName("selected")] long Selected,
    [property: JsonPropertyName("dryRun")] bool DryRun,
    [property: JsonPropertyName("responses")] IReadOnlyDictionary<string, long> Responses);

internal sealed record SourcesCheckOutput(
    [property: JsonPropertyName("healthy")] bool Healthy,
    [property: JsonPropertyName("sources")] IReadOnlyList<SourceCheckItem> Sources);

internal sealed record SourceCheckItem(
    [property: JsonPropertyName("application")] string Application,
    [property: JsonPropertyName("environment")] string Environment,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("lastSeenAt")] DateTimeOffset? LastSeenAt,
    [property: JsonPropertyName("silentSeconds")] long? SilentSeconds,
    [property: JsonPropertyName("allowedSilenceSeconds")] long AllowedSilenceSeconds);

/// <summary>
/// Source-generated metadata for CLI output: System.Text.Json default options with
/// indentation, as the former <c>new JsonSerializerOptions { WriteIndented = true }</c>.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(PolicyValidationOutput))]
[JsonSerializable(typeof(PipelineValidationOutput))]
[JsonSerializable(typeof(InitOutput))]
[JsonSerializable(typeof(PackInspectOutput))]
[JsonSerializable(typeof(PackTestReportOutput))]
[JsonSerializable(typeof(PrivacyValidationOutput))]
[JsonSerializable(typeof(PolicyTestOutput))]
[JsonSerializable(typeof(PolicyDiffOutput))]
[JsonSerializable(typeof(PolicyBundleDiffOutput))]
[JsonSerializable(typeof(ArchiveReplayOutput))]
[JsonSerializable(typeof(SourcesCheckOutput))]
[JsonSerializable(typeof(ArchiveCreateOutput))]
[JsonSerializable(typeof(ArchiveVerifyOutput))]
[JsonSerializable(typeof(QueueSnapshot))]
[JsonSerializable(typeof(QueueBackupManifest))]
[JsonSerializable(typeof(IReadOnlyList<DeadLetterRecord>))]
[JsonSerializable(typeof(SignedEvidence))]
[JsonSerializable(typeof(List<DoctorCommand.Check>))]
internal sealed partial class CliJsonContext : JsonSerializerContext;

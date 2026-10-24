using System.Text.Json.Serialization;
using Bower.Abstractions;
using Bower.Evidence;
using Bower.Packs;
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

/// <summary>
/// Source-generated metadata for CLI output: System.Text.Json default options with
/// indentation, as the former <c>new JsonSerializerOptions { WriteIndented = true }</c>.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(PolicyValidationOutput))]
[JsonSerializable(typeof(PipelineValidationOutput))]
[JsonSerializable(typeof(InitOutput))]
[JsonSerializable(typeof(PackInspectOutput))]
[JsonSerializable(typeof(PrivacyValidationOutput))]
[JsonSerializable(typeof(PolicyTestOutput))]
[JsonSerializable(typeof(QueueSnapshot))]
[JsonSerializable(typeof(IReadOnlyList<DeadLetterRecord>))]
[JsonSerializable(typeof(SignedEvidence))]
[JsonSerializable(typeof(List<DoctorCommand.Check>))]
internal sealed partial class CliJsonContext : JsonSerializerContext;

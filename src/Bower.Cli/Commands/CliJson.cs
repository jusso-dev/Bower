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

/// <summary>
/// Source-generated metadata for CLI output: System.Text.Json default options with
/// indentation, as the former <c>new JsonSerializerOptions { WriteIndented = true }</c>.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(PolicyValidationOutput))]
[JsonSerializable(typeof(PipelineValidationOutput))]
[JsonSerializable(typeof(InitOutput))]
[JsonSerializable(typeof(PackInspectOutput))]
[JsonSerializable(typeof(QueueSnapshot))]
[JsonSerializable(typeof(IReadOnlyList<DeadLetterRecord>))]
[JsonSerializable(typeof(SignedEvidence))]
[JsonSerializable(typeof(List<DoctorCommand.Check>))]
internal sealed partial class CliJsonContext : JsonSerializerContext;

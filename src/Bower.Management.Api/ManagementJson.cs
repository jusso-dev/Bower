using System.Text.Json;
using System.Text.Json.Serialization;
using Bower.Jobs;
using Bower.Pipeline;

namespace Bower.Management.Api;

/// <summary>Error body (<c>{"error": "..."}</c>).</summary>
public sealed record ErrorResponse(string Error);

/// <summary>Liveness body.</summary>
public sealed record HealthResponse(string Status);

/// <summary>Pipeline validation result with its performance estimate (null for a cyclic graph or duplicate node ids).</summary>
public sealed record PipelineValidationResponse(
    bool IsValid,
    IReadOnlyList<PipelineValidationIssue> Issues,
    IReadOnlyList<string> TopologicalOrder,
    PipelinePerformanceEstimate? Estimate);

/// <summary>
/// Source-generated metadata for every management API body (ASP.NET Core Web defaults).
/// The API resolves JSON metadata only from here, so a missing type fails in tests rather
/// than at runtime in the Native AOT binary. Collection runtime types are listed because
/// results are written by their runtime type.
/// </summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(CurrentAccess))]
[JsonSerializable(typeof(OverviewRecord))]
[JsonSerializable(typeof(CollectorRecord))]
[JsonSerializable(typeof(IReadOnlyList<CollectorRecord>))]
[JsonSerializable(typeof(List<CollectorRecord>))]
[JsonSerializable(typeof(CollectorRegistration))]
[JsonSerializable(typeof(CollectorHeartbeat))]
[JsonSerializable(typeof(HeartbeatResponse))]
[JsonSerializable(typeof(CollectorCommandRequest))]
[JsonSerializable(typeof(CollectorCommandRecord))]
[JsonSerializable(typeof(IReadOnlyList<CollectorCommandRecord>))]
[JsonSerializable(typeof(List<CollectorCommandRecord>))]
[JsonSerializable(typeof(TelemetryPipeline))]
[JsonSerializable(typeof(TelemetryPipeline[]))]
[JsonSerializable(typeof(PipelineValidationResponse))]
[JsonSerializable(typeof(CustomLogInput))]
[JsonSerializable(typeof(CustomLogPreviewRequest))]
[JsonSerializable(typeof(CustomLogGenerationResult))]
[JsonSerializable(typeof(CustomLogPreviewResult))]
[JsonSerializable(typeof(ApprovalRequest))]
[JsonSerializable(typeof(ApprovalRecord))]
[JsonSerializable(typeof(IReadOnlyList<ApprovalRecord>))]
[JsonSerializable(typeof(List<ApprovalRecord>))]
[JsonSerializable(typeof(DesiredPolicyRequest))]
[JsonSerializable(typeof(IReadOnlyList<AuditRecord>))]
[JsonSerializable(typeof(List<AuditRecord>))]
[JsonSerializable(typeof(IReadOnlyList<BackgroundJobStatus>))]
[JsonSerializable(typeof(BackgroundJobStatus[]))]
[JsonSerializable(typeof(PrivacyProfileContentRequest))]
[JsonSerializable(typeof(PrivacyProfilePreviewRequest))]
[JsonSerializable(typeof(PrivacyProfileSubmission))]
[JsonSerializable(typeof(PrivacyProfileAssignmentRequest))]
[JsonSerializable(typeof(PrivacyProfileValidation))]
[JsonSerializable(typeof(PrivacyProfilePreview))]
[JsonSerializable(typeof(PrivacyProfileVersionDetail))]
[JsonSerializable(typeof(IReadOnlyList<PrivacyProfileVersionSummary>))]
[JsonSerializable(typeof(List<PrivacyProfileVersionSummary>))]
[JsonSerializable(typeof(IReadOnlyList<PrivacyProfileAssignment>))]
[JsonSerializable(typeof(List<PrivacyProfileAssignment>))]
[JsonSerializable(typeof(ManagedPrivacyProfile))]
[JsonSerializable(typeof(SetupStatus))]
[JsonSerializable(typeof(SetupDestinationRequest))]
[JsonSerializable(typeof(SetupDestination))]
[JsonSerializable(typeof(SetupProbeRequest))]
[JsonSerializable(typeof(SetupProbeChoice))]
[JsonSerializable(typeof(SetupCanaryRun))]
[JsonSerializable(typeof(SetupCheckResult))]
[JsonSerializable(typeof(EnrolmentTokenRequest))]
[JsonSerializable(typeof(EnrolmentTokenRecord))]
[JsonSerializable(typeof(IReadOnlyList<EnrolmentTokenRecord>))]
[JsonSerializable(typeof(List<EnrolmentTokenRecord>))]
[JsonSerializable(typeof(IssuedEnrolmentToken))]
[JsonSerializable(typeof(CollectorEnrolmentRequest))]
[JsonSerializable(typeof(CollectorCredentialRotationRequest))]
[JsonSerializable(typeof(IssuedCollectorCredential))]
[JsonSerializable(typeof(CollectorCredentialRecord))]
[JsonSerializable(typeof(IReadOnlyList<CollectorCredentialRecord>))]
[JsonSerializable(typeof(List<CollectorCredentialRecord>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails))]
[JsonSerializable(typeof(HttpValidationProblemDetails))]
public sealed partial class ManagementJsonContext : JsonSerializerContext;

/// <summary>Signed evidence bundles as <c>bower evidence run</c> writes them (default options, indented).</summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(Bower.Evidence.SignedEvidence))]
internal sealed partial class SetupEvidenceJsonContext : JsonSerializerContext;

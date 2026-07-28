using System.Text.Json;

namespace Bower.Ocsf;

public enum OcsfSourceKind
{
    BowerEnvelope,
    WindowsEvent,
    Sysmon,
    LinuxSyslog,
    CloudTrail,
    GuardDuty,
    SecurityHub,
    CrowdStrike,
    DefenderXdr,
    PaloAlto,
    Fortinet,
    MicrosoftSentinel
}

public sealed record OcsfEvent
{
    public required int ClassUid { get; init; }

    public required string ClassName { get; init; }

    public required int CategoryUid { get; init; }

    public required string CategoryName { get; init; }

    public required int ActivityId { get; init; }

    public required string ActivityName { get; init; }

    public required int SeverityId { get; init; }

    public required string Severity { get; init; }

    public required DateTimeOffset Time { get; init; }

    public required string TypeName { get; init; }

    public string? Message { get; init; }

    public string? Status { get; init; }

    public string? SourceId { get; init; }

    public string? MetadataProductName { get; init; }

    public string? MetadataProductVendor { get; init; }

    public string? MetadataVersion { get; init; }

    public string? ActorUserName { get; init; }

    public string? SrcEndpointIp { get; init; }

    public string? TargetName { get; init; }

    public IReadOnlyDictionary<string, string>? Unmapped { get; init; }

    public IReadOnlyDictionary<string, JsonElement>? Extensions { get; init; }
}

public sealed record OcsfNormalisationResult(
    bool Succeeded,
    OcsfEvent? Event,
    string MappingVersion,
    string SourceKind,
    IReadOnlyList<string> Warnings,
    string? FailureCode);

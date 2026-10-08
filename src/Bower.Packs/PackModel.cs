using System.Text.Json.Serialization;

namespace Bower.Packs;

/// <summary>pack.yaml: the author-facing description of a pack's source directory.</summary>
public sealed record PackSource
{
    public required string ApiVersion { get; init; }

    public required string Kind { get; init; }

    public required PackSourceMetadata Metadata { get; init; }

    public List<string> Policies { get; init; } = [];

    public string? PrivacyProfile { get; init; }

    public List<string> Parsers { get; init; } = [];

    public List<string> Detections { get; init; } = [];

    public List<string> Samples { get; init; } = [];

    /// <summary>Include a generated DCR/table ARM template.</summary>
    public bool Dcr { get; init; }
}

public sealed record PackSourceMetadata
{
    public required string Id { get; init; }

    public required string Version { get; init; }

    public required string Name { get; init; }

    public string? Description { get; init; }

    public required string Owner { get; init; }
}

public static class PackRoles
{
    public const string Policy = "policy";
    public const string PrivacyProfile = "privacy-profile";
    public const string Parser = "parser";
    public const string Detection = "detection";
    public const string Sample = "sample";
    public const string Dcr = "dcr";
}

public sealed record PackFile(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("bytes")] long Bytes);

public sealed record PackPolicyEntry(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("hash")] string Hash,
    [property: JsonPropertyName("eventTypes")] IReadOnlyList<string> EventTypes);

/// <summary>The signed manifest. Every file in the archive is listed with its hash.</summary>
public sealed record PackManifest(
    [property: JsonPropertyName("apiVersion")] string ApiVersion,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("owner")] string Owner,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("files")] IReadOnlyList<PackFile> Files,
    [property: JsonPropertyName("policies")] IReadOnlyList<PackPolicyEntry> Policies,
    [property: JsonPropertyName("packHash")] string PackHash)
{
    public const string CurrentKind = "PackManifest";
}

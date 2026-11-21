using Bower.Pipeline;

namespace Bower.Source.Kubernetes;

/// <summary>Exact <c>key=value</c> pod label selector.</summary>
public sealed record LabelSelectorEntry(string Key, string Value);

public sealed record KubernetesLogSourceOptions
{
    public const int DefaultMaxLineBytes = 64 * 1024;
    public const int MaxAllowedLineBytes = 64 * 1024;
    public const int DefaultMaxPartialBytes = 64 * 1024;
    public const int DefaultMaxBatchLines = 256;
    public const int MaxAllowedBatchLines = 500;
    public const int DefaultMaxPods = 200;
    public const int MaxAllowedPods = 500;

    public string PodLogRoot { get; init; } = "/var/log/pods";

    /// <summary>Explicit allow-listed Kubernetes namespaces. No wildcards or cluster-wide collection.</summary>
    public IReadOnlyList<string> Namespaces { get; init; } = [];

    /// <summary>Explicit label selectors (<c>key=value</c>). Pods must match at least one selector.</summary>
    public IReadOnlyList<LabelSelectorEntry> LabelSelectors { get; init; } = [];

    /// <summary>Explicit allow-list of pod label keys to attach to emitted events (redacted like any field).</summary>
    public IReadOnlyList<string> AllowedMetadataLabels { get; init; } = [];

    public int MaxLineBytes { get; init; } = DefaultMaxLineBytes;

    public int MaxPartialBytes { get; init; } = DefaultMaxPartialBytes;

    public int MaxBatchLines { get; init; } = DefaultMaxBatchLines;

    public int MaxPods { get; init; } = DefaultMaxPods;

    /// <summary>When a container log file is first seen, start at its end unless false.</summary>
    public bool StartAtEnd { get; init; } = true;

    /// <summary>Optional bounded multi-line continuation rule for joined CRI messages.</summary>
    public CustomLogMultilineRule? Multiline { get; init; }

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(PodLogRoot) || !Path.IsPathRooted(PodLogRoot))
        {
            throw new ArgumentException("PodLogRoot must be a rooted directory path.", nameof(PodLogRoot));
        }

        if (Namespaces.Count is 0 or > 32)
        {
            throw new ArgumentException("Kubernetes log source requires 1..32 explicitly allow-listed namespaces.", nameof(Namespaces));
        }

        foreach (string ns in Namespaces)
        {
            if (!IsValidDnsLabel(ns))
            {
                throw new ArgumentException($"Invalid Kubernetes namespace '{ns}'. Wildcards and uppercase letters are refused.");
            }
        }

        if (LabelSelectors.Count is 0 or > 16)
        {
            throw new ArgumentException("Kubernetes log source requires 1..16 explicit label selectors.", nameof(LabelSelectors));
        }

        foreach (LabelSelectorEntry selector in LabelSelectors)
        {
            if (!IsValidLabelKey(selector.Key) || !IsValidLabelValue(selector.Value))
            {
                throw new ArgumentException($"Invalid Kubernetes label selector '{selector.Key}={selector.Value}'.");
            }
        }

        if (AllowedMetadataLabels.Count > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(AllowedMetadataLabels), "AllowedMetadataLabels cannot exceed 16 keys.");
        }

        foreach (string key in AllowedMetadataLabels)
        {
            if (!IsValidLabelKey(key))
            {
                throw new ArgumentException($"Invalid allowed metadata label key '{key}'.");
            }
        }

        if (MaxLineBytes is < 512 or > MaxAllowedLineBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxLineBytes), $"MaxLineBytes must be between 512 and {MaxAllowedLineBytes}.");
        }

        if (MaxPartialBytes is < 512 or > MaxAllowedLineBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxPartialBytes), $"MaxPartialBytes must be between 512 and {MaxAllowedLineBytes}.");
        }

        if (MaxBatchLines is < 1 or > MaxAllowedBatchLines)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxBatchLines), $"MaxBatchLines must be between 1 and {MaxAllowedBatchLines}.");
        }

        if (MaxPods is < 1 or > MaxAllowedPods)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxPods), $"MaxPods must be between 1 and {MaxAllowedPods}.");
        }

        if (Multiline is not null)
        {
            List<string> issues = [];
            CustomLogMultilineRule.Validate(Multiline, issues);
            if (issues.Count > 0)
            {
                throw new ArgumentException(string.Join(" ", issues), nameof(Multiline));
            }
        }
    }

    internal static bool IsValidDnsLabel(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 63
        && char.IsAsciiLetterLower(value[0]) || (value is { Length: > 0 and <= 63 } && char.IsAsciiDigit(value[0]))
        && value is { Length: > 0 and <= 63 }
        && (char.IsAsciiLetterLower(value[^1]) || char.IsAsciiDigit(value[^1]))
        && value.All(ch => char.IsAsciiLetterLower(ch) || char.IsAsciiDigit(ch) || ch == '-');

    internal static bool IsValidLabelKey(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '-' or '/');

    internal static bool IsValidLabelValue(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 63
        && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '-');

    internal static bool IsSafePathSegment(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && !value.Contains('/')
        && !value.Contains('\\')
        && !value.Contains("..", StringComparison.Ordinal)
        && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '-');
}

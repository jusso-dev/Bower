using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Source.File;

namespace Bower.Source.Kubernetes;

public sealed record KubernetesPollResult(
    int PodsScanned,
    int FilesTailed,
    int LinesRead,
    int EventsDelivered,
    int DroppedNonSecurity,
    int MalformedLines,
    int OversizedLines,
    bool StoppedOnBackpressure);

/// <summary>
/// Allow-listed Kubernetes container log source. Resolves pods strictly within allow-listed
/// namespaces and label selectors, tails <c>/var/log/pods</c> via <see cref="FileTailReader"/>
/// (rotation-aware, symlink-safe, bounded), parses CRI partial/final lines, attaches minimal
/// pod metadata plus allow-listed labels, and advances durable checkpoints only after
/// caller acknowledgement.
/// </summary>
public sealed class KubernetesLogSource
{
    private readonly KubernetesLogSourceOptions options;
    private readonly IKubernetesPodCatalog catalog;
    private readonly ISourceCursorStore cursorStore;
    private readonly TimeProvider clock;
    private readonly HashSet<string> allowedNamespaces;
    private readonly HashSet<string> allowedMetadataLabels;
    private readonly FileTailReaderOptions tailOptions;
    private readonly Dictionary<string, PartialBuffer> partials = new(StringComparer.Ordinal);

    public KubernetesLogSource(
        KubernetesLogSourceOptions options,
        IKubernetesPodCatalog catalog,
        ISourceCursorStore cursorStore,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(cursorStore);
        options.Validate();

        this.options = options;
        this.catalog = catalog;
        this.cursorStore = cursorStore;
        this.clock = clock ?? TimeProvider.System;
        allowedNamespaces = new HashSet<string>(options.Namespaces, StringComparer.Ordinal);
        allowedMetadataLabels = new HashSet<string>(options.AllowedMetadataLabels, StringComparer.Ordinal);
        tailOptions = new FileTailReaderOptions
        {
            MaxLineBytes = options.MaxLineBytes,
            MaxLinesPerBatch = options.MaxBatchLines,
            MaxBytesPerBatch = options.MaxLineBytes * Math.Min(options.MaxBatchLines, 64),
            StartAtEnd = options.StartAtEnd,
            UseFileIds = false
        };
    }

    public async Task<KubernetesPollResult> PollOnceAsync(
        Func<SecurityEventEnvelope, CancellationToken, Task<bool>> onEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        cancellationToken.ThrowIfCancellationRequested();

        List<KubernetesPodInfo> pods = await DiscoverAllowedPodsAsync(cancellationToken);

        int filesTailed = 0;
        int linesRead = 0;
        int eventsDelivered = 0;
        int droppedNonSecurity = 0;
        int malformedLines = 0;
        int oversizedLines = 0;
        bool backpressure = false;

        foreach (KubernetesPodInfo pod in pods)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (backpressure)
            {
                break;
            }

            foreach (string container in pod.Containers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!KubernetesLogSourceOptions.IsSafePathSegment(container))
                {
                    continue;
                }

                string? logPath = ResolveCurrentContainerLogPath(pod, container);
                if (logPath is null)
                {
                    continue;
                }

                filesTailed++;
                string cursorKey = $"k8s:{pod.Namespace}/{pod.Uid}/{container}";
                SourceCursorSnapshot? snapshot = await cursorStore.ReadAsync(cursorKey, cancellationToken);
                FileTailCursor? existingCursor = FileTailCursor.Deserialize(snapshot?.Value);
                long expectedVersion = snapshot?.Version ?? 0;

                string rotatedPath = $"{logPath}.1";
                FileTailBatch batch = FileTailReader.Read(
                    logPath,
                    System.IO.File.Exists(rotatedPath) ? rotatedPath : null,
                    existingCursor,
                    tailOptions,
                    cancellationToken);
                linesRead += batch.Lines.Count;

                FileTailCursor? committedCursor = null;
                bool stoppedHere = false;

                foreach (FileTailLine line in batch.Lines)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (line.Oversized)
                    {
                        oversizedLines++;
                        partials.Remove(cursorKey);
                        continue;
                    }

                    string lineText = Encoding.UTF8.GetString(line.Bytes);
                    if (!CriLogParser.TryParse(lineText, out CriLogLine? cri) || cri is null)
                    {
                        malformedLines++;
                        partials.Remove(cursorKey);
                        continue;
                    }

                    string? assembledMessage;
                    if (cri.IsPartial)
                    {
                        if (!TryAppendPartial(cursorKey, cri.Message))
                        {
                            oversizedLines++;
                            partials.Remove(cursorKey);
                        }

                        continue;
                    }

                    if (partials.Remove(cursorKey, out PartialBuffer? partial))
                    {
                        if (partial.Length + Encoding.UTF8.GetByteCount(cri.Message) > options.MaxPartialBytes)
                        {
                            oversizedLines++;
                            continue;
                        }

                        partial.Builder.Append(cri.Message);
                        assembledMessage = partial.Builder.ToString();
                    }
                    else
                    {
                        assembledMessage = cri.Message;
                    }

                    SecurityEventEnvelope? envelope = TryParseSecurityEnvelope(
                        assembledMessage,
                        pod,
                        container,
                        cri.Stream,
                        batch.Cursor.Fingerprint,
                        line.StartOffset);
                    if (envelope is null)
                    {
                        droppedNonSecurity++;
                        continue;
                    }

                    bool accepted = await onEvent(envelope, cancellationToken);
                    if (!accepted)
                    {
                        committedCursor = batch.RewindTo(line);
                        backpressure = true;
                        stoppedHere = true;
                        break;
                    }

                    eventsDelivered++;
                }

                FileTailCursor targetCursor = stoppedHere ? committedCursor! : batch.Cursor;
                string serialized = targetCursor.Serialize();
                if (!string.Equals(serialized, snapshot?.Value, StringComparison.Ordinal))
                {
                    await cursorStore.TryAdvanceAsync(
                        cursorKey,
                        expectedVersion,
                        serialized,
                        clock.GetUtcNow(),
                        cancellationToken);
                }

                if (backpressure)
                {
                    break;
                }
            }
        }

        return new KubernetesPollResult(
            pods.Count,
            filesTailed,
            linesRead,
            eventsDelivered,
            droppedNonSecurity,
            malformedLines,
            oversizedLines,
            backpressure);
    }

    private async Task<List<KubernetesPodInfo>> DiscoverAllowedPodsAsync(CancellationToken cancellationToken)
    {
        Dictionary<string, KubernetesPodInfo> byUid = new(StringComparer.Ordinal);
        foreach (string ns in options.Namespaces)
        {
            foreach (LabelSelectorEntry selector in options.LabelSelectors)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IReadOnlyList<KubernetesPodInfo> listed = await catalog.ListPodsAsync(ns, selector, cancellationToken);
                foreach (KubernetesPodInfo pod in listed)
                {
                    // Enforce allow-lists fail-closed even if the catalog returns unselected pods.
                    if (!IsPodAllowed(pod))
                    {
                        continue;
                    }

                    byUid.TryAdd(pod.Uid, pod);
                    if (byUid.Count >= options.MaxPods)
                    {
                        return [.. byUid.Values.OrderBy(p => p.Uid, StringComparer.Ordinal)];
                    }
                }
            }
        }

        return [.. byUid.Values.OrderBy(p => p.Uid, StringComparer.Ordinal)];
    }

    internal bool IsPodAllowed(KubernetesPodInfo pod)
    {
        if (!allowedNamespaces.Contains(pod.Namespace))
        {
            return false;
        }

        if (!KubernetesLogSourceOptions.IsSafePathSegment(pod.Namespace)
            || !KubernetesLogSourceOptions.IsSafePathSegment(pod.Name)
            || !KubernetesLogSourceOptions.IsSafePathSegment(pod.Uid))
        {
            return false;
        }

        foreach (LabelSelectorEntry selector in options.LabelSelectors)
        {
            if (pod.Labels.TryGetValue(selector.Key, out string? actual)
                && string.Equals(actual, selector.Value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    internal string? ResolveCurrentContainerLogPath(KubernetesPodInfo pod, string container)
    {
        string podDirName = $"{pod.Namespace}_{pod.Name}_{pod.Uid}";
        string containerDir = Path.Combine(options.PodLogRoot, podDirName, container);
        if (!Directory.Exists(containerDir))
        {
            return null;
        }

        // Standard kubelet container log files are numeric restart indices: 0.log, 1.log, ...
        int bestRestart = -1;
        string? bestPath = null;
        foreach (string file in Directory.EnumerateFiles(containerDir, "*.log"))
        {
            string name = Path.GetFileNameWithoutExtension(file);
            if (int.TryParse(name, out int restartIndex) && restartIndex > bestRestart)
            {
                bestRestart = restartIndex;
                bestPath = file;
            }
        }

        return bestPath;
    }

    private bool TryAppendPartial(string cursorKey, string fragment)
    {
        int fragmentBytes = Encoding.UTF8.GetByteCount(fragment);
        if (!partials.TryGetValue(cursorKey, out PartialBuffer? buffer))
        {
            if (fragmentBytes > options.MaxPartialBytes)
            {
                return false;
            }

            buffer = new PartialBuffer();
            partials[cursorKey] = buffer;
        }

        if (buffer.Length + fragmentBytes > options.MaxPartialBytes)
        {
            return false;
        }

        buffer.Builder.Append(fragment);
        buffer.Length += fragmentBytes;
        return true;
    }

    private SecurityEventEnvelope? TryParseSecurityEnvelope(
        string message,
        KubernetesPodInfo pod,
        string container,
        string stream,
        string fileFingerprint,
        long startOffset)
    {
        string trimmed = message.Trim();
        if (!trimmed.StartsWith('{') || !trimmed.EndsWith('}'))
        {
            return null;
        }

        SecurityEventEnvelope? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize(trimmed, BowerJson.Envelope);
        }
        catch (JsonException)
        {
            return null;
        }

        if (parsed is null
            || string.IsNullOrWhiteSpace(parsed.EventCategory)
            || string.IsNullOrWhiteSpace(parsed.EventType)
            || string.IsNullOrWhiteSpace(parsed.EventAction)
            || parsed.Application is null
            || string.IsNullOrWhiteSpace(parsed.Application.Name))
        {
            return null;
        }

        Dictionary<string, string> labels = parsed.Labels is { Count: > 0 } existing
            ? new Dictionary<string, string>(existing, StringComparer.Ordinal)
            : new Dictionary<string, string>(StringComparer.Ordinal);
        labels["k8s.namespace"] = pod.Namespace;
        labels["k8s.pod"] = pod.Name;
        labels["k8s.container"] = container;
        labels["k8s.stream"] = stream;

        foreach (string key in allowedMetadataLabels)
        {
            if (pod.Labels.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
            {
                labels[$"k8s.label.{key}"] = value;
            }
        }

        string deterministicId = string.IsNullOrWhiteSpace(parsed.EventId)
            ? BuildDeterministicEventId(pod.Uid, container, fileFingerprint, startOffset)
            : parsed.EventId;

        return parsed with
        {
            EventId = deterministicId,
            EventOriginalId = parsed.EventOriginalId ?? deterministicId,
            Labels = labels
        };
    }

    internal static string BuildDeterministicEventId(
        string podUid,
        string container,
        string fileFingerprint,
        long startOffset)
    {
        string material = $"k8s\u001f{podUid}\u001f{container}\u001f{fileFingerprint}\u001f{startOffset}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return $"k8s-{Convert.ToHexStringLower(hash)[..32]}";
    }

    private sealed class PartialBuffer
    {
        public StringBuilder Builder { get; } = new();
        public int Length { get; set; }
    }
}

using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.Kubernetes;

public sealed record KubernetesPodInfo(
    string Namespace,
    string Name,
    string Uid,
    IReadOnlyList<string> Containers,
    IReadOnlyDictionary<string, string> Labels);

/// <summary>
/// Platform seam for listing allow-listed pods on the current node.
/// </summary>
public interface IKubernetesPodCatalog
{
    Task<IReadOnlyList<KubernetesPodInfo>> ListPodsAsync(
        string namespaceName,
        LabelSelectorEntry selector,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Minimal Kubernetes API client using only namespaced <c>get/list pods</c> RBAC.
/// Reads its bearer token strictly from a file (never env vars) and caps response bytes.
/// </summary>
public sealed class KubernetesApiPodCatalog : IKubernetesPodCatalog
{
    public const int MaxResponseBytes = 4 * 1024 * 1024;

    private readonly HttpClient httpClient;
    private readonly Uri apiServerBaseUri;
    private readonly string? tokenFilePath;
    private readonly string? nodeName;

    public KubernetesApiPodCatalog(
        HttpClient httpClient,
        Uri apiServerBaseUri,
        string? tokenFilePath = null,
        string? nodeName = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(apiServerBaseUri);
        this.httpClient = httpClient;
        this.apiServerBaseUri = apiServerBaseUri;
        this.tokenFilePath = tokenFilePath;
        this.nodeName = nodeName;
    }

    public async Task<IReadOnlyList<KubernetesPodInfo>> ListPodsAsync(
        string namespaceName,
        LabelSelectorEntry selector,
        CancellationToken cancellationToken = default)
    {
        if (!KubernetesLogSourceOptions.IsValidDnsLabel(namespaceName))
        {
            throw new ArgumentException("Invalid namespace.", nameof(namespaceName));
        }

        string query = $"?labelSelector={Uri.EscapeDataString($"{selector.Key}={selector.Value}")}";
        if (!string.IsNullOrWhiteSpace(nodeName))
        {
            query += $"&fieldSelector={Uri.EscapeDataString($"spec.nodeName={nodeName}")}";
        }

        Uri requestUri = new(apiServerBaseUri, $"/api/v1/namespaces/{Uri.EscapeDataString(namespaceName)}/pods{query}");
        using HttpRequestMessage request = new(HttpMethod.Get, requestUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(tokenFilePath) && System.IO.File.Exists(tokenFilePath))
        {
            string token = (await System.IO.File.ReadAllTextAsync(tokenFilePath, cancellationToken)).Trim();
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        using HttpResponseMessage response = await httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();

        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream bounded = new();
        byte[] buffer = new byte[16 * 1024];
        int total = 0;
        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > MaxResponseBytes)
            {
                throw new InvalidDataException("Kubernetes pod list response exceeded 4 MiB safety cap.");
            }

            bounded.Write(buffer, 0, read);
        }

        bounded.Position = 0;
        K8sPodList? list = await JsonSerializer.DeserializeAsync(
            bounded,
            KubernetesJsonContext.Default.K8sPodList,
            cancellationToken);
        if (list?.Items is null)
        {
            return [];
        }

        List<KubernetesPodInfo> result = new(list.Items.Count);
        foreach (K8sPodItem item in list.Items)
        {
            string? ns = item.Metadata?.Namespace;
            string? name = item.Metadata?.Name;
            string? uid = item.Metadata?.Uid;
            if (string.IsNullOrWhiteSpace(ns) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(uid))
            {
                continue;
            }

            string[] containers = item.Spec?.Containers?
                .Select(c => c.Name)
                .Where(c => !string.IsNullOrWhiteSpace(c))
                .Cast<string>()
                .Distinct(StringComparer.Ordinal)
                .ToArray() ?? [];
            IReadOnlyDictionary<string, string> labels = item.Metadata?.Labels is { Count: > 0 } map
                ? map
                : new Dictionary<string, string>(StringComparer.Ordinal);
            result.Add(new KubernetesPodInfo(ns, name, uid, containers, labels));
        }

        return result;
    }
}

internal sealed class K8sPodList
{
    [JsonPropertyName("items")]
    public List<K8sPodItem>? Items { get; set; }
}

internal sealed class K8sPodItem
{
    [JsonPropertyName("metadata")]
    public K8sPodMetadata? Metadata { get; set; }

    [JsonPropertyName("spec")]
    public K8sPodSpec? Spec { get; set; }
}

internal sealed class K8sPodMetadata
{
    [JsonPropertyName("namespace")]
    public string? Namespace { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("uid")]
    public string? Uid { get; set; }

    [JsonPropertyName("labels")]
    public Dictionary<string, string>? Labels { get; set; }
}

internal sealed class K8sPodSpec
{
    [JsonPropertyName("containers")]
    public List<K8sContainer>? Containers { get; set; }
}

internal sealed class K8sContainer
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

[JsonSerializable(typeof(K8sPodList))]
internal sealed partial class KubernetesJsonContext : JsonSerializerContext;

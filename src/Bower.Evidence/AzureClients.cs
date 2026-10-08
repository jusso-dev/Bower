using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Identity;

namespace Bower.Evidence;

/// <summary>Rows from a Log Analytics query, as column-name dictionaries.</summary>
public sealed record QueryRows(IReadOnlyList<IReadOnlyDictionary<string, JsonNode?>> Rows, string? Error);

public interface ILogAnalyticsQuery
{
    Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken);
}

public interface IArmReader
{
    /// <summary>GETs an ARM resource; null when it does not exist or is not readable.</summary>
    Task<JsonObject?> GetAsync(string resourceId, string apiVersion, CancellationToken cancellationToken);
}

/// <summary>Builds the read-only verifier credential (kept separate from the ingest identity).</summary>
public static class VerifierCredential
{
    public static TokenCredential Create(string? mode, string? clientId = null) =>
        (mode ?? "azure-cli").ToLowerInvariant() switch
        {
            "azure-cli" => new AzureCliCredential(),
            "managed-identity" => string.IsNullOrWhiteSpace(clientId)
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(clientId)),
            "workload-identity" => new WorkloadIdentityCredential(),
            "environment" => new EnvironmentCredential(),
            _ => throw new ArgumentException("Credential must be azure-cli, managed-identity, workload-identity or environment.")
        };
}

/// <summary>Log Analytics query REST API (read-only).</summary>
public sealed class LogAnalyticsQueryClient(HttpClient http, TokenCredential credential) : ILogAnalyticsQuery
{
    private static readonly string[] Scopes = ["https://api.loganalytics.io/.default"];

    public async Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
    {
        AccessToken token = await credential.GetTokenAsync(new TokenRequestContext(Scopes), cancellationToken);
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            new Uri($"https://api.loganalytics.azure.com/v1/workspaces/{Uri.EscapeDataString(workspaceId)}/query"))
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { query = kql, timespan = System.Xml.XmlConvert.ToString(timespan) }),
                Encoding.UTF8,
                "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            // Only the error code is kept; bodies can echo query text.
            string code = JsonNode.Parse(body)?["error"]?["code"]?.GetValue<string>() ?? $"http-{(int)response.StatusCode}";
            return new QueryRows([], code);
        }

        return Parse(body);
    }

    internal static QueryRows Parse(string body)
    {
        JsonObject? table = (JsonNode.Parse(body)?["tables"] as JsonArray)?.FirstOrDefault() as JsonObject;
        if (table is null)
        {
            return new QueryRows([], null);
        }

        string[] columns = (table["columns"] as JsonArray ?? [])
            .Select(column => column?["name"]?.GetValue<string>() ?? string.Empty)
            .ToArray();
        List<IReadOnlyDictionary<string, JsonNode?>> rows = [];
        foreach (JsonArray row in (table["rows"] as JsonArray ?? []).OfType<JsonArray>())
        {
            Dictionary<string, JsonNode?> values = new(StringComparer.Ordinal);
            for (int index = 0; index < columns.Length && index < row.Count; index++)
            {
                values[columns[index]] = row[index]?.DeepClone();
            }

            rows.Add(values);
        }

        return new QueryRows(rows, null);
    }
}

/// <summary>Azure Resource Manager GET (read-only).</summary>
public sealed class ArmReader(HttpClient http, TokenCredential credential) : IArmReader
{
    private static readonly string[] Scopes = ["https://management.azure.com/.default"];

    public async Task<JsonObject?> GetAsync(string resourceId, string apiVersion, CancellationToken cancellationToken)
    {
        if (!resourceId.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Resource id must start with /subscriptions/.", nameof(resourceId));
        }

        AccessToken token = await credential.GetTokenAsync(new TokenRequestContext(Scopes), cancellationToken);
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            new Uri($"https://management.azure.com{resourceId}?api-version={Uri.EscapeDataString(apiVersion)}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        return response.IsSuccessStatusCode
            ? JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken)) as JsonObject
            : null;
    }
}

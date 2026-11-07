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

    // Duplicate keys fail the parse; MaxDepth is the reader default, pinned for Rust parity.
    private static readonly JsonDocumentOptions QueryDocumentOptions = new() { AllowDuplicateProperties = false, MaxDepth = 64 };

    public async Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
    {
        AccessToken token = await credential.GetTokenAsync(new TokenRequestContext(Scopes), cancellationToken);
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            new Uri($"https://api.loganalytics.azure.com/v1/workspaces/{Uri.EscapeDataString(workspaceId)}/query"))
        {
            Content = new StringContent(
                JsonSerializer.Serialize(
                    new LogAnalyticsQueryRequest(kql, System.Xml.XmlConvert.ToString(timespan)),
                    EvidenceJsonContext.Default.LogAnalyticsQueryRequest),
                Encoding.UTF8,
                "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        // Log Analytics caches query responses by default. Polling must see fresh
        // destination state rather than repeatedly receiving a cached empty result.
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        string body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            // Only the error code is kept; bodies can echo query text. Gateways can answer
            // with an empty or HTML body: fall back to the status code, as the Rust port does.
            return new QueryRows([], ErrorCode(body) ?? $"http-{(int)response.StatusCode}");
        }

        return Parse(body);
    }

    private static string? ErrorCode(string body)
    {
        try
        {
            return JsonNode.Parse(body)?["error"]?["code"] is JsonValue code && code.TryGetValue(out string? text) ? text : null;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    internal static QueryRows Parse(string body)
    {
        // A 2xx answer must be a JSON object. An empty body (204 No Content) or a gateway's
        // non-JSON page is a failed query, never an empty result; the body is not kept.
        if (ParseObject(body) is not JsonObject root)
        {
            return Invalid;
        }

        if (root.TryGetPropertyValue("error", out JsonNode? error) && error is not null)
        {
            // A successful HTTP response can contain partial results and an error.
            // Do not use those rows as complete evidence.
            return new QueryRows([], ProbeOutcomes.QueryIncompleteCode);
        }

        // Log Analytics always returns at least the PrimaryResult table with column and row
        // arrays; zero rows is an empty rows array. Anything less cannot prove absence.
        if (root["tables"] is not JsonArray { Count: > 0 } tables
            || tables[0] is not JsonObject table
            || table["columns"] is not JsonArray columnNodes
            || table["rows"] is not JsonArray rowNodes)
        {
            return Invalid;
        }

        List<string> columns = [];
        foreach (JsonNode? column in columnNodes)
        {
            if (column is not JsonObject named || ProbeOutcomes.Text(named["name"]) is not { } name)
            {
                return Invalid;
            }

            columns.Add(name);
        }

        List<IReadOnlyDictionary<string, JsonNode?>> rows = [];
        foreach (JsonNode? rowNode in rowNodes)
        {
            if (rowNode is not JsonArray row)
            {
                return Invalid;
            }

            Dictionary<string, JsonNode?> values = new(StringComparer.Ordinal);
            for (int index = 0; index < columns.Count && index < row.Count; index++)
            {
                values[columns[index]] = row[index]?.DeepClone();
            }

            rows.Add(values);
        }

        return new QueryRows(rows, null);
    }

    private static QueryRows Invalid => new([], ProbeOutcomes.QueryInvalidResponseCode);

    private static JsonObject? ParseObject(string body)
    {
        try
        {
            // An escaped lone surrogate parses but throws when the string is read, so every
            // string and property name is decoded here first, as Rust's parser does.
            Utf8JsonReader reader = new(Encoding.UTF8.GetBytes(body), new JsonReaderOptions { MaxDepth = QueryDocumentOptions.MaxDepth });
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName)
                {
                    _ = reader.GetString();
                }
            }

            // Rejecting duplicate keys here means no later read can throw an exception whose
            // message names a key.
            return JsonNode.Parse(body, documentOptions: QueryDocumentOptions) as JsonObject;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return null;
        }
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

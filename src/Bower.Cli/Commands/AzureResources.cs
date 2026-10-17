using System.Text.Json.Nodes;
using Bower.Dcr;
using Bower.Evidence;

namespace Bower.Cli.Commands;

/// <summary>
/// Read-only ARM GETs for <c>doctor</c> and <c>dcr diff</c>, each with its resource
/// provider's pinned api-version (<see cref="AzureApiVersions"/>).
/// </summary>
internal static class AzureResources
{
    /// <summary>Per-request timeout for ARM reads (the same as <c>evidence run</c>).</summary>
    public static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(30);

    public static ArmReader CreateReader(string? credential) =>
        new(new HttpClient { Timeout = HttpTimeout }, VerifierCredential.Create(credential));

    /// <summary>A <c>Microsoft.Insights/dataCollectionRules</c> resource.</summary>
    public static Task<JsonObject?> GetRuleAsync(IArmReader arm, string ruleId) =>
        arm.GetAsync(ruleId, AzureApiVersions.DataCollectionRules, CancellationToken.None);

    /// <summary>A <c>Microsoft.OperationalInsights/workspaces</c> resource.</summary>
    public static Task<JsonObject?> GetWorkspaceAsync(IArmReader arm, string workspaceId) =>
        arm.GetAsync(workspaceId, AzureApiVersions.LogAnalytics, CancellationToken.None);

    /// <summary>A <c>Microsoft.OperationalInsights/workspaces/tables</c> resource.</summary>
    public static Task<JsonObject?> GetTableAsync(IArmReader arm, string workspaceId, string table) =>
        arm.GetAsync($"{workspaceId}/tables/{table}", AzureApiVersions.LogAnalytics, CancellationToken.None);
}

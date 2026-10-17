namespace Bower.Dcr;

/// <summary>
/// Pinned Azure Resource Manager api-versions, one per resource provider. ARM rejects an
/// api-version the provider does not publish, so each resource type uses its own.
/// Keep these, the generated template and <c>deploy/bicep/main.bicep</c> identical.
/// </summary>
public static class AzureApiVersions
{
    /// <summary>
    /// <c>Microsoft.OperationalInsights/workspaces</c> and <c>workspaces/tables</c>
    /// (GA; supports <c>plan</c>, <c>retentionInDays</c> and <c>totalRetentionInDays</c>).
    /// </summary>
    public const string LogAnalytics = "2025-07-01";

    /// <summary>
    /// <c>Microsoft.Insights/dataCollectionRules</c> (latest GA; supports <c>kind: Direct</c>
    /// and <c>endpoints.logsIngestion</c>).
    /// </summary>
    public const string DataCollectionRules = "2024-03-11";
}

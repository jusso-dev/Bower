using Azure.Core;
using Azure.Identity;

namespace Bower.Functions.Collector;

/// <summary>Which single credential the function uses for Logs Ingestion (never a chain).</summary>
public sealed record CredentialSelection(FunctionCredentialMode Mode, string? UserAssignedClientId)
{
    public string Description => Mode switch
    {
        FunctionCredentialMode.ManagedIdentity when UserAssignedClientId is null => "managed-identity:system-assigned",
        FunctionCredentialMode.ManagedIdentity => "managed-identity:user-assigned",
        _ => "azure-cli:development"
    };
}

/// <summary>
/// Builds exactly one credential. Default: the app's system-assigned managed identity; a
/// user-assigned identity only when its client ID is configured. No secrets, certificates,
/// environment credentials or <c>DefaultAzureCredential</c> probing.
/// </summary>
public static class FunctionCredentialFactory
{
    public static CredentialSelection Select(FunctionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return settings.AzureCredential switch
        {
            FunctionCredentialMode.ManagedIdentity => new CredentialSelection(
                FunctionCredentialMode.ManagedIdentity, settings.AzureClientId),
            FunctionCredentialMode.AzureCli when settings.IsDevelopment => new CredentialSelection(
                FunctionCredentialMode.AzureCli, null),
            _ => throw new InvalidOperationException("Unsupported Azure credential mode for this environment.")
        };
    }

    public static TokenCredential Create(FunctionSettings settings)
    {
        CredentialSelection selection = Select(settings);
        return selection.Mode switch
        {
            FunctionCredentialMode.ManagedIdentity => new ManagedIdentityCredential(
                selection.UserAssignedClientId is null
                    ? ManagedIdentityId.SystemAssigned
                    : ManagedIdentityId.FromUserAssignedClientId(selection.UserAssignedClientId)),
            _ => new AzureCliCredential()
        };
    }
}

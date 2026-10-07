using Azure.Core;
using Azure.Identity;

namespace Bower.Collector;

/// <summary>Builds exactly one configured credential source for least privilege.</summary>
public static class AzureCredentialFactory
{
    public static TokenCredential Create(CollectorSettings settings) =>
        settings.AzureCredential switch
        {
            AzureCredentialMode.ManagedIdentity => string.IsNullOrWhiteSpace(settings.AzureClientId)
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(
                    ManagedIdentityId.FromUserAssignedClientId(settings.AzureClientId)),
            AzureCredentialMode.WorkloadIdentity => new WorkloadIdentityCredential(),
            AzureCredentialMode.Environment => new EnvironmentCredential(),
            AzureCredentialMode.AzureCli => new AzureCliCredential(),
            _ => throw new InvalidOperationException("Unsupported Azure credential mode.")
        };
}

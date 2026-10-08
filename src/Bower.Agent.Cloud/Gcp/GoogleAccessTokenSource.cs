using Google.Apis.Auth.OAuth2;

namespace Bower.Agent.Cloud.Gcp;

/// <summary>
/// Application Default Credentials: GKE Workload Identity, the Compute metadata server or a
/// Workload Identity Federation (external_account) configuration. Service account key files
/// are refused unless explicitly allowed, so no long-lived Google key is stored by default.
/// </summary>
public sealed class GoogleAccessTokenSource(bool allowServiceAccountKey) : IGoogleAccessTokenSource, IDisposable
{
    private const string PubSubScope = "https://www.googleapis.com/auth/pubsub";
    private readonly SemaphoreSlim gate = new(1, 1);
    private ITokenAccess? credential;

    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        ITokenAccess access = credential ?? await LoadAsync(cancellationToken);
        // The library caches the token and refreshes it before expiry.
        return await access.GetAccessTokenForRequestAsync(cancellationToken: cancellationToken);
    }

    private async Task<ITokenAccess> LoadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (credential is not null)
            {
                return credential;
            }

            GoogleCredential adc = await GoogleCredential.GetApplicationDefaultAsync(cancellationToken);
            Check(adc.UnderlyingCredential, allowServiceAccountKey);
            credential = adc.CreateScoped(PubSubScope);
            return credential;
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose() => gate.Dispose();

    internal static void Check(ICredential underlying, bool allowServiceAccountKey)
    {
        if (underlying is ServiceAccountCredential && !allowServiceAccountKey)
        {
            throw new InvalidOperationException(
                "A Google service account key was found through Application Default Credentials. "
                + "Use Workload Identity (GKE), the attached service account (Compute/Cloud Run) or "
                + "Workload Identity Federation, or set BOWER_GCP_ALLOW_KEY_FILE=true for a lab.");
        }
    }
}

using Bower.Agent.Cloud.Gcp.Auth;

namespace Bower.Agent.Cloud.Gcp;

/// <summary>
/// Application Default Credentials (AIP-4110) without a Google client library, so the agent
/// stays Native AOT: <c>GOOGLE_APPLICATION_CREDENTIALS</c>, then the gcloud well-known file,
/// then the Compute/GKE metadata server (GKE Workload Identity, attached service accounts).
/// Credential files may be Workload Identity Federation (<c>external_account</c>)
/// configurations. Service account key files and gcloud user credentials are refused unless
/// explicitly allowed, so no long-lived Google secret is stored by default. Tokens are cached
/// in memory until shortly before expiry and are never logged or written anywhere.
/// </summary>
public sealed class GoogleAccessTokenSource : IGoogleAccessTokenSource, IDisposable
{
    private const string PubSubScope = "https://www.googleapis.com/auth/pubsub";
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);

    private readonly bool allowServiceAccountKey;
    private readonly Func<string, string?> environment;
    private readonly GoogleAuthHttp http;
    private readonly TimeProvider time;
    private readonly SemaphoreSlim gate = new(1, 1);
    private IGoogleCredential? credential;
    private volatile CachedToken? cached;

    public GoogleAccessTokenSource(bool allowServiceAccountKey)
        : this(allowServiceAccountKey, Environment.GetEnvironmentVariable, GoogleAuthHttp.CreateDefault(), TimeProvider.System)
    {
    }

    internal GoogleAccessTokenSource(
        bool allowServiceAccountKey,
        Func<string, string?> environment,
        GoogleAuthHttp http,
        TimeProvider time)
    {
        this.allowServiceAccountKey = allowServiceAccountKey;
        this.environment = environment;
        this.http = http;
        this.time = time;
    }

    internal static IReadOnlyList<string> Scopes { get; } = [PubSubScope];

    /// <summary>The credential flow in use, once loaded (for diagnostics; no secrets).</summary>
    internal string? CredentialKind => credential?.Kind;

    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        if (cached is { } token && time.GetUtcNow() < token.RefreshAt)
        {
            return token.Token.Value;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            DateTimeOffset now = time.GetUtcNow();
            if (cached is { } current && now < current.RefreshAt)
            {
                return current.Token.Value;
            }

            IGoogleCredential source = credential ??= await DiscoverAsync(cancellationToken);
            GoogleAccessToken fresh = await source.FetchAsync(cancellationToken);
            TimeSpan lifetime = fresh.ExpiresAt - now;
            if (lifetime <= TimeSpan.Zero)
            {
                throw new InvalidOperationException("The Google access token has already expired.");
            }

            // Refresh five minutes early, or halfway through a short-lived token.
            cached = new CachedToken(fresh, fresh.ExpiresAt - (lifetime > 2 * RefreshMargin ? RefreshMargin : lifetime / 2));
            return fresh.Value;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Loads and checks credentials up front so a refused key file stops start-up.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            credential ??= await DiscoverAsync(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        (credential as IDisposable)?.Dispose();
        http.Dispose();
        gate.Dispose();
    }

    private async Task<IGoogleCredential> DiscoverAsync(CancellationToken cancellationToken)
    {
        if (environment("GOOGLE_APPLICATION_CREDENTIALS") is { } path && !string.IsNullOrWhiteSpace(path))
        {
            return FromFile(path, "GOOGLE_APPLICATION_CREDENTIALS");
        }

        if (WellKnownFile() is { } wellKnown && File.Exists(wellKnown))
        {
            return FromFile(wellKnown, "the gcloud application default credentials file");
        }

        if (await MetadataServerCredential.IsAvailableAsync(http, MetadataServerCredential.ProbeRoot(environment), cancellationToken))
        {
            return new MetadataServerCredential(http, MetadataServerCredential.Root(environment), Scopes, time);
        }

        throw new InvalidOperationException(
            "No Google Application Default Credentials found. Use GKE Workload Identity or an attached "
            + "service account (metadata server), or set GOOGLE_APPLICATION_CREDENTIALS to a Workload "
            + "Identity Federation configuration.");
    }

    internal IGoogleCredential FromFile(string path, string origin)
    {
        byte[] json;
        try
        {
            using FileStream stream = File.OpenRead(path);
            if (stream.Length > GoogleCredentialFile.MaximumBytes)
            {
                throw new InvalidOperationException(
                    $"The Google credential file from {origin} exceeds {GoogleCredentialFile.MaximumBytes} bytes.");
            }

            json = new byte[stream.Length];
            stream.ReadExactly(json);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"The Google credential file from {origin} could not be read ({exception.GetType().Name}).");
        }

        GoogleCredentialFile file = GoogleCredentialFile.Parse(json);
        return file.Type switch
        {
            "external_account" => new ExternalAccountCredential(file, Scopes, http, environment, time),
            "service_account" when allowServiceAccountKey => new ServiceAccountKeyCredential(file, Scopes, http, time),
            "service_account" => throw new InvalidOperationException(
                "A Google service account key was found through Application Default Credentials. "
                + "Use Workload Identity (GKE), the attached service account (Compute/Cloud Run) or "
                + "Workload Identity Federation, or set BOWER_GCP_ALLOW_KEY_FILE=true for a lab."),
            "authorized_user" when allowServiceAccountKey => new AuthorizedUserCredential(file, http, time),
            "authorized_user" => throw new InvalidOperationException(
                "gcloud user credentials (a long-lived refresh token) were found through Application Default "
                + "Credentials. Use Workload Identity, an attached service account or Workload Identity "
                + "Federation, or set BOWER_GCP_ALLOW_KEY_FILE=true for a lab."),
            _ => throw new InvalidOperationException(
                "Unsupported Google credential file type; Bower accepts external_account (Workload Identity "
                + "Federation), and service_account or authorized_user only with BOWER_GCP_ALLOW_KEY_FILE=true.")
        };
    }

    /// <summary>gcloud's ADC file: <c>$CLOUDSDK_CONFIG</c>, else ~/.config/gcloud (%APPDATA%\gcloud on Windows).</summary>
    private string? WellKnownFile()
    {
        const string Name = "application_default_credentials.json";
        if (environment("CLOUDSDK_CONFIG") is { Length: > 0 } config)
        {
            return Path.Combine(config, Name);
        }

        if (OperatingSystem.IsWindows())
        {
            return environment("APPDATA") is { Length: > 0 } appData ? Path.Combine(appData, "gcloud", Name) : null;
        }

        return environment("HOME") is { Length: > 0 } home ? Path.Combine(home, ".config", "gcloud", Name) : null;
    }

    private sealed record CachedToken(GoogleAccessToken Token, DateTimeOffset RefreshAt);
}

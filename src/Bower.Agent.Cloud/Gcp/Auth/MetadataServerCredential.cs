namespace Bower.Agent.Cloud.Gcp.Auth;

/// <summary>
/// Access tokens from the Compute Engine / GKE metadata server (AIP-4115): the attached
/// service account on Compute Engine, Cloud Run and GKE node pools, or the Kubernetes service
/// account's mapped identity under GKE Workload Identity. No secret is stored locally.
/// </summary>
internal sealed class MetadataServerCredential(GoogleAuthHttp http, Uri root, IReadOnlyList<string> scopes, TimeProvider time)
    : IGoogleCredential
{
    private const string FlavorHeader = "Metadata-Flavor";
    private const string Flavor = "Google";

    public string Kind => "metadata server";

    /// <summary>
    /// The metadata server root. <c>GCE_METADATA_HOST</c> (host[:port]) overrides the default
    /// <c>metadata.google.internal</c>, as in Google's libraries; it must be a metadata or
    /// loopback host because the connection is plain HTTP.
    /// </summary>
    public static Uri Root(Func<string, string?> environment) => HostRoot(environment("GCE_METADATA_HOST"), "metadata.google.internal");

    /// <summary>
    /// Root used to detect the metadata server: <c>GCE_METADATA_HOST</c> when set (emulators),
    /// otherwise <c>GCE_METADATA_IP</c> or 169.254.169.254, so detection needs no DNS.
    /// </summary>
    public static Uri ProbeRoot(Func<string, string?> environment) =>
        HostRoot(environment("GCE_METADATA_HOST") ?? environment("GCE_METADATA_IP"), "169.254.169.254");

    /// <summary>True when a Google metadata server answers with <c>Metadata-Flavor: Google</c>.</summary>
    public static async Task<bool> IsAvailableAsync(GoogleAuthHttp http, Uri probeRoot, CancellationToken cancellationToken)
    {
        // Google's libraries retry the probe a few times with a short timeout.
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using HttpRequestMessage request = new(HttpMethod.Get, probeRoot);
                request.Headers.Add(FlavorHeader, Flavor);
                HttpResult result = await http.SendAsync(
                    request,
                    "Metadata server probe",
                    GoogleAuthHttp.MaximumResponseBytes,
                    cancellationToken,
                    TimeSpan.FromSeconds(3));
                return HasFlavor(result);
            }
            catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or InvalidOperationException
                && !cancellationToken.IsCancellationRequested)
            {
                // Not reachable (yet); try again.
            }
        }

        return false;
    }

    public async Task<GoogleAccessToken> FetchAsync(CancellationToken cancellationToken)
    {
        Uri url = new(
            root,
            "computeMetadata/v1/instance/service-accounts/default/token?scopes="
            + Uri.EscapeDataString(string.Join(',', scopes)));
        using HttpRequestMessage request = new(HttpMethod.Get, url);
        request.Headers.Add(FlavorHeader, Flavor);
        HttpResult result = await http.SendAsync(
            request,
            "Metadata server token request",
            GoogleAuthHttp.MaximumResponseBytes,
            cancellationToken);
        if (!HasFlavor(result))
        {
            throw new InvalidOperationException("The metadata server response is missing Metadata-Flavor: Google.");
        }

        return GoogleOAuth.ReadTokenResponse(result.Body, "Metadata server token request", time.GetUtcNow());
    }

    private static bool HasFlavor(HttpResult result) =>
        result.Headers.TryGetValues(FlavorHeader, out IEnumerable<string>? values)
        && values.Any(value => string.Equals(value, Flavor, StringComparison.Ordinal));

    private static Uri HostRoot(string? host, string fallback)
    {
        string value = string.IsNullOrWhiteSpace(host) ? fallback : host.Trim();
        if (!Uri.TryCreate($"http://{value}/", UriKind.Absolute, out Uri? root)
            || root.AbsolutePath != "/"
            || !string.IsNullOrEmpty(root.UserInfo)
            || !string.IsNullOrEmpty(root.Query)
            || !GoogleAuthHttp.IsMetadataOrLoopback(root))
        {
            throw new InvalidOperationException(
                "GCE_METADATA_HOST and GCE_METADATA_IP must be a metadata server or loopback host[:port].");
        }

        return root;
    }
}

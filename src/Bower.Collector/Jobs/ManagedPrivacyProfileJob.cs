using System.Net;
using System.Net.Http.Headers;
using Azure.Core;
using Bower.Packs;
using Bower.Redaction.Privacy;

namespace Bower.Collector.Jobs;

/// <summary>
/// Management mode only (BOWER_PRIVACY_PROFILE_SOURCE=management): fetches the privacy
/// profile version assigned to this collector. A new verified version is staged in the
/// cache atomically and the host stops gracefully so the supervisor (Docker restart policy,
/// systemd <c>Restart=on-failure</c>) restarts it with the new profile: the process exits
/// with <see cref="RestartExitCode"/>. Anything that does not
/// verify keeps the running profile and fails the job. Metadata-only logs.
/// </summary>
public sealed partial class ManagedPrivacyProfileJob(
    IHttpClientFactory httpClientFactory,
    TokenCredential credential,
    CollectorSettings settings,
    PolicyBundle bundle,
    IHostApplicationLifetime lifetime,
    ILogger<ManagedPrivacyProfileJob> logger)
{
    public const string Id = "managed-privacy-profile";

    /// <summary>EX_TEMPFAIL: a deliberate restart to apply a new privacy profile.</summary>
    public const int RestartExitCode = 75;

    private static int restartRequested;

    /// <summary>True once a staged or cleared profile asked the supervisor for a restart.</summary>
    public static bool RestartRequested => Volatile.Read(ref restartRequested) == 1;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        AccessToken accessToken = await credential.GetTokenAsync(
            new TokenRequestContext([settings.ManagementScope!]),
            cancellationToken);
        HttpClient client = httpClientFactory.CreateClient(ManagementHeartbeatJob.HttpClientName);
        // The bearer token is attached per request, never to shared default headers.
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            $"api/collectors/{Uri.EscapeDataString(settings.CollectorId)}/privacy-profile/deployment")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken.Token) }
        };

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException
            || (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // Collection and delivery continue with the current privacy profile.
            LogUnreachable(logger, exception.GetType().Name);
            throw;
        }

        using (response)
        {
            switch (response.StatusCode)
            {
                case HttpStatusCode.NoContent:
                    Clear();
                    return;
                case HttpStatusCode.Conflict:
                    LogCollectorNotActive(logger);
                    return;
                case HttpStatusCode.OK:
                    byte[] document = await ReadBoundedAsync(response.Content, cancellationToken);
                    Stage(document);
                    return;
                default:
                    LogUnexpectedStatus(logger, (int)response.StatusCode);
                    throw new ManagedPrivacyProfileException(
                        $"Management returned HTTP {(int)response.StatusCode} for the privacy profile deployment.");
            }
        }
    }

    private void Stage(byte[] document)
    {
        VerifiedManagedPrivacyProfile verified;
        try
        {
            byte[]? key = settings.PrivacyHmacKeyFile is null
                ? null
                : PrivacyProfileLoader.ReadKeyFile(settings.PrivacyHmacKeyFile);
            verified = ManagedPrivacyProfileCache.Verify(
                document,
                settings.CollectorId,
                ManagedPrivacyProfileCache.ReadTrustedKeys(settings),
                key,
                settings.PrivacyHmacKeyId);
        }
        catch (ManagedPrivacyProfileException exception)
        {
            LogRejected(logger, exception.Message);
            throw;
        }

        if (string.Equals(verified.ContentHash, bundle.PrivacyProfileHash, StringComparison.Ordinal))
        {
            return;
        }

        // Only verified bytes reach the disk, and only through an atomic replace.
        ManagedPrivacyProfileCache.WriteAtomically(ManagedPrivacyProfileCache.CachePath(settings), document);
        LogStaged(logger, verified.ProfileId, verified.Version);
        RequestRestart();
    }

    private void Clear()
    {
        string path = ManagedPrivacyProfileCache.CachePath(settings);
        bool cached = File.Exists(path);
        if (!cached && bundle.PrivacyProfileHash is null)
        {
            return;
        }

        if (cached)
        {
            File.Delete(path);
        }

        LogCleared(logger);
        RequestRestart();
    }

    private void RequestRestart()
    {
        Volatile.Write(ref restartRequested, 1);
        lifetime.StopApplication();
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > ManagedPrivacyProfileCache.MaximumDocumentBytes)
        {
            throw new ManagedPrivacyProfileException("Managed privacy profile document is too large.");
        }

        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream buffer = new();
        byte[] chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > ManagedPrivacyProfileCache.MaximumDocumentBytes)
            {
                throw new ManagedPrivacyProfileException("Managed privacy profile document is too large.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    [LoggerMessage(
        EventId = 1201,
        Level = LogLevel.Warning,
        Message = "Managed privacy profile sync failed with {ExceptionType}; the current privacy profile stays active.")]
    private static partial void LogUnreachable(ILogger logger, string exceptionType);

    [LoggerMessage(
        EventId = 1202,
        Level = LogLevel.Information,
        Message = "Collector is not active in management; managed privacy profile sync skipped.")]
    private static partial void LogCollectorNotActive(ILogger logger);

    [LoggerMessage(
        EventId = 1203,
        Level = LogLevel.Warning,
        Message = "Management returned HTTP {StatusCode} for the privacy profile deployment; the current privacy profile stays active.")]
    private static partial void LogUnexpectedStatus(ILogger logger, int statusCode);

    [LoggerMessage(
        EventId = 1204,
        Level = LogLevel.Error,
        Message = "Managed privacy profile rejected: {Reason} The current privacy profile stays active.")]
    private static partial void LogRejected(ILogger logger, string reason);

    [LoggerMessage(
        EventId = 1205,
        Level = LogLevel.Warning,
        Message = "privacy profile {ProfileId}@{Version} staged; restarting to apply")]
    private static partial void LogStaged(ILogger logger, string profileId, string version);

    [LoggerMessage(
        EventId = 1206,
        Level = LogLevel.Warning,
        Message = "Managed privacy profile unassigned; cache cleared, restarting to apply the built-in default privacy profile")]
    private static partial void LogCleared(ILogger logger);
}

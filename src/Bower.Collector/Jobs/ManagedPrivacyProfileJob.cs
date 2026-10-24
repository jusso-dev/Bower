using System.Net;
using System.Net.Http.Headers;
using Azure.Core;
using Bower.Packs;
using Bower.Redaction.Privacy;

namespace Bower.Collector.Jobs;

/// <summary>
/// Management mode only (BOWER_PRIVACY_PROFILE_SOURCE=management): fetches this collector's
/// signed assignment envelope. The cache holds the last verified envelope (assigned or
/// cleared) and is the assignment-revision high-water mark:
/// <list type="bullet">
/// <item>a lower revision is rejected (rollback/replay); the same revision must sign
/// exactly the cached fields;</item>
/// <item>a higher revision is verified, written atomically and, when it changes the active
/// protection, applied by a graceful restart (exit <see cref="RestartExitCode"/> for the
/// supervisor: Docker restart policy, systemd <c>Restart=on-failure</c>);</item>
/// <item>an unsigned 204 never removes a verified cache: protection stays, the job fails;
/// without a cache 204 means never assigned (the built-in default is intended).</item>
/// </list>
/// Anything that does not verify keeps the running profile and fails the job. Metadata-only logs.
/// </summary>
public sealed partial class ManagedPrivacyProfileJob(
    IHttpClientFactory httpClientFactory,
    TokenCredential credential,
    CollectorSettings settings,
    PolicyBundle bundle,
    ManagedPrivacyProfileState state,
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
                    NoContent();
                    return;
                case HttpStatusCode.Conflict:
                    LogCollectorNotActive(logger);
                    return;
                case HttpStatusCode.OK:
                    byte[] document = await ReadBoundedAsync(response.Content, cancellationToken);
                    Apply(document);
                    return;
                default:
                    LogUnexpectedStatus(logger, (int)response.StatusCode);
                    throw new ManagedPrivacyProfileException(
                        $"Management returned HTTP {(int)response.StatusCode} for the privacy profile deployment.");
            }
        }
    }

    private void Apply(byte[] document)
    {
        VerifiedManagedPrivacyProfile? cached;
        VerifiedManagedPrivacyProfile verified;
        try
        {
            byte[]? key = settings.PrivacyHmacKeyFile is null
                ? null
                : PrivacyProfileLoader.ReadKeyFile(settings.PrivacyHmacKeyFile);
            cached = ManagedPrivacyProfileCache.LoadVerified(settings, key);
            verified = ManagedPrivacyProfileCache.Verify(
                document,
                settings.CollectorId,
                ManagedPrivacyProfileCache.ReadTrustedKeys(settings),
                key,
                settings.PrivacyHmacKeyId);
            if (cached is not null)
            {
                RequireNotOlder(verified, cached);
            }
        }
        catch (ManagedPrivacyProfileException exception)
        {
            LogRejected(logger, exception.Message);
            throw;
        }

        if (cached is not null && verified.AssignmentRevision == cached.AssignmentRevision)
        {
            return;
        }

        // Only verified bytes reach the disk, and only through an atomic replace. The new
        // envelope becomes the high-water mark even when it needs no restart.
        ManagedPrivacyProfileCache.WriteAtomically(ManagedPrivacyProfileCache.CachePath(settings), document);
        bool changesProtection = verified.IsCleared
            ? bundle.PrivacyProfileHash is not null
            : !string.Equals(verified.ContentHash, bundle.PrivacyProfileHash, StringComparison.Ordinal);
        if (!changesProtection)
        {
            state.MarkResolved(verified);
            LogRecorded(logger, verified.AssignmentRevision, verified.Action);
            return;
        }

        state.MarkRestartPending(verified);
        if (verified.IsCleared)
        {
            LogCleared(logger, verified.AssignmentRevision);
        }
        else
        {
            LogStaged(logger, verified.ProfileId!, verified.Version!);
        }

        RequestRestart();
    }

    /// <summary>Lower revisions are replays or rollbacks; the same revision must sign the same fields.</summary>
    private static void RequireNotOlder(VerifiedManagedPrivacyProfile received, VerifiedManagedPrivacyProfile cached)
    {
        if (received.AssignmentRevision < cached.AssignmentRevision)
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile assignment revision {received.AssignmentRevision} is older than the " +
                $"cached revision {cached.AssignmentRevision}.");
        }

        if (received.AssignmentRevision == cached.AssignmentRevision
            && !received.SignedPayload.AsSpan().SequenceEqual(cached.SignedPayload))
        {
            throw new ManagedPrivacyProfileException(
                $"Managed privacy profile assignment revision {received.AssignmentRevision} does not match the " +
                "cached document.");
        }
    }

    private void NoContent()
    {
        // 204 is unsigned: it can never remove verified protection. Only a signed, newer
        // "cleared" envelope returns a collector to the built-in default.
        if (File.Exists(ManagedPrivacyProfileCache.CachePath(settings)))
        {
            LogUnsignedNoContent(logger);
            throw new ManagedPrivacyProfileException(
                "Management returned 204 although a verified assignment is cached; the cached privacy " +
                "profile protection stays active.");
        }

        state.MarkNeverAssigned();
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
        Message = "Managed privacy profile assignment cleared (revision {Revision}); restarting to apply the built-in default privacy profile")]
    private static partial void LogCleared(ILogger logger, long revision);

    [LoggerMessage(
        EventId = 1207,
        Level = LogLevel.Information,
        Message = "Managed privacy profile assignment revision {Revision} ({Action}) recorded; the active protection is unchanged")]
    private static partial void LogRecorded(ILogger logger, long revision, string action);

    [LoggerMessage(
        EventId = 1208,
        Level = LogLevel.Warning,
        Message = "Management returned 204 although a verified assignment is cached; the cached privacy profile protection stays active")]
    private static partial void LogUnsignedNoContent(ILogger logger);
}

using System.Collections.Concurrent;
using System.Net;
using Azure.Core;
using Azure.Identity;
using Bower.Packs;
using Bower.Persistence;
using Bower.Source.MicrosoftCloud;

namespace Bower.Collector;

/// <summary>
/// Collector side of the Microsoft cloud source (see <see cref="PackRecordIntake"/>).
/// <see cref="MicrosoftCloudSubmitOutcome.Queued"/> means durably enqueued; only then can the
/// cursor move past the page.
/// </summary>
internal sealed class CollectorMicrosoftCloudSink(PackRecordIntake intake) : IMicrosoftCloudSink
{
    public async ValueTask<MicrosoftCloudSubmitOutcome> SubmitAsync(
        MicrosoftCloudInputOptions input,
        string record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        PackRecordOutcome outcome = await intake.SubmitAsync(
            input.Route.Pack,
            input.Route.Parser,
            $"mscloud:{input.Id}:{input.Route.Pack}:{input.Route.Parser}",
            record,
            cancellationToken);
        return outcome switch
        {
            PackRecordOutcome.Queued => MicrosoftCloudSubmitOutcome.Queued,
            PackRecordOutcome.Duplicate => MicrosoftCloudSubmitOutcome.Duplicate,
            PackRecordOutcome.Suppressed => MicrosoftCloudSubmitOutcome.Suppressed,
            PackRecordOutcome.NotSelected => MicrosoftCloudSubmitOutcome.NotSelected,
            PackRecordOutcome.Invalid => MicrosoftCloudSubmitOutcome.Invalid,
            PackRecordOutcome.TooLarge => MicrosoftCloudSubmitOutcome.TooLarge,
            PackRecordOutcome.Unavailable => MicrosoftCloudSubmitOutcome.Unavailable,
            _ => MicrosoftCloudSubmitOutcome.Rejected
        };
    }
}

internal static class MicrosoftCloudRoutes
{
    /// <summary>Every input must route to an active parser of a loaded signed pack; checked at start-up and before a signed reload.</summary>
    public static void Validate(MicrosoftCloudSourceConfiguration configuration, PolicyBundle bundle)
    {
        foreach (MicrosoftCloudInputOptions input in configuration.Inputs)
        {
            if (PackRecordIntake.Parser(bundle, input.Route.Pack, input.Route.Parser) is null)
            {
                throw new InvalidOperationException(
                    $"Microsoft cloud input {input.Id}: route pack {input.Route.Pack} parser {input.Route.Parser} is not an active parser of a loaded pack.");
            }

            if (input.Credential is { } credential && !File.Exists(credential.CertificatePath))
            {
                throw new InvalidOperationException(
                    $"Microsoft cloud input {input.Id}: credential.certificatePath does not exist.");
            }
        }
    }

    /// <summary>
    /// HTTPS only, no automatic redirects (a redirect could carry the bearer token to another
    /// host), the system proxy and trust store, bounded connection lifetime.
    /// </summary>
    public static HttpClient CreateHttpClient() =>
        new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            ConnectTimeout = TimeSpan.FromSeconds(30)
        })
        {
            Timeout = TimeSpan.FromSeconds(100)
        };
}

/// <summary>
/// Tokens from exactly one credential per input: the collector's configured Azure credential
/// (BOWER_AZURE_CREDENTIAL), or the input's certificate app registration for another tenant.
/// Azure.Identity caches tokens in memory only; nothing is written to disk or logged.
/// </summary>
internal sealed class MicrosoftCloudTokenProvider(Func<TokenCredential> collectorCredential) : IMicrosoftCloudTokenProvider
{
    private readonly ConcurrentDictionary<string, TokenCredential> credentials = new(StringComparer.Ordinal);

    public async ValueTask<string> GetTokenAsync(
        MicrosoftCloudInputOptions input,
        string scope,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (forceRefresh)
        {
            // Drop the cached credential so a refused token is never reused.
            credentials.TryRemove(input.Id, out _);
        }

        TokenCredential credential = credentials.GetOrAdd(input.Id, _ => Create(input));
        AccessToken token = await credential.GetTokenAsync(
            new TokenRequestContext([scope], tenantId: input.TenantId),
            cancellationToken);
        return token.Token;
    }

    private TokenCredential Create(MicrosoftCloudInputOptions input) =>
        input.Credential is { } certificate
            ? new ClientCertificateCredential(input.TenantId, certificate.ClientId, certificate.CertificatePath)
            : collectorCredential();
}

/// <summary>Cursor table in the queue database, then the input loops; stopped first on shutdown.</summary>
internal sealed partial class MicrosoftCloudIntakeService(
    MicrosoftCloudSource source,
    MicrosoftCloudCursors cursors,
    ILogger<MicrosoftCloudIntakeService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await cursors.Store.InitializeAsync(cancellationToken);
        await source.StartAsync(cancellationToken);
        foreach (MicrosoftCloudInputStatus input in source.Snapshot())
        {
            LogPolling(logger, input.Id, input.SourceKind);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken) =>
        await source.DisposeAsync().AsTask().WaitAsync(cancellationToken);

    [LoggerMessage(EventId = 1130, Level = LogLevel.Information, Message = "Microsoft cloud input {Input} polling {Kind}.")]
    private static partial void LogPolling(ILogger logger, string input, string kind);
}

/// <summary>Test seam: an <see cref="HttpClient"/> over a fake Microsoft API. Never registered in production.</summary>
internal sealed class MicrosoftCloudHttpClient(HttpClient client)
{
    public HttpClient Client { get; } = client;
}

/// <summary>The source cursor table inside the queue database (<c>BOWER_QUEUE_PATH</c>).</summary>
internal sealed class MicrosoftCloudCursors(string queuePath)
{
    public EfSourceCursorStore Store { get; } = new(queuePath);
}

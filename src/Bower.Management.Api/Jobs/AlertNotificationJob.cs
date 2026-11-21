namespace Bower.Management.Api.Jobs;

/// <summary>
/// Evaluates active plain-language fleet alerts, skips audited mutes, deduplicates repeated
/// alerts within <see cref="AlertNotificationOptions.DedupWindow"/>, marks resolved alerts,
/// and dispatches metadata-only notifications to configured channels (Teams webhook / email).
/// </summary>
public sealed partial class AlertNotificationJob(
    ManagementStore store,
    AlertNotificationOptions options,
    IEnumerable<IAlertNotificationChannel> channels,
    TimeProvider clock,
    ILogger<AlertNotificationJob> logger)
{
    public const string Id = "alert-notifications";
    public const int RetryAttempts = 1;

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        IAlertNotificationChannel[] configuredChannels = channels.Where(channel => channel.IsConfigured).ToArray();
        HomeRecord home = await store.HomeAsync(now, cancellationToken);

        HashSet<string> activeKeys = new(StringComparer.Ordinal);
        int sent = 0;

        foreach (HomeAttention attention in home.Attention)
        {
            string dedupKey = $"{attention.Id}:{attention.State}";
            activeKeys.Add(dedupKey);

            if (attention.Muted || configuredChannels.Length == 0)
            {
                continue;
            }

            if (!await store.ShouldSendAlertNotificationAsync(dedupKey, options.DedupWindow, now, cancellationToken))
            {
                continue;
            }

            string? alertsUrl = options.ConsoleBaseUrl is null
                ? null
                : new Uri(options.ConsoleBaseUrl, "/alerts").ToString();
            AlertNotificationMessage message = new(
                dedupKey,
                attention.Id,
                attention.State,
                attention.Message,
                attention.Fix.Action,
                attention.Count,
                alertsUrl,
                now);

            bool deliveredAny = false;
            foreach (IAlertNotificationChannel channel in configuredChannels)
            {
                try
                {
                    await channel.SendAsync(message, cancellationToken);
                    deliveredAny = true;
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    LogChannelFailure(logger, channel.Name, attention.Id, exception.GetType().Name);
                }
            }

            if (deliveredAny)
            {
                await store.RecordAlertNotificationSentAsync(dedupKey, attention.Id, attention.State, now, cancellationToken);
                sent++;
            }
        }

        await store.ResolveClearedAlertNotificationsAsync(activeKeys, now, cancellationToken);
        return sent;
    }

    [LoggerMessage(
        EventId = 2110,
        Level = LogLevel.Warning,
        Message = "Alert notification channel {Channel} failed for condition {ConditionId} with {ExceptionType}.")]
    private static partial void LogChannelFailure(ILogger logger, string channel, string conditionId, string exceptionType);
}

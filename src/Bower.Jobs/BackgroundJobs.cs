using Hangfire;
using Hangfire.InMemory;
using Hangfire.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.Jobs;

/// <summary>Status of one recurring job. Metadata only: never exception text or arguments.</summary>
public sealed record BackgroundJobStatus(
    string Id,
    string Schedule,
    DateTimeOffset? LastRunAt,
    string? LastState,
    DateTimeOffset? NextRunAt);

public static class BackgroundJobServiceCollectionExtensions
{
    /// <summary>
    /// Adds a Hangfire server backed by in-memory storage. Bower's recurring jobs are
    /// idempotent maintenance and reporting tasks whose durable state lives in Bower's own
    /// stores, so scheduler state can be rebuilt on every start. No dashboard is exposed.
    /// </summary>
    public static IServiceCollection AddBowerBackgroundJobs(
        this IServiceCollection services,
        string serverName,
        int workerCount = 2)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);

        services.AddHangfire(configuration => configuration
            .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseInMemoryStorage(new InMemoryStorageOptions
            {
                MaxExpirationTime = TimeSpan.FromHours(24)
            }));
        services.AddHangfireServer(options =>
        {
            options.ServerName = serverName;
            options.WorkerCount = workerCount;
            options.SchedulePollingInterval = TimeSpan.FromSeconds(5);
            options.ShutdownTimeout = TimeSpan.FromSeconds(15);
        });
        services.AddSingleton<BackgroundJobCatalog>();
        return services;
    }
}

/// <summary>Reads recurring job state from Hangfire storage for health reporting.</summary>
public sealed class BackgroundJobCatalog(JobStorage storage)
{
    public IReadOnlyList<BackgroundJobStatus> List()
    {
        using IStorageConnection connection = storage.GetConnection();
        return connection.GetRecurringJobs()
            .OrderBy(job => job.Id, StringComparer.Ordinal)
            .Select(job => new BackgroundJobStatus(
                job.Id,
                job.Cron,
                ToUtc(job.LastExecution),
                job.LastJobState,
                ToUtc(job.NextExecution)))
            .ToArray();
    }

    public bool Exists(string id) =>
        List().Any(job => string.Equals(job.Id, id, StringComparison.Ordinal));

    private static DateTimeOffset? ToUtc(DateTime? value) =>
        value is null
            ? null
            : new DateTimeOffset(DateTime.SpecifyKind(value.Value, DateTimeKind.Utc));
}

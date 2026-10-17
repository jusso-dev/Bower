using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Bower.Jobs;

/// <summary>Status of one recurring job. Metadata only: never exception text or arguments.</summary>
public sealed record BackgroundJobStatus(
    string Id,
    string Schedule,
    DateTimeOffset? LastRunAt,
    string? LastState,
    DateTimeOffset? NextRunAt);

/// <summary>Recorded job states, reported through <see cref="BackgroundJobStatus.LastState"/>.</summary>
public static class BackgroundJobStates
{
    public const string Enqueued = "Enqueued";
    public const string Processing = "Processing";
    public const string Scheduled = "Scheduled";
    public const string Succeeded = "Succeeded";
    public const string Failed = "Failed";
}

public static class BackgroundJobServiceCollectionExtensions
{
    /// <summary>
    /// Adds Bower's in-process recurring job scheduler. Jobs are idempotent maintenance and
    /// reporting tasks whose durable state lives in Bower's own stores, so scheduler state is
    /// rebuilt on every start. Nothing is exposed over HTTP except through Bower APIs.
    /// </summary>
    public static IServiceCollection AddBowerBackgroundJobs(
        this IServiceCollection services,
        string serverName,
        int workerCount = 2)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentOutOfRangeException.ThrowIfLessThan(workerCount, 1);

        services.AddSingleton(new BackgroundJobOptions(serverName, workerCount));
        services.AddSingleton<RecurringJobRegistry>();
        services.AddSingleton<BackgroundJobCatalog>();
        services.AddHostedService<RecurringJobScheduler>();
        return services;
    }
}

/// <summary>Scheduler settings.</summary>
public sealed record BackgroundJobOptions(string ServerName, int WorkerCount)
{
    /// <summary>How often due jobs and manual triggers are picked up.</summary>
    public TimeSpan PollingInterval { get; init; } = TimeSpan.FromSeconds(1);
}

/// <summary>
/// Registered recurring jobs and their run state. A job never overlaps itself: a due or
/// triggered job that is already running waits for the current run to finish.
/// </summary>
public sealed class RecurringJobRegistry(TimeProvider? clock = null)
{
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly Lock gate = new();
    private readonly SortedDictionary<string, RecurringJob> jobs = new(StringComparer.Ordinal);

    /// <summary>
    /// Adds or replaces a recurring job. <typeparamref name="TJob"/> is resolved from a new
    /// DI scope for every run. A failed run is retried up to <paramref name="retryAttempts"/>
    /// times with a growing delay before it is recorded as failed.
    /// </summary>
    public void AddOrUpdate<TJob>(
        string id,
        Func<TJob, CancellationToken, Task> run,
        string cron,
        int retryAttempts = 0)
        where TJob : notnull
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(run);
        ArgumentOutOfRangeException.ThrowIfNegative(retryAttempts);
        CronSchedule schedule = CronSchedule.Parse(cron);

        lock (gate)
        {
            jobs.TryGetValue(id, out RecurringJob? existing);
            jobs[id] = new RecurringJob(
                id,
                schedule,
                (services, cancellationToken) => run(services.GetRequiredService<TJob>(), cancellationToken),
                retryAttempts)
            {
                NextRunAt = schedule.GetNextOccurrence(clock.GetUtcNow()),
                LastRunAt = existing?.LastRunAt,
                LastState = existing?.LastState
            };
        }
    }

    /// <summary>Requests an immediate run. Returns false for an unknown job id.</summary>
    public bool Trigger(string id)
    {
        lock (gate)
        {
            if (!jobs.TryGetValue(id, out RecurringJob? job))
            {
                return false;
            }

            job.Triggered = true;
            return true;
        }
    }

    public IReadOnlyList<BackgroundJobStatus> List()
    {
        lock (gate)
        {
            return jobs.Values
                .Select(job => new BackgroundJobStatus(
                    job.Id,
                    job.Schedule.Expression,
                    job.LastRunAt,
                    job.LastState,
                    job.NextRunAt))
                .ToArray();
        }
    }

    /// <summary>Claims every due or triggered job that is not already running.</summary>
    internal IReadOnlyList<RecurringJob> ClaimDue(DateTimeOffset now)
    {
        lock (gate)
        {
            List<RecurringJob> due = [];
            foreach (RecurringJob job in jobs.Values)
            {
                if (job.Running || (!job.Triggered && job.NextRunAt > now))
                {
                    continue;
                }

                job.Running = true;
                job.Triggered = false;
                job.LastRunAt = now;
                job.LastState = BackgroundJobStates.Enqueued;
                // Missed occurrences are coalesced into this run, never replayed.
                job.NextRunAt = job.Schedule.GetNextOccurrence(now);
                due.Add(job);
            }

            return due;
        }
    }

    internal void SetState(RecurringJob job, string state)
    {
        lock (gate)
        {
            job.LastState = state;
        }
    }

    internal void Complete(RecurringJob job, string state)
    {
        lock (gate)
        {
            job.LastState = state;
            job.Running = false;
        }
    }

    internal sealed class RecurringJob(
        string id,
        CronSchedule schedule,
        Func<IServiceProvider, CancellationToken, Task> run,
        int retryAttempts)
    {
        public string Id { get; } = id;

        public CronSchedule Schedule { get; } = schedule;

        public Func<IServiceProvider, CancellationToken, Task> Run { get; } = run;

        public int RetryAttempts { get; } = retryAttempts;

        public DateTimeOffset NextRunAt { get; set; }

        public DateTimeOffset? LastRunAt { get; set; }

        public string? LastState { get; set; }

        public bool Running { get; set; }

        public bool Triggered { get; set; }
    }
}

/// <summary>Reads recurring job state for health reporting.</summary>
public sealed class BackgroundJobCatalog(RecurringJobRegistry registry)
{
    public IReadOnlyList<BackgroundJobStatus> List() => registry.List();

    public bool Exists(string id) =>
        List().Any(job => string.Equals(job.Id, id, StringComparison.Ordinal));
}

/// <summary>
/// Runs due recurring jobs on a <see cref="PeriodicTimer"/>, at most
/// <see cref="BackgroundJobOptions.WorkerCount"/> at a time, each in its own DI scope.
/// Event delivery, acknowledgement and queue state never run here.
/// </summary>
internal sealed partial class RecurringJobScheduler(
    RecurringJobRegistry registry,
    BackgroundJobOptions options,
    IServiceScopeFactory scopes,
    ILogger<RecurringJobScheduler> logger,
    TimeProvider? clock = null) : BackgroundService
{
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly SemaphoreSlim workers = new(options.WorkerCount, options.WorkerCount);
    private readonly List<Task> running = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(options.PollingInterval, clock);
        try
        {
            do
            {
                running.RemoveAll(task => task.IsCompleted);
                foreach (RecurringJobRegistry.RecurringJob job in registry.ClaimDue(clock.GetUtcNow()))
                {
                    running.Add(RunAsync(job, stoppingToken));
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown.
        }

        await Task.WhenAll(running);
    }

    public override void Dispose()
    {
        workers.Dispose();
        base.Dispose();
    }

    private async Task RunAsync(RecurringJobRegistry.RecurringJob job, CancellationToken stoppingToken)
    {
        await Task.Yield();
        string state = BackgroundJobStates.Failed;
        bool acquired = false;
        try
        {
            await workers.WaitAsync(stoppingToken);
            acquired = true;
            for (int attempt = 0; ; attempt++)
            {
                registry.SetState(job, BackgroundJobStates.Processing);
                try
                {
                    await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                    await job.Run(scope.ServiceProvider, stoppingToken);
                    state = BackgroundJobStates.Succeeded;
                    return;
                }
                catch (Exception exception) when (exception is not OperationCanceledException
                    || !stoppingToken.IsCancellationRequested)
                {
                    // Exception type only: job exceptions can carry paths or remote detail.
                    LogJobFailed(logger, job.Id, attempt + 1, exception.GetType().Name);
                    if (attempt >= job.RetryAttempts)
                    {
                        return;
                    }
                }

                registry.SetState(job, BackgroundJobStates.Scheduled);
                await Task.Delay(RetryDelay(attempt + 1), clock, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown: the next start reschedules the job.
        }
        finally
        {
            if (acquired)
            {
                workers.Release();
            }

            registry.Complete(job, state);
        }
    }

    /// <summary>15 s, 30 s, 60 s ... capped at 10 minutes.</summary>
    internal static TimeSpan RetryDelay(int retry) =>
        TimeSpan.FromSeconds(Math.Min(600, 15 * Math.Pow(2, retry - 1)));

    [LoggerMessage(
        EventId = 3001,
        Level = LogLevel.Warning,
        Message = "Background job {JobId} attempt {Attempt} failed with {ExceptionType}.")]
    private static partial void LogJobFailed(ILogger logger, string jobId, int attempt, string exceptionType);
}

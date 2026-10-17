using Bower.Jobs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bower.UnitTests;

public sealed class BackgroundJobsTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 26, 2, 14, 19, TimeSpan.Zero);
    private static readonly string[] OrderedIds = ["a-job", "b-job"];

    [Theory]
    [InlineData("* * * * *", "2026-07-26T02:15:00Z")]
    [InlineData("0 * * * *", "2026-07-26T03:00:00Z")]
    [InlineData("0 3 * * *", "2026-07-26T03:00:00Z")]
    [InlineData("0 2 * * *", "2026-07-27T02:00:00Z")]
    [InlineData("*/5 * * * *", "2026-07-26T02:15:00Z")]
    [InlineData("10-20/5 * * * *", "2026-07-26T02:15:00Z")]
    [InlineData("0 0 1 * *", "2026-08-01T00:00:00Z")]
    [InlineData("0 0 29 2 *", "2028-02-29T00:00:00Z")]
    [InlineData("0 0 * * 0", "2026-08-02T00:00:00Z")]
    [InlineData("0 0 * * 7", "2026-08-02T00:00:00Z")]
    // Both day fields restricted: either matches (standard cron). 2026-07-31 is a Friday.
    [InlineData("0 0 13 * 5", "2026-07-31T00:00:00Z")]
    public void Cron_FindsTheNextUtcOccurrence(string expression, string expected)
    {
        CronSchedule schedule = CronSchedule.Parse(expression);

        Assert.Equal(DateTimeOffset.Parse(expected, System.Globalization.CultureInfo.InvariantCulture), schedule.GetNextOccurrence(Start));
        Assert.Equal(expression, schedule.Expression);
    }

    [Fact]
    public void Cron_NextOccurrenceIsStrictlyLater()
    {
        CronSchedule hourly = CronSchedule.Parse(Cron.Hourly());
        DateTimeOffset onTheHour = new(2026, 7, 26, 3, 0, 0, TimeSpan.Zero);

        Assert.Equal(onTheHour.AddHours(1), hourly.GetNextOccurrence(onTheHour));
        Assert.Equal("0 * * * *", Cron.Hourly());
        Assert.Equal("0 3 * * *", Cron.Daily(3));
        Assert.Equal("* * * * *", Cron.Minutely());
    }

    [Theory]
    [InlineData("* * * *")]
    [InlineData("* * * * * *")]
    [InlineData("60 * * * *")]
    [InlineData("* 24 * * *")]
    [InlineData("* * 0 * *")]
    [InlineData("* * * 13 *")]
    [InlineData("* * * * 8")]
    [InlineData("20-10 * * * *")]
    [InlineData("*/0 * * * *")]
    [InlineData("0 0 * JAN *")]
    [InlineData("-1 * * * *")]
    public void Cron_RejectsInvalidExpressions(string expression)
    {
        Assert.Throws<FormatException>(() => CronSchedule.Parse(expression));
    }

    [Fact]
    public void Cron_RejectsAnExpressionThatNeverMatches()
    {
        CronSchedule never = CronSchedule.Parse("0 0 31 2 *");

        Assert.Throws<InvalidOperationException>(() => never.GetNextOccurrence(Start));
    }

    [Fact]
    public void Registry_ClaimsDueJobsOnceAndCoalescesMissedRuns()
    {
        FakeClock clock = new(Start);
        RecurringJobRegistry registry = new(clock);
        registry.AddOrUpdate<object>("hourly", (_, _) => Task.CompletedTask, Cron.Hourly(), retryAttempts: 2);

        BackgroundJobStatus scheduled = Assert.Single(registry.List());
        Assert.Equal(new DateTimeOffset(2026, 7, 26, 3, 0, 0, TimeSpan.Zero), scheduled.NextRunAt);
        Assert.Null(scheduled.LastRunAt);
        Assert.Empty(registry.ClaimDue(clock.GetUtcNow()));

        // Three hours pass (for example the process was suspended): one run, not three.
        clock.Advance(TimeSpan.FromHours(3));
        RecurringJobRegistry.RecurringJob job = Assert.Single(registry.ClaimDue(clock.GetUtcNow()));
        Assert.Equal(2, job.RetryAttempts);
        Assert.Equal(new DateTimeOffset(2026, 7, 26, 6, 0, 0, TimeSpan.Zero), job.NextRunAt);

        // A job never overlaps itself: still running, so it is not claimed again.
        clock.Advance(TimeSpan.FromHours(1));
        Assert.Empty(registry.ClaimDue(clock.GetUtcNow()));

        registry.Complete(job, BackgroundJobStates.Succeeded);
        Assert.Single(registry.ClaimDue(clock.GetUtcNow()));
        Assert.Equal(BackgroundJobStates.Enqueued, Assert.Single(registry.List()).LastState);
    }

    [Fact]
    public void Registry_TriggersKnownJobsOnly()
    {
        FakeClock clock = new(Start);
        RecurringJobRegistry registry = new(clock);
        registry.AddOrUpdate<object>("b-job", (_, _) => Task.CompletedTask, Cron.Daily(2));
        registry.AddOrUpdate<object>("a-job", (_, _) => Task.CompletedTask, "*/5 * * * *");

        Assert.False(registry.Trigger("missing"));
        Assert.True(registry.Trigger("b-job"));
        RecurringJobRegistry.RecurringJob job = Assert.Single(registry.ClaimDue(clock.GetUtcNow()));

        Assert.Equal("b-job", job.Id);
        Assert.Equal(OrderedIds, registry.List().Select(item => item.Id));
        Assert.True(new BackgroundJobCatalog(registry).Exists("a-job"));
        Assert.False(new BackgroundJobCatalog(registry).Exists("A-JOB"));
    }

    [Fact]
    public void Registry_RejectsInvalidRegistrations()
    {
        RecurringJobRegistry registry = new();

        Assert.Throws<FormatException>(() => registry.AddOrUpdate<object>("bad", (_, _) => Task.CompletedTask, "nope"));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            registry.AddOrUpdate<object>("bad", (_, _) => Task.CompletedTask, Cron.Hourly(), retryAttempts: -1));
        Assert.Empty(registry.List());
    }

    [Theory]
    [InlineData(1, 15)]
    [InlineData(2, 30)]
    [InlineData(3, 60)]
    [InlineData(6, 480)]
    [InlineData(7, 600)]
    [InlineData(20, 600)]
    public void Scheduler_RetryDelayGrowsAndIsCapped(int retry, int seconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(seconds), RecurringJobScheduler.RetryDelay(retry));
    }

    [Fact]
    public async Task Scheduler_RunsTriggeredJobsInAScopeAndRecordsOutcomeOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        ServiceCollection services = new();
        RunCounter counter = new();
        services.AddSingleton(counter);
        services.AddScoped<CountingJob>();
        services.AddScoped<FailingJob>();
        await using ServiceProvider provider = services.BuildServiceProvider();
        RecurringJobRegistry registry = new();
        registry.AddOrUpdate<CountingJob>("counting", (job, token) => job.RunAsync(token), Cron.Daily(2));
        registry.AddOrUpdate<FailingJob>("failing", (job, token) => job.RunAsync(token), Cron.Daily(2));
        using RecurringJobScheduler scheduler = new(
            registry,
            new BackgroundJobOptions("test", 2) { PollingInterval = TimeSpan.FromMilliseconds(20) },
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<RecurringJobScheduler>.Instance);

        await scheduler.StartAsync(cancellationToken);
        Assert.True(registry.Trigger("counting"));
        Assert.True(registry.Trigger("failing"));
        await WaitForAsync(
            () => registry.List().All(job => job.LastState is BackgroundJobStates.Succeeded or BackgroundJobStates.Failed),
            cancellationToken);
        await scheduler.StopAsync(cancellationToken);

        Dictionary<string, BackgroundJobStatus> jobs = registry.List().ToDictionary(job => job.Id, StringComparer.Ordinal);
        Assert.Equal(BackgroundJobStates.Succeeded, jobs["counting"].LastState);
        Assert.Equal(BackgroundJobStates.Failed, jobs["failing"].LastState);
        Assert.NotNull(jobs["failing"].LastRunAt);
        Assert.Equal(1, counter.Runs);
    }

    private static async Task WaitForAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        while (!condition())
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10), timeout.Token);
        }
    }

    private sealed class RunCounter
    {
        private int runs;

        public int Runs => Volatile.Read(ref runs);

        public void Increment() => Interlocked.Increment(ref runs);
    }

    private sealed class CountingJob(RunCounter counter)
    {
        public Task RunAsync(CancellationToken cancellationToken)
        {
            counter.Increment();
            return Task.CompletedTask;
        }
    }

    private sealed class FailingJob
    {
        private readonly string detail = "secret-detail-never-reported";

        public Task RunAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException(detail);
    }
}

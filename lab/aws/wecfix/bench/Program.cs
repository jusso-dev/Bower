// Per-poll cost of the Windows Event Log reader against a real channel (wecfix).
// Metadata only: counts, record positions and timings. Never renders or prints event content.
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Persistence;
using Bower.Source.WindowsEventLog;
using Microsoft.Data.Sqlite;

[assembly: SupportedOSPlatform("windows")]

string mode = args.Length > 0 ? args[0] : "help";
string Option(string name, string fallback)
{
    int index = Array.IndexOf(args, "--" + name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
}

string channel = Option("channel", "ForwardedEvents");
int[] ids = [.. Option("event-ids", "4625").Split(',').Select(id => int.Parse(id, CultureInfo.InvariantCulture))];
string[] providers = Option("providers", "Microsoft-Windows-Security-Auditing").Split(',', StringSplitOptions.RemoveEmptyEntries);
int polls = int.Parse(Option("polls", "10"), CultureInfo.InvariantCulture);
int servicePid = int.Parse(Option("service-pid", "0"), CultureInfo.InvariantCulture);
int batch = int.Parse(Option("batch", "256"), CultureInfo.InvariantCulture);
WindowsEventQuery Query(long after) => new(channel, ids, providers, after);

JsonObject Info()
{
    using EventLogSession session = new();
    EventLogInformation info = session.GetLogInformation(channel, PathType.LogName);
    using IWindowsEventChannel probe = new WindowsEventLogChannelFactory().Open(channel);
    WindowsChannelRange range = probe.GetRange();
    return new JsonObject
    {
        ["channel"] = channel,
        ["recordCount"] = info.RecordCount,
        ["fileSize"] = info.FileSize,
        ["oldestRecordNumber"] = info.OldestRecordNumber,
        ["isLogFull"] = info.IsLogFull,
        ["oldestPosition"] = range.OldestRecordId,
        ["newestPosition"] = range.NewestRecordId
    };
}

(double Wall, double Client, double Service) Measure(Action action)
{
    using Process self = Process.GetCurrentProcess();
    Process? service = servicePid > 0 ? Process.GetProcessById(servicePid) : null;
    self.Refresh();
    TimeSpan client = self.TotalProcessorTime;
    TimeSpan svc = service?.TotalProcessorTime ?? TimeSpan.Zero;
    long started = Stopwatch.GetTimestamp();
    action();
    double wall = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
    self.Refresh();
    service?.Refresh();
    double clientMs = (self.TotalProcessorTime - client).TotalMilliseconds;
    double serviceMs = service is null ? -1 : (service.TotalProcessorTime - svc).TotalMilliseconds;
    service?.Dispose();
    return (wall, clientMs, serviceMs);
}

JsonObject Series(string name, Func<int> poll)
{
    List<(double Wall, double Client, double Service)> samples = [];
    long returned = 0;
    for (int i = 0; i < polls; i++)
    {
        int count = 0;
        samples.Add(Measure(() => count = poll()));
        returned += count;
    }

    static double Median(IEnumerable<double> values)
    {
        double[] sorted = [.. values.Order()];
        return sorted.Length == 0 ? 0 : sorted[sorted.Length / 2];
    }

    return new JsonObject
    {
        ["strategy"] = name,
        ["polls"] = polls,
        ["eventsReturned"] = returned,
        ["wallMsMedian"] = Math.Round(Median(samples.Select(s => s.Wall)), 3),
        ["wallMsMax"] = Math.Round(samples.Max(s => s.Wall), 3),
        ["clientCpuMsMedian"] = Math.Round(Median(samples.Select(s => s.Client)), 3),
        ["clientCpuMsTotal"] = Math.Round(samples.Sum(s => s.Client), 3),
        ["serviceCpuMsMedian"] = Math.Round(Median(samples.Select(s => s.Service)), 3),
        ["serviceCpuMsTotal"] = Math.Round(samples.Sum(s => s.Service), 3)
    };
}

long Newest()
{
    using IWindowsEventChannel probe = new WindowsEventLogChannelFactory().Open(channel);
    return probe.GetRange().NewestRecordId;
}

int Drain(EventLogReader reader, int maximum)
{
    int count = 0;
    while (count < maximum)
    {
        using EventRecord? record = reader.ReadEvent();
        if (record is null)
        {
            break;
        }

        count++;
    }

    return count;
}

int SeekRead(string xpath, long after, int maximum)
{
    using EventLogSession session = new();
    EventLogQuery query = new(channel, PathType.LogName, xpath) { Session = session, TolerateQueryErrors = false };
    EventBookmark? bookmark = after == 0 ? null : new EventBookmark(WindowsNativeBookmark.Create(channel, after));
    using EventLogReader reader = new(query, bookmark) { BatchSize = Math.Clamp(maximum, 1, 512) };
    return Drain(reader, maximum);
}

switch (mode)
{
    case "info":
        Console.WriteLine(Info().ToJsonString());
        break;
    case "profile":
    {
        // Steady state of the soak: the bookmark is at (or just behind) the newest record.
        string filtered = Query(0).ToXPath(includeRecordPosition: false);
        JsonArray results = [];
        JsonObject output = new() { ["info"] = Info(), ["xpath"] = filtered, ["results"] = results };
        long newest = Newest();
        using IWindowsEventChannel legacy = new WindowsEventLogChannelFactory().Open(channel);
        results.Add(Series("range-only (2 boundary queries)", () => { legacy.GetRange(); return 0; }));
        results.Add(Series("filtered query + seek to newest", () => SeekRead(filtered, newest, batch)));
        results.Add(Series("unfiltered query + seek to newest", () => SeekRead("*", newest, batch)));
        results.Add(Series("filtered query, no seek, first record", () => SeekRead(filtered, 0, 1)));
        results.Add(Series("filtered query + seek to oldest + 1", () => SeekRead(filtered, Math.Max(1, legacy.GetRange().OldestRecordId), 1)));
        results.Add(Series("channel.GetRange + channel.Read at newest (one poll)", () =>
        {
            long position = legacy.GetRange().NewestRecordId;
            return legacy.Read(Query(position), batch, includeMessage: false, CancellationToken.None).Count;
        }));
        Console.WriteLine(output.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        break;
    }

    case "continue":
    {
        // Does a long-lived reader return records appended after it reached the end, and
        // what does resuming cost? --after-eof none|current|bookmark.
        string filtered = Query(0).ToXPath(includeRecordPosition: false);
        string resume = Option("after-eof", "none");
        long newest = Newest();
        using EventLogSession session = new();
        EventLogQuery query = new(channel, PathType.LogName, filtered) { Session = session };
        using EventLogReader reader = new(query, new EventBookmark(WindowsNativeBookmark.Create(channel, newest))) { BatchSize = Math.Min(batch, 512) };
        JsonArray rounds = [];
        int wait = int.Parse(Option("wait-ms", "3000"), CultureInfo.InvariantCulture);
        EventBookmark? last = null;
        long lastPosition = newest;
        bool eof = false;
        for (int i = 0; i < polls; i++)
        {
            string outcome = "ok";
            int count = 0, stale = 0;
            (double Wall, double Client, double Service) m = (0, 0, 0);
            try
            {
                m = Measure(() =>
                {
                    if (eof && resume == "current")
                    {
                        reader.Seek(SeekOrigin.Current, 0);
                    }
                    else if (eof && resume == "bookmark")
                    {
                        reader.Seek(last ?? new EventBookmark(WindowsNativeBookmark.Create(channel, lastPosition)), 1);
                    }

                    eof = false;
                    while (count < batch)
                    {
                        using EventRecord? record = reader.ReadEvent();
                        if (record is null)
                        {
                            eof = true;
                            break;
                        }

                        long position = WindowsNativeBookmark.Position(record.Bookmark.BookmarkXml, channel);
                        if (position <= lastPosition)
                        {
                            stale++;
                            continue;
                        }

                        lastPosition = position;
                        last = record.Bookmark;
                        count++;
                    }
                });
            }
            catch (Exception exception)
            {
                // Windows error code only; never the message text.
                outcome = exception.GetType().Name + ":0x" + exception.HResult.ToString("x8", CultureInfo.InvariantCulture);
            }

            rounds.Add(new JsonObject
            {
                ["round"] = i,
                ["outcome"] = outcome,
                ["returned"] = count,
                ["staleOrRepeated"] = stale,
                ["eof"] = eof,
                ["lastPosition"] = lastPosition,
                ["wallMs"] = Math.Round(m.Wall, 3),
                ["clientCpuMs"] = Math.Round(m.Client, 3),
                ["serviceCpuMs"] = Math.Round(m.Service, 3)
            });
            Thread.Sleep(wait);
        }

        Console.WriteLine(new JsonObject { ["afterEof"] = resume, ["info"] = Info(), ["rounds"] = rounds }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        break;
    }

    case "source":
    {
        // The product channel as the source drives it: GetRange then Read at the bookmark,
        // polled every interval for a while. Reports per-poll cost and events returned.
        int seconds = int.Parse(Option("seconds", "60"), CultureInfo.InvariantCulture);
        int interval = int.Parse(Option("interval-ms", "1000"), CultureInfo.InvariantCulture);
        using IWindowsEventChannel product = new WindowsEventLogChannelFactory().Open(channel);
        long position = product.GetRange().NewestRecordId;
        long total = 0, maxLag = 0;
        List<(double Wall, double Client, double Service)> samples = [];
        Stopwatch clock = Stopwatch.StartNew();
        while (clock.Elapsed.TotalSeconds < seconds)
        {
            int count = 0;
            samples.Add(Measure(() =>
            {
                WindowsChannelRange range = product.GetRange();
                IReadOnlyList<WindowsRawEvent> events = product.Read(Query(position), batch, includeMessage: false, CancellationToken.None);
                count = events.Count;
                if (events.Count > 0)
                {
                    position = events[^1].RecordId;
                }

                if (events.Count < batch && range.NewestRecordId > position)
                {
                    position = range.NewestRecordId;
                }

                maxLag = Math.Max(maxLag, range.NewestRecordId - position);
            }));
            total += count;
            if (interval > 0)
            {
                Thread.Sleep(interval);
            }
        }

        // Cost by tenth of the run: does a poll get dearer the more polls one session has run?
        JsonArray deciles = [];
        int size = Math.Max(1, samples.Count / 10);
        for (int start = 0; start + size <= samples.Count; start += size)
        {
            List<(double Wall, double Client, double Service)> slice = samples.GetRange(start, size);
            deciles.Add(new JsonObject
            {
                ["fromPoll"] = start,
                ["polls"] = size,
                ["wallMsMean"] = Math.Round(slice.Average(x => x.Wall), 4),
                ["clientCpuMsMean"] = Math.Round(slice.Average(x => x.Client), 4),
                ["serviceCpuMsMean"] = Math.Round(slice.Average(x => x.Service), 4)
            });
        }

        double[] cpu = [.. samples.Select(s => s.Client).Order()];
        double[] svc = [.. samples.Select(s => s.Service).Order()];
        double[] wall = [.. samples.Select(s => s.Wall).Order()];
        Console.WriteLine(new JsonObject
        {
            ["info"] = Info(),
            ["polls"] = samples.Count,
            ["eventsReturned"] = total,
            ["maxLagRecords"] = maxLag,
            ["wallMsMedian"] = Math.Round(wall[wall.Length / 2], 3),
            ["wallMsP95"] = Math.Round(wall[(int)(wall.Length * 0.95)], 3),
            ["clientCpuMsMedian"] = Math.Round(cpu[cpu.Length / 2], 3),
            ["clientCpuMsTotal"] = Math.Round(cpu.Sum(), 3),
            ["serviceCpuMsMedian"] = Math.Round(svc[svc.Length / 2], 3),
            ["serviceCpuMsTotal"] = Math.Round(svc.Sum(), 3),
            ["deciles"] = deciles
        }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        break;
    }

    case "queue":
    {
        // Per-event cost of the real queue (one enqueue, then delivery settlement in tens) as
        // the database file grows. The file is grown with an unrelated padding table, so a
        // rising cost belongs to the file size, not to the number of queue rows.
        string db = Option("db", @"C:\BowerLab\qbench\queue.db");
        int[] sizes = [.. Option("sizes-mb", "25,100,300,600,1200").Split(',').Select(x => int.Parse(x, CultureInfo.InvariantCulture))];
        int events = int.Parse(Option("events", "300"), CultureInfo.InvariantCulture);
        Directory.CreateDirectory(Path.GetDirectoryName(db)!);
        foreach (string file in new[] { db, db + "-wal", db + "-shm" })
        {
            File.Delete(file);
        }

        SqliteEventStore store = new(db, 8L << 30);
        await store.InitializeAsync();
        string padding = new('x', 4000);
        JsonArray rows = [];
        long sequence = 0;
        foreach (int target in sizes)
        {
            await using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db, Pooling = false }.ToString()))
            {
                await connection.OpenAsync();
                await using SqliteCommand command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE IF NOT EXISTS bench_padding(id INTEGER PRIMARY KEY, value TEXT NOT NULL);";
                await command.ExecuteNonQueryAsync();
                while (new FileInfo(db).Length < (long)target << 20)
                {
                    await using SqliteTransaction transaction = connection.BeginTransaction();
                    command.Transaction = transaction;
                    command.CommandText = "INSERT INTO bench_padding(value) VALUES ($v);";
                    command.Parameters.Clear();
                    command.Parameters.AddWithValue("$v", padding);
                    for (int i = 0; i < 2000; i++)
                    {
                        await command.ExecuteNonQueryAsync();
                    }

                    await transaction.CommitAsync();
                    command.Transaction = null;
                    command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                    await command.ExecuteNonQueryAsync();
                }
            }

            using Process self = Process.GetCurrentProcess();
            self.Refresh();
            TimeSpan user = self.UserProcessorTime, kernel = self.PrivilegedProcessorTime;
            long started = Stopwatch.GetTimestamp();
            for (int i = 0; i < events; i++)
            {
                string id = "bench-" + (++sequence).ToString(CultureInfo.InvariantCulture);
                string payload = "{\"eventId\":\"" + id + "\",\"pad\":\"" + padding[..1200] + "\"}";
                await store.EnqueueAsync(new QueuedEvent(id, id, payload, DateTimeOffset.UtcNow));
                if (i % 10 == 9)
                {
                    IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(10, TimeSpan.FromMinutes(1));
                    await store.MarkDeliveredBatchAsync([.. leased.Select(e => e.EventId)], "bench-ack",
                        leased.ToDictionary(e => e.EventId, e => e.LeaseToken!));
                }
            }

            double wall = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            self.Refresh();
            rows.Add(new JsonObject
            {
                ["databaseMb"] = new FileInfo(db).Length >> 20,
                ["events"] = events,
                ["wallMsPerEvent"] = Math.Round(wall / events, 3),
                ["userCpuMsPerEvent"] = Math.Round((self.UserProcessorTime - user).TotalMilliseconds / events, 3),
                ["kernelCpuMsPerEvent"] = Math.Round((self.PrivilegedProcessorTime - kernel).TotalMilliseconds / events, 3)
            });
        }

        SqliteConnection.ClearAllPools();
        Console.WriteLine(new JsonObject { ["rows"] = rows }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        break;
    }

    case "rows":
    {
        // Per-event enqueue cost as acknowledged (retained) rows grow, the soak's saw-tooth.
        // Also prints SQLite's plan for the ledger head lookup every enqueue runs.
        string db = Option("db", Path.Combine(Path.GetTempPath(), "bower-wecfix-rows", "queue.db"));
        int[] sizes = [.. Option("rows", "1000,25000,50000,100000").Split(',').Select(x => int.Parse(x, CultureInfo.InvariantCulture))];
        int events = int.Parse(Option("events", "200"), CultureInfo.InvariantCulture);
        Directory.CreateDirectory(Path.GetDirectoryName(db)!);
        foreach (string file in new[] { db, db + "-wal", db + "-shm" })
        {
            File.Delete(file);
        }

        SqliteEventStore store = new(db, 8L << 30);
        await store.InitializeAsync();
        string pad = new('x', 1200);
        long sequence = 0;
        async Task EnqueueDeliver(int count)
        {
            for (int i = 0; i < count; i++)
            {
                string id = "rows-" + (++sequence).ToString(CultureInfo.InvariantCulture);
                await store.EnqueueAsync(new QueuedEvent(id, id, "{\"eventId\":\"" + id + "\",\"pad\":\"" + pad + "\"}", DateTimeOffset.UtcNow));
                if (sequence % 100 == 0)
                {
                    IReadOnlyList<QueuedEvent> leased = await store.LeaseAsync(100, TimeSpan.FromMinutes(1));
                    await store.MarkDeliveredBatchAsync([.. leased.Select(e => e.EventId)], "ack", leased.ToDictionary(e => e.EventId, e => e.LeaseToken!));
                }
            }
        }

        JsonArray rows = [];
        string plan = "";
        foreach (int target in sizes)
        {
            await EnqueueDeliver((int)Math.Max(0, target - sequence));
            using Process self = Process.GetCurrentProcess();
            self.Refresh();
            TimeSpan cpu = self.TotalProcessorTime;
            long started = Stopwatch.GetTimestamp();
            await EnqueueDeliver(events);
            double wall = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            self.Refresh();
            await using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db, Pooling = false }.ToString()))
            {
                await connection.OpenAsync();
                await using SqliteCommand command = connection.CreateCommand();
                command.CommandText = "EXPLAIN QUERY PLAN SELECT sequence, chain_hash FROM (SELECT sequence, chain_hash FROM queue_ledger UNION ALL SELECT end_sequence, chain_hash FROM queue_ledger_segments) ORDER BY sequence DESC LIMIT 1;";
                await using SqliteDataReader reader = await command.ExecuteReaderAsync();
                List<string> steps = [];
                while (await reader.ReadAsync())
                {
                    steps.Add(reader.GetString(3));
                }

                plan = string.Join(" | ", steps);
                await reader.DisposeAsync();
                command.CommandText = "SELECT count(*) FROM queue_ledger;";
                long ledger = (long)(await command.ExecuteScalarAsync())!;
                rows.Add(new JsonObject
                {
                    ["retainedRows"] = sequence,
                    ["ledgerRows"] = ledger,
                    ["events"] = events,
                    ["wallMsPerEvent"] = Math.Round(wall / events, 3),
                    ["cpuMsPerEvent"] = Math.Round((self.TotalProcessorTime - cpu).TotalMilliseconds / events, 3)
                });
            }
        }

        SqliteConnection.ClearAllPools();
        Console.WriteLine(new JsonObject { ["sqlite"] = SqliteVersion(), ["headPlan"] = plan, ["rows"] = rows }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        break;
    }

    default:
        Console.Error.WriteLine("usage: bench info|profile|continue|source [--channel C] [--event-ids 4625] [--providers P] [--polls N] [--service-pid PID]");
        return 2;
}

return 0;

static string SqliteVersion()
{
    using SqliteConnection connection = new("Data Source=:memory:");
    connection.Open();
    using SqliteCommand command = connection.CreateCommand();
    command.CommandText = "SELECT sqlite_version();";
    return (string)command.ExecuteScalar()!;
}

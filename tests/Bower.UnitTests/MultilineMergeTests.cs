using System.Text;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.Persistence;
using Bower.Pipeline;
using Bower.Redaction.Privacy;
using Bower.Source.File;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>
/// Multi-line merge (#95): bounded start/continuation rules in parsers, merge before redaction
/// (catching secrets split across lines), Java/.NET stack trace pack samples, preview support
/// and crash-safe durable cursor handling in the file tail source.
/// </summary>
public sealed class MultilineMergeTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 11, 22, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public void StartMode_MergesJavaStackTraceIntoOneRecord()
    {
        CustomLogMultilineRule rule = new(
            MultilineMode.Start,
            @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
            MaxLines: 32,
            MaxBytes: 8192,
            FlushTimeoutMilliseconds: 1000);

        string[] lines =
        [
            "2026-11-22T01:00:00Z ERROR AuthService login failed for user=alice@example.test",
            "java.lang.SecurityException: invalid credentials",
            "\tat com.example.auth.AuthService.verify(AuthService.java:84)",
            "Caused by: javax.crypto.BadPaddingException: token rejected",
            "\tat com.example.auth.TokenVerifier.check(TokenVerifier.java:42)",
            "2026-11-22T01:00:01Z INFO HealthCheck status=ok"
        ];

        IReadOnlyList<MergedLineRecord> merged = MultilineLineMerger.MergeAll(rule, lines, BaseTime);

        Assert.Equal(2, merged.Count);
        Assert.Equal(1, merged[0].FirstLineNumber);
        Assert.Equal(5, merged[0].LineCount);
        Assert.Contains("java.lang.SecurityException", merged[0].Text, StringComparison.Ordinal);
        Assert.Contains("TokenVerifier.java:42", merged[0].Text, StringComparison.Ordinal);
        Assert.Equal(6, merged[1].FirstLineNumber);
        Assert.Equal(1, merged[1].LineCount);
        Assert.Equal("2026-11-22T01:00:01Z INFO HealthCheck status=ok", merged[1].Text);
    }

    [Fact]
    public void ContinuationMode_MergesDotNetStackTraceIntoOneRecord()
    {
        CustomLogMultilineRule rule = new(
            MultilineMode.Continuation,
            @"^(?:\s+at\s|\s+---|\s+--->)",
            MaxLines: 32,
            MaxBytes: 8192,
            FlushTimeoutMilliseconds: 1000);

        string[] lines =
        [
            "2026-11-22T01:00:00Z ERROR System.UnauthorizedAccessException: Access denied",
            "   ---> System.Security.SecurityException: invalid session",
            "   at Contoso.Auth.SessionGuard.Validate(String id) in /src/SessionGuard.cs:line 51",
            "   --- End of inner exception stack trace ---",
            "   at Contoso.Api.LoginEndpoint.HandleAsync() in /src/LoginEndpoint.cs:line 29",
            "2026-11-22T01:00:02Z WARN RateLimiter throttled client"
        ];

        IReadOnlyList<MergedLineRecord> merged = MultilineLineMerger.MergeAll(rule, lines, BaseTime);

        Assert.Equal(2, merged.Count);
        Assert.Equal(1, merged[0].FirstLineNumber);
        Assert.Equal(5, merged[0].LineCount);
        Assert.Contains("SessionGuard.Validate", merged[0].Text, StringComparison.Ordinal);
        Assert.Contains("LoginEndpoint.HandleAsync", merged[0].Text, StringComparison.Ordinal);
        Assert.Equal(6, merged[1].FirstLineNumber);
        Assert.Equal(1, merged[1].LineCount);
    }

    [Fact]
    public void Boundaries_EnforceMaxLinesMaxBytesAndFlushTimeout()
    {
        // MaxLines boundary flushes as soon as the cap is reached.
        MultilineLineMerger lineLimited = new(new CustomLogMultilineRule(
            MultilineMode.Start, @"^START", MaxLines: 3, MaxBytes: 4096, FlushTimeoutMilliseconds: 500));

        Assert.Empty(lineLimited.AddLine("START one", BaseTime, 1));
        Assert.Empty(lineLimited.AddLine("  cont-1", BaseTime, 2));
        IReadOnlyList<MergedLineRecord> atCap = lineLimited.AddLine("  cont-2", BaseTime, 3);
        MergedLineRecord capped = Assert.Single(atCap);
        Assert.True(capped.ReachedLimit);
        Assert.Equal(3, capped.LineCount);
        Assert.False(lineLimited.HasBuffered);

        // MaxBytes boundary flushes before exceeding MaxBytes.
        MultilineLineMerger byteLimited = new(new CustomLogMultilineRule(
            MultilineMode.Start, @"^START", MaxLines: 64, MaxBytes: 256, FlushTimeoutMilliseconds: 500));
        string payloadA = "START " + new string('a', 150);
        string payloadB = "  " + new string('b', 150);
        Assert.Empty(byteLimited.AddLine(payloadA, BaseTime, 1));
        IReadOnlyList<MergedLineRecord> flushedByBytes = byteLimited.AddLine(payloadB, BaseTime, 2);
        MergedLineRecord first = Assert.Single(flushedByBytes);
        Assert.True(first.ReachedLimit);
        Assert.Equal(payloadA, first.Text);
        Assert.True(byteLimited.HasBuffered);
        Assert.Equal(payloadB, byteLimited.Flush()!.Text);

        // Timeout flush emits buffered record only once FlushTimeoutMilliseconds has elapsed.
        MultilineLineMerger timed = new(new CustomLogMultilineRule(
            MultilineMode.Start, @"^START", MaxLines: 16, MaxBytes: 4096, FlushTimeoutMilliseconds: 1000));
        Assert.Empty(timed.AddLine("START pending", BaseTime, 1));
        Assert.Empty(timed.AddLine("  frame-1", BaseTime.AddMilliseconds(200), 2));
        Assert.Null(timed.FlushExpired(BaseTime.AddMilliseconds(1199)));
        MergedLineRecord? expired = timed.FlushExpired(BaseTime.AddMilliseconds(1200));
        Assert.NotNull(expired);
        Assert.Equal(2, expired.LineCount);
        Assert.False(timed.HasBuffered);
    }

    [Fact]
    public void Validation_RejectsBacktrackingRegexAndOutOfRangeBounds()
    {
        CustomLogParserConfiguration bad = new(
            "1.0",
            CustomLogFormat.Regex,
            [new CustomLogField("message", CustomLogValueType.Text, "message", "EventMessage", true)],
            Pattern: "^(?<message>.*)$",
            Multiline: new CustomLogMultilineRule(
                MultilineMode.Start,
                "^(?=lookahead)",
                MaxLines: 1,
                MaxBytes: 10,
                FlushTimeoutMilliseconds: 10,
                JoinSeparator: "123456789"));

        IReadOnlyList<string> issues = CustomLogParser.ValidateConfiguration(bad);

        Assert.Contains(issues, issue => issue.Contains("non-backtracking", StringComparison.Ordinal));
        Assert.Contains(issues, issue => issue.Contains("maxLines", StringComparison.Ordinal));
        Assert.Contains(issues, issue => issue.Contains("maxBytes", StringComparison.Ordinal));
        Assert.Contains(issues, issue => issue.Contains("flushTimeoutMilliseconds", StringComparison.Ordinal));
        Assert.Contains(issues, issue => issue.Contains("joinSeparator", StringComparison.Ordinal));
    }

    [Fact]
    public void CustomLogParserPreview_MergesStackTraceBeforeParsingAndKeepsPrivacyFloor()
    {
        CustomLogParserConfiguration configuration = new(
            "1.0",
            CustomLogFormat.Regex,
            [
                new CustomLogField("timestamp", CustomLogValueType.DateTime, "time", "TimeGenerated", false),
                new CustomLogField("severity", CustomLogValueType.Text, "severity", "EventSeverity", false),
                new CustomLogField("message", CustomLogValueType.Text, "message", "EventMessage", true)
            ],
            Pattern: @"^(?<timestamp>\d{4}-\d{2}-\d{2}T[^\s]+)\s+(?<severity>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+(?<message>.*)$",
            Multiline: new CustomLogMultilineRule(MultilineMode.Start, @"^\d{4}-\d{2}-\d{2}T"));

        const string sample =
            """
            2026-11-22T01:00:00Z ERROR java.lang.RuntimeException: boom for user alice@example.test
            	at com.example.App.run(App.java:10)
            	at com.example.Main.main(Main.java:5)
            2026-11-22T01:00:05Z WARN System.InvalidOperationException: bad state
               at Contoso.Worker.Execute() in Worker.cs:line 42
            """;

        CustomLogPreviewResult preview = CustomLogParser.Preview(configuration, sample);

        Assert.True(preview.IsValid, string.Join(" ", preview.Issues));
        Assert.Equal(2, preview.ParsedLineCount);
        Assert.Equal(2, preview.Rows.Count);
        Assert.Equal(1, preview.Rows[0].SourceLine);
        Assert.Equal(4, preview.Rows[1].SourceLine);
        Assert.True(preview.Rows[0].Fields["message"].Redacted);
        Assert.Equal("[redacted]", preview.Rows[0].Fields["message"].Value);
    }

    [Fact]
    public void PackTester_RawLines_MergesJavaAndDotNetStackTracesAndRedactsSecretsSplitAcrossLines()
    {
        using TemporaryDirectory directory = new();
        string packSource = Path.Combine(directory.Path, "stacktrace-pack");
        Directory.CreateDirectory(Path.Combine(packSource, "policies"));
        Directory.CreateDirectory(Path.Combine(packSource, "parsers"));
        Directory.CreateDirectory(Path.Combine(packSource, "samples"));

        File.WriteAllText(Path.Combine(packSource, "pack.yaml"), """
            apiVersion: bower.security/v1
            kind: Pack
            metadata:
              id: app-stacktrace-test
              version: 1.0.0
              name: App stack traces
              description: Test pack for multiline stack traces
              owner: Security Operations
            policies:
              - policies/app-errors.yaml
            parsers:
              - parsers/app-multiline.json
            samples:
              - samples/stacktraces.jsonl
            """);

        File.WriteAllText(Path.Combine(packSource, "policies", "app-errors.yaml"), """
            apiVersion: bower.security/v1
            kind: TelemetryPolicy

            metadata:
              id: BWR-PACK-APP-STACKTRACE-AUTH
              name: Application authentication exceptions
              version: 1.0.0
              owner: Security Operations
              reviewDate: 2027-06-30

            match:
              eventCategories:
                - authentication
              eventTypes:
                - authentication_failure

            requirements:
              requiredFields:
                - timeGenerated
                - eventType
                - eventResult
                - application.name
              atLeastOne:
                - actor.username
              recommendedFields:
                - eventOutcomeReason

            decision:
              action: accept
              minimumValueScore: 50
              neverSample: true

            routing:
              profile: authentication
              destination: security-events
            """);

        // Parser merges multi-line Java/.NET stack traces via Start pattern and extracts
        // timestamp, actor and outcome reason (carrying the first exception summary line, which
        // still passes through Bower's redaction engine before persistence).
        File.WriteAllText(Path.Combine(packSource, "parsers", "app-multiline.json"), """
            {
              "version": "1.0",
              "format": "Json",
              "fields": [
                {"sourceName": "id", "type": "Text", "ocsfPath": "metadata.uid", "asimField": "EventOriginalUid", "sensitive": false},
                {"sourceName": "message", "type": "Text", "ocsfPath": "message", "asimField": "EventMessage", "sensitive": true},
                {"sourceName": "timestamp", "type": "DateTime", "ocsfPath": "time", "asimField": "TimeGenerated", "sensitive": true},
                {"sourceName": "user", "type": "Text", "ocsfPath": "actor.user.name", "asimField": "TargetUsername", "sensitive": true},
                {"sourceName": "reason", "type": "Text", "ocsfPath": "status_detail", "asimField": "EventResultDetails", "sensitive": true},
                {"sourceName": "result", "type": "Text", "ocsfPath": "status", "asimField": "EventResult", "sensitive": true}
              ],
              "multiline": {
                "mode": "Start",
                "pattern": "^\\d{4}-\\d{2}-\\d{2}T",
                "maxLines": 32,
                "maxBytes": 8192,
                "flushTimeoutMilliseconds": 1000,
                "joinSeparator": ""
              },
              "runtime": {
                "applicationName": "example-app",
                "environment": "production",
                "eventCategory": "authentication",
                "eventType": "authentication_failure",
                "eventAction": "authentication.exception",
                "eventResult": "failure",
                "transforms": [
                  ".m = regex_extract(.message, '^(?<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+) ERROR user=(?<user>[^ ]+) (?<detail>.+)$')",
                  ".timestamp = parse_timestamp(.m.ts, \"rfc3339\")",
                  ".user = .m.user",
                  ".reason = .m.detail",
                  "if .m.user != null && .timestamp != null { .result = \"failure\" } else { .result = \"ignored\" }",
                  "del(.m)"
                ],
                "match": {
                  "result": "failure"
                },
                "fields": {
                  "eventId": "id",
                  "timeGenerated": "timestamp",
                  "actor.username": "user",
                  "eventOutcomeReason": "reason"
                }
              }
            }
            """);

        // Sample 1: Java stack trace with an AWS access key split across lines 1 and 2.
        // Because multiline merge runs BEFORE redaction (with joinSeparator ""), the split key
        // reassembles to AKIAIOSFODNN7EXAMPLE and is redacted before persistence!
        // Sample 2: .NET stack trace merged into 1 event.
        File.WriteAllText(Path.Combine(packSource, "samples", "stacktraces.jsonl"),
            string.Join('\n',
                """{"name":"java stack trace merges into one event and redacts secret split across lines","parser":"app-multiline","expect":"redact-and-accept","expectEvents":1,"rawLines":["{{now}} ERROR user=svc-java java.lang.SecurityException: bad key AKIAIOSFOD","NN7EXAMPLE in header","\tat com.example.Auth.check(Auth.java:42)","Caused by: javax.security.auth.login.FailedLoginException: denied"],"mustNotContain":["AKIAIOSFODNN7EXAMPLE","AKIAIOSFOD"]}""",
                """{"name":"dotnet stack trace merges into one event","parser":"app-multiline","expect":"accept","expectEvents":1,"rawLines":["{{now}} ERROR user=svc-dotnet System.UnauthorizedAccessException: denied","   at Contoso.Auth.Check() in /src/Auth.cs:line 19","   --- End of stack trace ---"],"expectFields":{"eventType":"authentication_failure","application.name":"example-app"}}"""));

        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string built = PackArchive.Build(packSource, privatePem, directory.Path);
        LoadedPack loaded = PackArchive.Load(built, [publicPem]);

        IReadOnlyList<PackSampleResult> results = PackTester.Run(loaded, PrivacyPolicy.CreateDefault());
        Assert.Equal(2, results.Count);
        Assert.All(results, result => Assert.True(result.Passed, $"{result.Name}: {string.Join(" ", result.Problems)}"));
    }

    [Fact]
    public async Task FileTailSource_Multiline_FlushesOnTimeoutSurvivesCrashWithoutLossOrDuplicateAndHandlesBackpressure()
    {
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string logDir = Path.Combine(directory.Path, "logs");
        Directory.CreateDirectory(logDir);
        string logPath = Path.Combine(logDir, "app.log");

        // 64+ byte first line so file fingerprint is established on line 1.
        string startLine = "2026-11-22T01:00:00Z ERROR java.lang.SecurityException: authentication failed for synthetic-user";
        string frame1 = "\tat com.example.auth.AuthFilter.doFilter(AuthFilter.java:77)";
        string frame2 = "\tat com.example.auth.Chain.proceed(Chain.java:14)";
        await File.WriteAllTextAsync(logPath, $"{startLine}\n{frame1}\n{frame2}\n", cancellation);

        FileTailSourceConfiguration config = FileTailSourceConfigurationLoader.Parse(JsonSerializer.Serialize(new
        {
            apiVersion = "bower.security/v1",
            kind = "FileTailSource",
            allowedRoots = new[] { logDir },
            inputs = new[]
            {
                new
                {
                    id = "app",
                    path = logPath,
                    route = new { pack = "app-stacktrace", parser = 0 },
                    format = "text",
                    startAt = "beginning"
                }
            }
        }));

        FileTailMultilineOptions multilineRule = new(
            MatchStart: true,
            Pattern: @"^\d{4}-\d{2}-\d{2}T",
            MaxLines: 32,
            MaxBytes: 16_384,
            FlushTimeoutMilliseconds: 1_000,
            JoinSeparator: "\n");

        RecordingSink sink = new();
        string cursorDb = Path.Combine(directory.Path, "cursors.db");
        EfSourceCursorStore cursors = new(cursorDb);
        await cursors.InitializeAsync(cancellation);
        StepClock clock = new(BaseTime);

        // First run: reads the 3 lines into memory buffer, does NOT submit yet (waiting for more
        // continuation lines or timeout) and keeps durable cursor at offset 0.
        await using (FileTailSource first = new(config, sink, cursors, clock, _ => multilineRule))
        {
            FileTailPollResult poll1 = await first.PollOnceAsync("app", cancellation);
            Assert.Equal(0, poll1.Lines);
            Assert.Empty(sink.Records);
            SourceCursorSnapshot? persisted = await cursors.ReadAsync("file:app", cancellation);
            Assert.NotNull(persisted);
            Assert.Equal(0, FileTailCursor.Deserialize(persisted.Value)!.Offset);
        }

        // Simulate crash before flush: a fresh FileTailSource re-reads from offset 0, buffers the
        // same 3 lines, then flushes on timeout as ONE merged record with a stable EventId.
        await using (FileTailSource restarted = new(config, sink, cursors, clock, _ => multilineRule))
        {
            await restarted.PollOnceAsync("app", cancellation);
            Assert.Empty(sink.Records);

            // Backpressure on flush: rewind durable cursor to offset 0 and clear buffer.
            clock.Advance(TimeSpan.FromSeconds(2));
            sink.NextOutcome = FileTailSubmitOutcome.Unavailable;
            FileTailPollResult backpressured = await restarted.PollOnceAsync("app", cancellation);
            Assert.True(backpressured.Backpressure);
            Assert.Equal(0, FileTailCursor.Deserialize((await cursors.ReadAsync("file:app", cancellation))!.Value)!.Offset);

            // Queue recovers: re-read from 0, buffer, advance past timeout, flush once and commit cursor.
            sink.NextOutcome = FileTailSubmitOutcome.Queued;
            await restarted.PollOnceAsync("app", cancellation);
            clock.Advance(TimeSpan.FromSeconds(2));
            FileTailPollResult flushed = await restarted.PollOnceAsync("app", cancellation);
            Assert.Equal(3, flushed.Lines);
            string record = Assert.Single(sink.Records);
            using JsonDocument parsed = JsonDocument.Parse(record);
            string message = parsed.RootElement.GetProperty("message").GetString()!;
            Assert.Contains(startLine, message, StringComparison.Ordinal);
            Assert.Contains(frame1, message, StringComparison.Ordinal);
            Assert.Contains(frame2, message, StringComparison.Ordinal);
            Assert.Equal(new FileInfo(logPath).Length, FileTailCursor.Deserialize((await cursors.ReadAsync("file:app", cancellation))!.Value)!.Offset);
        }
    }

    private sealed class RecordingSink : IFileTailSink
    {
        public FileTailSubmitOutcome NextOutcome { get; set; } = FileTailSubmitOutcome.Queued;
        public List<string> Records { get; } = [];

        public ValueTask<FileTailSubmitOutcome> SubmitAsync(
            FileTailInputOptions input,
            string record,
            CancellationToken cancellationToken)
        {
            if (NextOutcome != FileTailSubmitOutcome.Unavailable)
            {
                Records.Add(record);
            }

            return ValueTask.FromResult(NextOutcome);
        }
    }

    private sealed class StepClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset current = start;
        public void Advance(TimeSpan delta) => current += delta;
        public override DateTimeOffset GetUtcNow() => current;
    }
}

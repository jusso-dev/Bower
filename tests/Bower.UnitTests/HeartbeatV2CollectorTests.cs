using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Integrity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Heartbeat v2 on the collector: command verification, the ledger and the heartbeat exchange.</summary>
[Collection(SerialHostTests.Name)]
public sealed class HeartbeatV2CollectorTests
{
    private const string CollectorId = "edge-01";
    private const string BearerToken = "management-bearer-token-value";
    private const string IngestToken = "collector-ingest-token-0123456789abcdef0123";
    private const string ProxyPassword = "proxy-password-value-never-sent";
    private static readonly DateTimeOffset Now = new(2026, 10, 26, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Verifier_RefusesFailClosedWithStableCodes()
    {
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        (string otherPrivate, _, _) = DetachedSigner.GenerateKeyPair();
        string[] trusted = [publicPem];

        string? Code(JsonNode document) => ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(document), CollectorId, trusted, Now).RejectionCode;

        JsonObject valid = Command(privatePem);
        ManagementCommandVerification accepted = ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(valid), CollectorId, trusted, Now);
        JsonObject tampered = Command(privatePem);
        tampered["command"] = "reload";
        JsonObject extra = Command(privatePem);
        extra["arguments"] = "/bin/sh";
        JsonObject wrongKind = Command(privatePem, kind: "bower.privacy-profile");

        Assert.Null(accepted.RejectionCode);
        Assert.Equal(ManagementCommandTypes.RunCanary, accepted.Command!.Command);
        Assert.Equal(Now.AddMinutes(15), accepted.Command.ExpiresAt);
        Assert.Equal(ManagementCommandResults.UntrustedSignature, Code(Command(otherPrivate)));
        Assert.Equal(ManagementCommandResults.UntrustedSignature, Code(tampered));
        Assert.Equal(ManagementCommandResults.WrongCollector, Code(Command(privatePem, collectorId: "edge-02")));
        Assert.Equal(ManagementCommandResults.UnknownCommand, Code(Command(privatePem, command: "exec")));
        Assert.Equal(ManagementCommandResults.NotYetValid, Code(Command(privatePem, issued: Now.AddMinutes(6))));
        Assert.Equal(ManagementCommandResults.Expired, Code(Command(privatePem, issued: Now.AddMinutes(-20), expires: Now)));
        Assert.Equal(ManagementCommandResults.InvalidLifetime, Code(Command(privatePem, expires: Now.AddMinutes(61))));
        Assert.Equal(ManagementCommandResults.InvalidLifetime,
            Code(Command(privatePem, issued: Now.AddMinutes(2), expires: Now.AddMinutes(1))));
        Assert.Equal(ManagementCommandResults.MalformedCommand, Code(extra));
        Assert.Equal(ManagementCommandResults.MalformedCommand, Code(wrongKind));
        Assert.Equal(ManagementCommandResults.MalformedCommand, Code(JsonValue.Create("run-canary")));
        Assert.Equal(ManagementCommandResults.MalformedCommand, Code(Command(privatePem, commandId: "not-a-command-id")));
        JsonObject badTime = Command(privatePem);
        badTime["issuedAt"] = "2026-10-26T00:00:00Z";
        Assert.Equal(ManagementCommandResults.MalformedCommand, Code(badTime));

        // Only a signature-verified document may name a command in the report: a tampered
        // copy of a real command must never mark that command rejected.
        Assert.Null(ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(extra), CollectorId, trusted, Now).CommandId);
        Assert.Null(ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(tampered), CollectorId, trusted, Now).CommandId);
        Assert.Null(ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(Command(otherPrivate)), CollectorId, trusted, Now).CommandId);
        Assert.Null(ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(JsonValue.Create(1)), CollectorId, trusted, Now).CommandId);
        // Signature-verified refusals still name the command so management can record them.
        Assert.Equal(new string('c', 32), ManagementCommandVerifier.Verify(
            JsonSerializer.SerializeToElement(Command(privatePem, command: "exec")), CollectorId, trusted, Now).CommandId);
        // System.Text.Json rejects a leap second; the Rust collector must too (vectors).
        JsonObject leap = Command(privatePem);
        leap["issuedAt"] = "2026-12-31T23:59:60.0000000Z";
        Assert.Equal(ManagementCommandResults.MalformedCommand, Code(leap));
    }

    [Fact]
    public async Task Heartbeat_StalledResponseBodyIsBoundedByTheExchangeTimeout()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (_, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        CollectorSettings settings = Settings(directory, publicPem);
        // Headers arrive, then the body never does (a stalled proxy or server).
        ManagementStub stub = new(request => request.RequestUri!.AbsolutePath.EndsWith("/register", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.Accepted)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StalledStream()) });
        ManagementCommandProcessor processor = new(
            settings, new ManagementCommandLedger(settings.ManagementCommandDirectory, TimeProvider.System),
            new ManagementCommandInbox(), TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ManagementCommandProcessor>.Instance);
        Bower.Persistence.SqliteEventStore store = new(settings.QueuePath, settings.MaximumQueueBytes);
        await store.InitializeAsync(ct);
        ManagementHeartbeatJob job = new(
            new SingleClientFactory(stub),
            new StaticCredential(),
            store,
            new Bower.Jobs.BackgroundJobCatalog(new Bower.Jobs.RecurringJobRegistry()),
            settings,
            Bower.Packs.PolicyBundle.Load(settings.PolicySources()),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ManagementHeartbeatJob>.Instance,
            commands: processor,
            exchangeTimeout: TimeSpan.FromMilliseconds(300));

        Task run = job.RunAsync(ct);
        Task finished = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(10), ct));

        Assert.Same(run, finished);
        // A timed-out exchange is a logged heartbeat failure, never an exception for the scheduler.
        await run;
    }

    [Fact]
    public async Task Processor_WithTrustedKeysThatAreNotP256PublicKeysAdvertisesNothingAndRefusesCommands()
    {
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        CollectorSettings valid = Settings(directory, publicPem);
        string garbage = Path.Combine(directory.Path, "garbage.pem");
        File.WriteAllText(garbage, "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n");
        string missing = Path.Combine(directory.Path, "missing.pem");

        foreach (CollectorSettings settings in new[]
        {
            valid with { ManagementCommandTrustedKeyFiles = [.. valid.ManagementCommandTrustedKeyFiles, garbage] },
            valid with { ManagementCommandTrustedKeyFiles = [missing] }
        })
        {
            ManagementCommandLedger ledger = new(
                Path.Combine(directory.Path, Guid.NewGuid().ToString("N")), TimeProvider.System);
            ManagementCommandInbox inbox = new();
            ManagementCommandProcessor processor = new(
                settings, ledger, inbox, TimeProvider.System,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<ManagementCommandProcessor>.Instance);
            JsonObject response = new()
            {
                ["schemaVersion"] = 2,
                ["commands"] = new JsonArray(Command(privatePem, issued: DateTimeOffset.UtcNow,
                    expires: DateTimeOffset.UtcNow.AddMinutes(5)))
            };

            await processor.HandleResponseAsync(
                new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json"), [],
                TestContext.Current.CancellationToken);

            Assert.Empty(processor.Capabilities);
            CommandResultReport refused = Assert.Single(ledger.PendingResults());
            Assert.Equal(ManagementCommandResults.CommandsNotConfigured, refused.Code);
        }
    }

    [Fact]
    public void Ledger_RunsEachCommandAtMostOnceAcrossRestarts()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        ManagementCommandLedger ledger = new(directory.Path, clock);
        VerifiedManagementCommand canary = Verified("1", "a");
        VerifiedManagementCommand reload = Verified("2", "b", ManagementCommandTypes.Reload);

        Assert.True(ledger.Available);
        Assert.Equal(CommandAdmission.Accepted, ledger.Admit(canary));
        Assert.Equal(CommandAdmission.Duplicate, ledger.Admit(canary));
        Assert.Equal(CommandAdmission.Rejected, ledger.Admit(canary with { Nonce = new string('9', 32) }));
        Assert.Equal(CommandAdmission.Rejected, ledger.Admit(canary with { CommandId = new string('8', 32) }));
        Assert.Equal(CommandAdmission.Accepted, ledger.Admit(reload));
        ledger.Complete(canary.CommandId, ManagementCommandResults.Succeeded, ManagementCommandResults.CanaryQueued);

        // A new process over the same directory: the unfinished reload is reported, never rerun.
        ManagementCommandLedger restarted = new(directory.Path, clock);
        IReadOnlyList<CommandResultReport> pending = restarted.PendingResults();

        Assert.Equal(CommandAdmission.Duplicate, restarted.Admit(canary));
        Assert.Equal(CommandAdmission.Duplicate, restarted.Admit(reload));
        Assert.Equal(2, pending.Count);
        Assert.Equal(ManagementCommandResults.CanaryQueued, pending.Single(item => item.CommandId == canary.CommandId).Code);
        CommandResultReport interrupted = pending.Single(item => item.CommandId == reload.CommandId);
        Assert.Equal(ManagementCommandResults.Failed, interrupted.Status);
        Assert.Equal(ManagementCommandResults.Interrupted, interrupted.Code);

        restarted.Acknowledge([canary.CommandId, reload.CommandId], pending);
        Assert.Empty(restarted.PendingResults());
        Assert.Empty(new ManagementCommandLedger(directory.Path, clock).PendingResults());

        // Acknowledged entries are pruned only after expiry; until then a replay is still a duplicate.
        Assert.Equal(CommandAdmission.Duplicate, restarted.Admit(canary));
    }

    [Fact]
    public void Ledger_RejectionsAreReportedOnceAndBounded()
    {
        using TemporaryDirectory directory = new();
        ManagementCommandLedger ledger = new(directory.Path, new FakeClock(Now));

        ledger.Reject(new string('1', 32), ManagementCommandResults.UntrustedSignature);
        ledger.Reject(new string('1', 32), ManagementCommandResults.UntrustedSignature);
        ledger.Reject(null, ManagementCommandResults.MalformedCommand);
        for (int index = 0; index < 40; index++)
        {
            ledger.Reject(null, ManagementCommandResults.MalformedCommand);
        }

        IReadOnlyList<CommandResultReport> pending = ledger.PendingResults();
        Assert.Equal(ManagementCommandLedger.MaximumReportedResults, pending.Count);
        Assert.All(pending, item => Assert.Equal(ManagementCommandResults.Rejected, item.Status));
        // Id-less rejections cannot be acknowledged: they are dropped once reported.
        ledger.Acknowledge([], pending);
        Assert.Empty(ledger.PendingResults());
        // Rejections are never written to disk: they were never executed.
        Assert.False(File.Exists(Path.Combine(directory.Path, ManagementCommandLedger.FileName)));
    }

    [Fact]
    public void Ledger_ThatCannotBeReadRefusesEveryCommand()
    {
        using TemporaryDirectory directory = new();
        File.WriteAllText(Path.Combine(directory.Path, ManagementCommandLedger.FileName), "{not json");
        ManagementCommandLedger ledger = new(directory.Path, new FakeClock(Now));

        Assert.False(ledger.Available);
        Assert.Equal(CommandAdmission.Rejected, ledger.Admit(Verified("1", "a")));
        Assert.Equal(ManagementCommandResults.LedgerUnavailable, Assert.Single(ledger.PendingResults()).Code);
    }

    [Fact]
    public void Ledger_RateLimitsReloads()
    {
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        ManagementCommandLedger ledger = new(directory.Path, clock);

        Assert.True(ledger.TryBeginReload());
        clock.Advance(TimeSpan.FromMinutes(9));
        Assert.False(new ManagementCommandLedger(directory.Path, clock).TryBeginReload());
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.True(new ManagementCommandLedger(directory.Path, clock).TryBeginReload());
    }

    [Fact]
    public async Task Heartbeat_ReportsV2MetadataRunsVerifiedCommandsAndReportsResultsNextTime()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        (string forger, _, _) = DetachedSigner.GenerateKeyPair();
        CollectorSettings settings = Settings(directory, publicPem);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string canaryId = new('c', 32);
        string forgedId = new('d', 32);
        List<string> bodies = [];
        string? acknowledge = null;
        ManagementStub stub = new(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/register", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }

            Assert.Equal($"Bearer {BearerToken}", request.Headers.Authorization!.ToString());
            string body = request.Content!.ReadAsStringAsync(ct).GetAwaiter().GetResult();
            bodies.Add(body);
            JsonArray commands = bodies.Count == 1
                ? [Command(privatePem, commandId: canaryId, issued: now, expires: now.AddMinutes(15)),
                    Command(forger, commandId: forgedId, issued: now, expires: now.AddMinutes(15))]
                : [];
            JsonArray acknowledged = acknowledge is null ? [] : [acknowledge, forgedId];
            return Json(new JsonObject
            {
                ["schemaVersion"] = 2,
                ["collectorId"] = CollectorId,
                ["status"] = "Active",
                ["commands"] = commands,
                ["acknowledgedResults"] = acknowledged
            });
        });
        await using WebApplication app = CollectorApplication.Build(
            settings,
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddHttpClient(ManagementHeartbeatJob.HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => stub);
            },
            credential: new StaticCredential());
        await CollectorApplication.InitializeAsync(app, ct);
        await app.StartAsync(ct);
        ManagementCommandLedger ledger = app.Services.GetRequiredService<ManagementCommandLedger>();

        await app.Services.GetRequiredService<ManagementHeartbeatJob>().RunAsync(ct);
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (ledger.PendingResults().Count < 2 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(25, ct);
        }

        acknowledge = canaryId;
        await app.Services.GetRequiredService<ManagementHeartbeatJob>().RunAsync(ct);
        await app.Services.GetRequiredService<ManagementHeartbeatJob>().RunAsync(ct);
        QueueSnapshot snapshot = await app.Services.GetRequiredService<IDurableEventStore>().GetSnapshotAsync(ct);

        Assert.Equal(3, bodies.Count);
        JsonObject first = JsonNode.Parse(bodies[0])!.AsObject();
        Assert.Equal(2, first["schemaVersion"]!.GetValue<int>());
        Assert.Equal(60, first["heartbeatIntervalSeconds"]!.GetValue<int>());
        Assert.Equal(["run-canary", "reload"], first["commandCapabilities"]!.AsArray().Select(item => item!.GetValue<string>()));
        Assert.Empty(first["commandResults"]!.AsArray());
        // Redaction counts by type since process start: counts only, never values.
        Assert.NotNull(first["redactions"]!["observedSince"]);
        Assert.NotNull(first["redactions"]!["counts"]!.AsArray());
        // Queue volume watermarks and queue use for fleet alerting: metadata only.
        JsonObject storage = first["storage"]!.AsObject();
        Assert.Matches("^(normal|warning|critical|unknown)$", storage["state"]!.GetValue<string>());
        Assert.Equal(settings.MaximumQueueBytes, storage["queueMaximumBytes"]!.GetValue<long>());
        Assert.True(storage["queueFileBytes"]!.GetValue<long>() > 0);
        Assert.Equal(0, storage["storageRefusals"]!.GetValue<long>());
        Assert.DoesNotContain(Path.GetDirectoryName(settings.QueuePath)!, storage.ToJsonString(), StringComparison.Ordinal);

        JsonObject second = JsonNode.Parse(bodies[1])!.AsObject();
        JsonArray results = second["commandResults"]!.AsArray();
        JsonNode canary = results.Single(item => item!["commandId"]?.GetValue<string>() == canaryId)!;
        // An unverified document never names a command id, even one it claims.
        JsonNode forged = results.Single(item => item!["commandId"] is null)!;
        Assert.DoesNotContain(forgedId, bodies[1], StringComparison.Ordinal);
        Assert.Equal("succeeded", canary["status"]!.GetValue<string>());
        Assert.Equal("canary-queued", canary["code"]!.GetValue<string>());
        Assert.Equal("rejected", forged["status"]!.GetValue<string>());
        Assert.Equal("untrusted-signature", forged["code"]!.GetValue<string>());
        Assert.Equal("queued", second["lastCanary"]!["outcome"]!.GetValue<string>());
        Assert.Equal(canaryId, second["lastCanary"]!["commandId"]!.GetValue<string>());
        // The canary went through the normal pipeline into the durable queue.
        Assert.Equal(1, snapshot.Queued + snapshot.Uploading + snapshot.Retrying + snapshot.Delivered);

        // Acknowledged results are not sent again; the canary stays as the last result.
        JsonObject third = JsonNode.Parse(bodies[2])!.AsObject();
        Assert.Empty(third["commandResults"]!.AsArray());
        Assert.Equal("queued", third["lastCanary"]!["outcome"]!.GetValue<string>());

        // Metadata only: no bearer token, ingest token or proxy password in any payload.
        Assert.All(bodies, body =>
        {
            Assert.DoesNotContain(BearerToken, body, StringComparison.Ordinal);
            Assert.DoesNotContain(IngestToken, body, StringComparison.Ordinal);
            Assert.DoesNotContain(ProxyPassword, body, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Heartbeat_AgainstAV1ManagementApiTakesNoCommandsAndKeepsResults()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        CollectorSettings settings = Settings(directory, publicPem);
        ManagementCommandLedger ledger = new(settings.ManagementCommandDirectory, TimeProvider.System);
        ledger.Reject(new string('e', 32), ManagementCommandResults.Expired);
        // A v1 API answers with its collector record, which happens to contain no commands.
        HttpResponseMessage Respond() => Json(new JsonObject
        {
            ["id"] = CollectorId,
            ["status"] = "Active",
            ["commands"] = new JsonArray(Command(privatePem, issued: DateTimeOffset.UtcNow,
                expires: DateTimeOffset.UtcNow.AddMinutes(5)))
        });
        ManagementStub stub = new(_ => Respond());
        ManagementCommandInbox inbox = new();
        ManagementCommandProcessor processor = new(
            settings, ledger, inbox, TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ManagementCommandProcessor>.Instance);
        Bower.Persistence.SqliteEventStore store = new(settings.QueuePath, settings.MaximumQueueBytes);
        await store.InitializeAsync(ct);
        ManagementHeartbeatJob job = new(
            new SingleClientFactory(stub),
            new StaticCredential(),
            store,
            new Bower.Jobs.BackgroundJobCatalog(new Bower.Jobs.RecurringJobRegistry()),
            settings,
            Bower.Packs.PolicyBundle.Load(settings.PolicySources()),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ManagementHeartbeatJob>.Instance,
            commands: processor);

        await job.RunAsync(ct);

        // No schemaVersion 2: nothing is admitted and the pending result is kept for a v2 API.
        Assert.Equal(ManagementCommandResults.Expired, Assert.Single(ledger.PendingResults()).Code);
        Assert.Equal(2, stub.Requests);
    }

    internal static JsonObject Command(
        string privatePem,
        string collectorId = CollectorId,
        string command = ManagementCommandTypes.RunCanary,
        string? commandId = null,
        DateTimeOffset? issued = null,
        DateTimeOffset? expires = null,
        string kind = ManagementCommandVerifier.Kind)
    {
        string id = commandId ?? new string('c', 32);
        string nonce = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        string issuedAt = ManagementCommandVerifier.FormatTimestamp(issued ?? Now);
        string expiresAt = ManagementCommandVerifier.FormatTimestamp(expires ?? (issued ?? Now).AddMinutes(15));
        DetachedSignature signature = DetachedSigner.Sign(
            ManagementCommandVerifier.SignedBytes(id, collectorId, command, nonce, issuedAt, expiresAt), privatePem);
        return new JsonObject
        {
            ["kind"] = kind,
            ["commandId"] = id,
            ["collectorId"] = collectorId,
            ["command"] = command,
            ["nonce"] = nonce,
            ["issuedAt"] = issuedAt,
            ["expiresAt"] = expiresAt,
            ["signature"] = new JsonObject
            {
                ["algorithm"] = signature.Algorithm,
                ["keyId"] = signature.KeyId,
                ["value"] = signature.Value
            }
        };
    }

    private static VerifiedManagementCommand Verified(
        string id,
        string nonce,
        string command = ManagementCommandTypes.RunCanary) =>
        new(new string(id[0], 32), command, new string(nonce[0], 32), Now, Now.AddMinutes(15));

    private static CollectorSettings Settings(TemporaryDirectory directory, string publicPem)
    {
        string keyFile = Path.Combine(directory.Path, "command-trusted.pem");
        File.WriteAllText(keyFile, publicPem);
        string passwordFile = Path.Combine(directory.Path, "proxy-password");
        File.WriteAllText(passwordFile, ProxyPassword + "\n");
        return new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "data", "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = CollectorId,
            IngestToken = IngestToken,
            SingleTrustDomain = true,
            // Discard port: a scheduled run during a test fails fast without a real server.
            ManagementEndpoint = new Uri("http://127.0.0.1:9"),
            ManagementScope = "api://bower/.default",
            ManagementProxy = new Uri("http://proxy.example.test:3128"),
            ManagementProxyUsername = "bower",
            ManagementProxyPasswordFile = passwordFile,
            ManagementCommandTrustedKeyFiles = [keyFile]
        };
    }

    private static HttpResponseMessage Json(JsonNode body) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };

    /// <summary>A response body whose reads never complete until cancelled.</summary>
    private sealed class StalledStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ManagementStub(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        private int requests;

        public int Requests => Volatile.Read(ref requests);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref requests);
            return Task.FromResult(respond(request));
        }
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://management.example.test/") };
    }

    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new(BearerToken, DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}

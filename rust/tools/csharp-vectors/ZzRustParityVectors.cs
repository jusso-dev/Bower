// TEMPORARY: emits parity vectors for the Rust port. Delete after use.
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Integrity;
using Bower.Output.AzureLogsIngestion;

namespace Bower.UnitTests;

public sealed class ZzRustParityVectors
{
    private const string OutputPath = "/tmp/claude-501/bower-rust-vectors.txt";
    private static readonly StringBuilder Output = new();

    private static void Emit(string key, string value) =>
        Output.Append(key).Append('\t').Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(value))).Append('\n');

    private const string RustPrivate = """
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg23+RoI8wdZpEuQxq
        BS2R37f10hGZVz0F4fH3fikntdihRANCAAR/kJ0mdJM1XRHGYshFVYdrnSMHoNyu
        IF2FBPSRZhWxim7E3ZxEjmz2CobxqIeiQWf7Y9RzhHBFrp08Z8k6y2cC
        -----END PRIVATE KEY-----
        """;

    private const string RustPublic = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf5CdJnSTNV0RxmLIRVWHa50jB6Dc
        riBdhQT0kWYVsYpuxN2cRI5s9gqG8aiHokFn+2PUc4RwRa6dPGfJOstnAg==
        -----END PUBLIC KEY-----
        """;

    private const string RustSignature =
        "iYnVWOtjujDtde8bet7iVwWN3GgygWzGsTl6LVl4p4Su0jZwesICsq3yh0VwiZzi1uMkCIw+7G5T3+Nhr3817g==";

    [Fact]
    public async Task Emit_All()
    {
        Integrity();
        Fingerprints();
        Processor();
        await Azure();
        File.WriteAllText(OutputPath, Output.ToString());
    }

    private static void Integrity()
    {
        string source = """{"b":1.50,"a":{"d":[1,{"z":-0,"y":1e5}],"c":"x<>&'+`\"\\\n\u0001é😀"},"":true,"😀":null,"A":[],"aa":{},"big":123456789012345678901234567890,"neg":-1.25E-7}""";
        Emit("canonical.source", source);
        Emit("canonical.text", CanonicalJson.Text(JsonNode.Parse(source)));

        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        Emit("cs.private", privatePem);
        Emit("cs.public", publicPem);
        Emit("cs.keyid", keyId);
        byte[] content = Encoding.UTF8.GetBytes("bower evidence");
        for (int i = 0; i < 8; i++)
        {
            Emit($"cs.sig.{i}", DetachedSigner.Sign(content, privatePem).Value);
        }

        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(privatePem);
        string sec1 = key.ExportECPrivateKeyPem();
        Emit("cs.sec1", sec1);
        Emit("cs.sec1.sig", DetachedSigner.Sign(content, sec1).Value);

        Emit("rust.verify", DetachedSigner.Verify(
            content,
            new DetachedSignature("ES256", "67a22e085bcb0ab5", RustSignature),
            [RustPublic]).ToString());
        Emit("rust.keyid", DetachedSigner.KeyIdFromPublicKeyPem(RustPublic));
        Emit("rust.keyid.fromprivate", DetachedSigner.KeyIdFromPublicKeyPem(RustPrivate));
        Emit("cs.sig.rustkey", DetachedSigner.Sign(content, RustPrivate).Value);
        Emit("sha256hex", Sha256Hex.Of("bower é"));
    }

    private static SecurityEventEnvelope Base() => TestEvents.AuthenticationFailure(TestEvents.Now);

    private static void Fingerprints()
    {
        SecurityEventEnvelope[] cases =
        [
            Base(),
            Base() with
            {
                EventOriginalId = null,
                TimeGenerated = new DateTimeOffset(2026, 7, 26, 12, 14, 19, TimeSpan.FromHours(10)).AddTicks(1234567),
                Actor = new ActorContext { UserId = "u-1", Username = "ignored" },
                Target = new TargetContext { Type = "account", Id = "acc-é" },
                EventResult = EventResult.Denied,
                Application = new ApplicationContext { Name = "App", Environment = "prod", TenantId = "tenant+1" }
            },
            Base() with { Actor = null, Target = new TargetContext { Type = "t" }, EventResult = EventResult.Unknown },
            Base() with
            {
                TimeGenerated = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.FromMinutes(-330)),
                EventResult = EventResult.Success,
                EventType = "type\u001fwith-separator"
            }
        ];
        for (int i = 0; i < cases.Length; i++)
        {
            Emit($"fp.{i}.json", JsonSerializer.Serialize(cases[i], BowerJson.Options));
            Emit($"fp.{i}.value", EventFingerprint.Create(cases[i]));
        }
    }

    private sealed class FakeRedactor(RedactionResult template) : IEventRedactor
    {
        public RedactionResult Redact(string json) => template with { RedactedJson = json };
    }

    private sealed class FakePolicy : ITelemetryPolicyEvaluator
    {
        public PolicyDecision Evaluate(SecurityEventEnvelope candidate) =>
            candidate.EventType == SecurityEventTypes.SensitiveDataDetected
                ? new PolicyDecision(DecisionAction.Accept, "BWR-POL-PRIVACY-DETECT", "1.0.0", "sha256:privacy", 80, ["privacy reason"], [])
                : candidate.EventId == "rejected"
                    ? new PolicyDecision(DecisionAction.Reject, "BWR-POL-AUTH-FAILURE", "1.0.0", "sha256:auth", 10, ["low value"], ["warn 1"])
                    : new PolicyDecision(DecisionAction.Accept, "BWR-POL-AUTH-FAILURE", "1.0.0", "sha256:auth", 90, ["reason 1", "reason 2"], ["warn 1"]);
    }

    private sealed class RecordingStore : IDurableEventStore
    {
        public List<QueuedEvent> Items { get; } = [];

        public Task<EnqueueResult> EnqueueAsync(QueuedEvent candidate, CancellationToken cancellationToken = default)
        {
            bool duplicate = Items.Any(item => item.Fingerprint == candidate.Fingerprint || item.EventId == candidate.EventId);
            if (!duplicate)
            {
                Items.Add(candidate);
            }

            return Task.FromResult(new EnqueueResult(!duplicate, duplicate, candidate.EventId));
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<QueuedEvent>> LeaseAsync(int maximumCount, TimeSpan leaseDuration, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task MarkDeliveredAsync(string eventId, string acknowledgement, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task MarkRetryingAsync(string eventId, string failureCode, DateTimeOffset retryAfter, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task MarkDeadLetteredAsync(string eventId, string failureCode, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<QueueSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> PurgeDeliveredAsync(DateTimeOffset deliveredBefore, int maximumCount, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task MaintainAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DeadLetterRecord>> ListDeadLetteredAsync(int maximumCount, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> ReplayDeadLetteredAsync(string? failureCodePrefix, IReadOnlyCollection<string>? eventIds, int maximumCount, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<LedgerHead> GetLedgerHeadAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<LedgerVerification> VerifyLedgerAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private static void Processor()
    {
        RedactionResult metadata = new(
            true,
            null,
            ["attributes.password"],
            ["attributes.contact", "actor.username"],
            null,
            ["secret.api-key:OpenAI", "id.email", "au.tfn", "field-name-secret", "au.tfn", "au.medicare:x"],
            new Dictionary<string, string>
            {
                ["secret.api-key"] = "Removed",
                ["au.tfn"] = "Masked",
                ["au.medicare:x"] = "Hashed",
                ["id.email"] = "Masked",
                ["field-name-secret"] = "Removed"
            });
        SecurityEventEnvelope accepted = Base() with
        {
            EventId = "evt-é-1",
            Attributes = new Dictionary<string, JsonElement>
            {
                ["n"] = JsonSerializer.SerializeToElement(1.50m),
                ["s"] = JsonSerializer.SerializeToElement("a+b <c> é")
            },
            Request = new RequestContext { TraceId = "trace-1", Method = "POST" }
        };
        SecurityEventEnvelope stale = Base() with
        {
            EventId = "stale",
            TimeGenerated = TestEvents.Now.AddYears(-6)
        };
        SecurityEventEnvelope rejected = Base() with { EventId = "rejected", Request = null };
        string[] inputs =
        [
            JsonSerializer.Serialize(accepted, BowerJson.Options),
            JsonSerializer.Serialize(stale, BowerJson.Options),
            JsonSerializer.Serialize(rejected, BowerJson.Options),
            JsonSerializer.Serialize(accepted, BowerJson.Options)
        ];

        RecordingStore store = new();
        SecurityEventProcessor processor = new(new FakeRedactor(metadata), new FakePolicy(), store, new FakeClock(TestEvents.Now));
        CollectorIdentity identity = new("collector-1", "0.1.0", "test", "sha256:configuration");
        for (int i = 0; i < inputs.Length; i++)
        {
            ProcessingResult result = processor.ProcessAsync(inputs[i], identity).GetAwaiter().GetResult();
            Emit($"proc.{i}.input", inputs[i]);
            Emit($"proc.{i}.result", JsonSerializer.Serialize(new
            {
                action = result.Action.ToString(),
                result.EventId,
                result.Queued,
                result.Duplicate,
                result.Reasons,
                result.PrivacyAlertEventId
            }));
        }

        for (int i = 0; i < store.Items.Count; i++)
        {
            QueuedEvent item = store.Items[i];
            Emit($"queued.{i}", $"{item.EventId}\n{item.Fingerprint}\n{item.ReceivedAt:O}\n{item.Payload}");
        }

        Emit("queued.count", store.Items.Count.ToString());
    }

    private sealed class ProbeHandler(Func<int, IReadOnlyList<string>, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<string> Log { get; } = [];
        public List<string[]> Batches { get; } = [];
        private int count;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int n = Interlocked.Increment(ref count);
            byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            if (request.Content.Headers.ContentEncoding.Contains("gzip"))
            {
                using GZipStream gzip = new(new MemoryStream(body), CompressionMode.Decompress);
                using MemoryStream plain = new();
                await gzip.CopyToAsync(plain, cancellationToken);
                body = plain.ToArray();
            }

            StringBuilder headers = new();
            headers.Append(request.Method).Append(' ').Append(request.RequestUri).Append('\n');
            foreach (var header in request.Headers.OrderBy(h => h.Key))
            {
                string value = header.Key == "Authorization" ? string.Join(",", header.Value).Split(' ')[0] + " <token>" : string.Join(",", header.Value);
                if (header.Key is "x-ms-client-request-id" or "traceparent" or "User-Agent")
                {
                    value = "<varies:" + value.Length + ">" + (header.Key == "User-Agent" ? value : "");
                }

                headers.Append(header.Key).Append(": ").Append(value).Append('\n');
            }

            foreach (var header in request.Content.Headers.OrderBy(h => h.Key))
            {
                headers.Append(header.Key).Append(": ").Append(string.Join(",", header.Value)).Append('\n');
            }

            using JsonDocument document = JsonDocument.Parse(body);
            string[] ids = document.RootElement.EnumerateArray().Select(item => item.GetProperty("eventId").GetString()!).ToArray();
            lock (Log)
            {
                Log.Add(headers + "\n" + Encoding.UTF8.GetString(body));
                Batches.Add(ids);
            }

            return respond(n, ids);
        }
    }

    private static HttpResponseMessage Response(HttpStatusCode status, int n, params (string, string)[] headers)
    {
        HttpResponseMessage response = new(status) { Content = new StringContent("{}") };
        response.Headers.Add("x-ms-request-id", $"req-{n}");
        foreach ((string name, string value) in headers)
        {
            response.Headers.TryAddWithoutValidation(name, value);
        }

        return response;
    }

    private sealed class StaticCredential(bool fail = false) : TokenCredential
    {
        public int Calls;

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            if (fail)
            {
                throw new AuthenticationFailedException("no token");
            }

            Emit("azure.scopes", string.Join(" ", requestContext.Scopes));
            return new("test-token", DateTimeOffset.UtcNow.AddHours(1));
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    private static AzureLogsIngestionOutput Output_(ProbeHandler handler, int concurrency = 1, int retries = 0, TokenCredential? credential = null) =>
        new(
            new AzureLogsIngestionOptions
            {
                Id = "azure-logs-ingestion",
                Endpoint = new Uri("https://example.ingest.monitor.azure.com"),
                DcrImmutableId = "dcr-00000000000000000000000000000000",
                StreamName = "Custom-BowerSecurity",
                MaximumConcurrency = concurrency
            },
            credential ?? new StaticCredential(),
            new LogsIngestionClientOptions
            {
                Transport = new HttpClientTransport(new HttpClient(handler)),
                Retry = { MaxRetries = retries, Delay = TimeSpan.FromMilliseconds(1), MaxDelay = TimeSpan.FromSeconds(5) }
            });

    private static QueuedEvent Event(string eventId, string padding = "", string extra = "") =>
        new(eventId, $"sha256:{eventId}",
            "{\"eventId\":\"" + eventId + "\",\"timeGenerated\":\"2026-10-08T00:00:00+00:00\",\"extra\":\"" + extra + "\",\"padding\":\"" + padding + "\"}",
            TestEvents.Now);

    private static string Describe(DeliveryResult result) =>
        JsonSerializer.Serialize(new
        {
            acked = result.AcknowledgedEventIds,
            failures = result.Failures.Select(f => $"{f.EventId}|{f.Code}|{f.IsRetryable}|{f.RetryAfter}"),
            ack = result.DestinationAcknowledgement
        });

    private static async Task Azure()
    {
        // 1. Request shape and body bytes.
        ProbeHandler shape = new((n, _) => Response(HttpStatusCode.NoContent, n));
        DeliveryResult r1 = await Output_(shape).DeliverAsync(
            [Event("a", extra: "x+y é <z> \\u00e9"), new QueuedEvent("b", "sha256:b", "{ \"eventId\" : \"b\", \"timeGenerated\":\"2026-10-08T00:00:00Z\", \"n\": 1.50, \"o\": {\"k\": [1, true, null]} }", TestEvents.Now)]);
        Emit("azure.shape.request", shape.Log[0]);
        Emit("azure.shape.result", Describe(r1));

        // 2. Batch boundary: largest second record that still shares a request.
        int padA = 400_000;
        int low = 1, high = 999_000;
        while (low < high)
        {
            int mid = (low + high + 1) / 2;
            ProbeHandler h = new((n, _) => Response(HttpStatusCode.NoContent, n));
            await Output_(h).DeliverAsync([Event("a", new string('x', padA)), Event("b", new string('y', mid))]);
            if (h.Batches.Count == 1) { low = mid; } else { high = mid - 1; }
        }

        Emit("azure.batch.padA", padA.ToString());
        Emit("azure.batch.maxPadB", low.ToString());
        Emit("azure.batch.recordA", Event("a", new string('x', padA)).Payload.Length.ToString());

        // three records near boundary
        ProbeHandler three = new((n, _) => Response(HttpStatusCode.NoContent, n));
        await Output_(three).DeliverAsync([Event("a", new string('x', 300_000)), Event("b", new string('x', 300_000)), Event("c", new string('x', 399_900)), Event("d", "")]);
        Emit("azure.batch.three", string.Join(";", three.Batches.Select(b => string.Join(",", b))));

        // 3. All fail.
        ProbeHandler allFail = new((n, _) => Response(HttpStatusCode.ServiceUnavailable, n));
        Emit("azure.allfail.result", Describe(await Output_(allFail).DeliverAsync([Event("a"), Event("b")])));

        // 4. Middle batch fails.
        string pad = new('x', 600 * 1024);
        ProbeHandler middle = new((n, ids) => Response(ids.Contains("b") ? HttpStatusCode.BadRequest : HttpStatusCode.NoContent, n));
        Emit("azure.middle.result", Describe(await Output_(middle).DeliverAsync([Event("a", pad), Event("b", pad), Event("c", pad)])));
        ProbeHandler lastFails = new((n, ids) => Response(ids.Contains("c") ? (HttpStatusCode)429 : HttpStatusCode.NoContent, n));
        Emit("azure.lastfails.result", Describe(await Output_(lastFails).DeliverAsync([Event("a", pad), Event("b", pad), Event("c", pad)])));
        ProbeHandler statuses = new((n, ids) => Response(ids.Contains("a") ? HttpStatusCode.RequestTimeout : ids.Contains("b") ? HttpStatusCode.Forbidden : (HttpStatusCode)413, n));
        Emit("azure.statuses.result", Describe(await Output_(statuses).DeliverAsync([Event("a", pad), Event("b", pad), Event("c", pad)])));

        // 5. Transport exception.
        ProbeHandler throws = new((_, _) => throw new HttpRequestException("boom"));
        try
        {
            Emit("azure.transport.result", Describe(await Output_(throws).DeliverAsync([Event("a")])));
        }
        catch (Exception exception)
        {
            Emit("azure.transport.result", "THROWS " + exception.GetType().FullName);
        }

        ProbeHandler throwsSecond = new((n, _) => n == 2 ? throw new HttpRequestException("boom") : Response(HttpStatusCode.NoContent, n));
        try
        {
            Emit("azure.transport2.result", Describe(await Output_(throwsSecond).DeliverAsync([Event("a", pad), Event("b", pad)])));
        }
        catch (Exception exception)
        {
            Emit("azure.transport2.result", "THROWS " + exception.GetType().FullName);
        }

        // 6. Retries.
        ProbeHandler retryAfterMs = new((n, _) => n == 1 ? Response((HttpStatusCode)429, n, ("retry-after-ms", "300")) : Response(HttpStatusCode.NoContent, n));
        Stopwatch watch = Stopwatch.StartNew();
        DeliveryResult r6 = await Output_(retryAfterMs, retries: 2).DeliverAsync([Event("a")]);
        Emit("azure.retry.ms", $"{retryAfterMs.Batches.Count} requests, {watch.ElapsedMilliseconds} ms, {Describe(r6)}");
        ProbeHandler retryAfter = new((n, _) => n == 1 ? Response(HttpStatusCode.ServiceUnavailable, n, ("Retry-After", "1")) : Response(HttpStatusCode.NoContent, n));
        watch.Restart();
        r6 = await Output_(retryAfter, retries: 2).DeliverAsync([Event("a")]);
        Emit("azure.retry.s", $"{retryAfter.Batches.Count} requests, {watch.ElapsedMilliseconds} ms, {Describe(r6)}");
        ProbeHandler noRetry = new((n, _) => Response(HttpStatusCode.BadRequest, n));
        r6 = await Output_(noRetry, retries: 2).DeliverAsync([Event("a")]);
        Emit("azure.retry.400", $"{noRetry.Batches.Count} requests, {Describe(r6)}");
        ProbeHandler exhausted = new((n, _) => Response(HttpStatusCode.InternalServerError, n));
        r6 = await Output_(exhausted, retries: 2).DeliverAsync([Event("a")]);
        Emit("azure.retry.exhausted", $"{exhausted.Batches.Count} requests, {Describe(r6)}");
        foreach (int status in new[] { 408, 429, 500, 501, 502, 503, 504, 505, 404, 409 })
        {
            ProbeHandler s = new((n, _) => Response((HttpStatusCode)status, n));
            await Output_(s, retries: 1).DeliverAsync([Event("a")]);
            Emit($"azure.retry.status.{status}", s.Batches.Count.ToString());
        }

        // 7. Token failure.
        ProbeHandler unused = new((n, _) => Response(HttpStatusCode.NoContent, n));
        try
        {
            Emit("azure.token.result", Describe(await Output_(unused, credential: new StaticCredential(fail: true)).DeliverAsync([Event("a")])) + $" requests={unused.Batches.Count}");
        }
        catch (Exception exception)
        {
            Emit("azure.token.result", "THROWS " + exception.GetType().FullName);
        }

        // 8. Token cached across batches/calls.
        StaticCredential counting = new();
        ProbeHandler cache = new((n, _) => Response(HttpStatusCode.NoContent, n));
        AzureLogsIngestionOutput cached = Output_(cache, credential: counting);
        await cached.DeliverAsync([Event("a", pad), Event("b", pad)]);
        await cached.DeliverAsync([Event("c")]);
        Emit("azure.token.calls", counting.Calls.ToString());
    }
}

using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Output.AzureLogsIngestion;

namespace Bower.UnitTests;

public sealed class AzureLogsIngestionOutputTests
{
    [Fact]
    public async Task Deliver_AcknowledgesAcceptedRecordsAsIngestionAcceptanceOnly()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);

        DeliveryResult result = await output.DeliverAsync(
            [Event("a"), Event("b")],
            TestContext.Current.CancellationToken);

        Assert.Equal(["a", "b"], result.AcknowledgedEventIds.Order());
        Assert.Empty(result.Failures);
        Assert.StartsWith("azure-logs-ingestion:accepted:", result.DestinationAcknowledgement, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deliver_AttributesFailedBatchToExactEvents()
    {
        // ~600 KB records force one upload request per record.
        string padding = new('x', 600 * 1024);
        RecordingHandler handler = new(eventIds =>
            eventIds.Contains("rejected") ? HttpStatusCode.BadRequest : HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);

        DeliveryResult result = await output.DeliverAsync(
            [Event("accepted", padding), Event("rejected", padding)],
            TestContext.Current.CancellationToken);

        Assert.Equal(["accepted"], result.AcknowledgedEventIds);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal("rejected", failure.EventId);
        Assert.Equal("azure-http-400-isolated", failure.Code);
        Assert.False(failure.IsRetryable);
    }

    [Fact]
    public async Task Deliver_MarksServerErrorsRetryable()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.ServiceUnavailable);
        AzureLogsIngestionOutput output = CreateOutput(handler);

        DeliveryResult result = await output.DeliverAsync(
            [Event("a")],
            TestContext.Current.CancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.True(Assert.Single(result.Failures).IsRetryable);
    }

    [Fact]
    public async Task Deliver_DeadLettersUnparseablePayloadWithoutFailingBatch()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);

        DeliveryResult result = await output.DeliverAsync(
            [Event("good"), new QueuedEvent("broken", "sha256:broken", "{not json", TestEvents.Now)],
            TestContext.Current.CancellationToken);

        Assert.Equal(["good"], result.AcknowledgedEventIds);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal("broken", failure.EventId);
        Assert.False(failure.IsRetryable);
    }

    [Fact]
    public async Task Deliver_DeadLettersPayloadWhoseEventIdDoesNotMatch()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);

        DeliveryResult result = await output.DeliverAsync(
            [new QueuedEvent("queued-id", "sha256:x", JsonSerializer.Serialize(new { eventId = "other" }), TestEvents.Now)],
            TestContext.Current.CancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Equal("payload-event-id-mismatch", Assert.Single(result.Failures).Code);
    }

    [Fact]
    public async Task Deliver_DeadLettersRecordsAzureWouldTruncate()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);
        string oversized = JsonSerializer.Serialize(new
        {
            eventId = "big",
            timeGenerated = "2026-10-08T00:00:00Z",
            actor = new { username = new string('x', 70_000) }
        });

        DeliveryResult result = await output.DeliverAsync(
            [new QueuedEvent("big", "sha256:big", oversized, TestEvents.Now), Event("ok")],
            TestContext.Current.CancellationToken);

        Assert.Equal(["ok"], result.AcknowledgedEventIds);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal("preflight-field-too-large", failure.Code);
        Assert.False(failure.IsRetryable);
    }

    [Fact]
    public async Task Deliver_DeadLettersTopLevelDuplicatePropertyAloneAndDeliversTheRest()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);
        const string duplicate = """{"eventId":"dup","timeGenerated":"2026-10-08T00:00:00Z","x":1,"x":2}""";

        // Before the fix JsonObject threw ArgumentException here and the whole batch was
        // retried forever as output-adapter-failure.
        DeliveryResult result = await output.DeliverAsync(
            [new QueuedEvent("dup", "sha256:dup", duplicate, TestEvents.Now), Event("ok")],
            TestContext.Current.CancellationToken);

        Assert.Equal(["ok"], result.AcknowledgedEventIds);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal("dup", failure.EventId);
        Assert.Equal("payload-invalid-json", failure.Code);
        Assert.False(failure.IsRetryable);
        Assert.Equal(["ok"], Assert.Single(handler.Requests).EventIds);
    }

    [Fact]
    public async Task Deliver_DeadLettersInvalidEscapesInsteadOfFailingTheUpload()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);
        const string loneSurrogate = """{"eventId":"bad","timeGenerated":"2026-10-08T00:00:00Z","o":{"s":"\uD800"}}""";

        DeliveryResult result = await output.DeliverAsync(
            [new QueuedEvent("bad", "sha256:bad", loneSurrogate, TestEvents.Now), Event("ok")],
            TestContext.Current.CancellationToken);

        Assert.Equal(["ok"], result.AcknowledgedEventIds);
        Assert.Equal("payload-invalid-json", Assert.Single(result.Failures).Code);
    }

    [Fact]
    public async Task Deliver_UploadsExactlyWhatTheJsonObjectSerializerWrote()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler);
        string[] payloads =
        [
            """{"eventId":"esc","timeGenerated":"2026-10-08T00:00:00Z","s":"<a>&'+é😀\/\u0001","n":1.0E+2,"big":123456789012345678901234567890,"neg":-0,"o":{"z":1,"a":[true,null]}}""",
            """ { "\u0065ventId" : "escaped-name" , "timeGenerated" : "2026-10-08T00:00:00Z", "k\u00e9y": "v\"q", "e": [ ], "f": { } } """,
            """{"eventId":"nested-dup","timeGenerated":"2026-10-08T00:00:00Z","o":{"x":1,"x":2},"a":[{"y":"\u00e9","y":false}]}""",
            """{"eventId":"plain","timeGenerated":"2026-10-08T00:00:00Z","actor":{"username":"alice"},"n":-1.25e-3,"t":true,"z":null}"""
        ];
        string[] ids = ["esc", "escaped-name", "nested-dup", "plain"];

        DeliveryResult result = await output.DeliverAsync(
            payloads.Select((payload, index) => new QueuedEvent(ids[index], "sha256:x", payload, TestEvents.Now)).ToArray(),
            TestContext.Current.CancellationToken);

        Assert.Equal(ids, result.AcknowledgedEventIds);
        // The previous adapter parsed each payload into a JsonObject, read its eventId (which
        // materializes the top level) and had the SDK write the node.
        string expected = "[" + string.Join(',', payloads.Select(payload =>
        {
            JsonObject record = JsonNode.Parse(payload)!.AsObject();
            _ = record["eventId"];
            return record.ToJsonString();
        })) + "]";
        Assert.Equal(expected, Assert.Single(handler.Requests).Body);
        // Measured C# body (rust/crates/bower-output-azure/tests/fixtures, "escapes").
        Assert.StartsWith(
            """[{"eventId":"esc","timeGenerated":"2026-10-08T00:00:00Z","s":"\u003Ca\u003E\u0026\u0027\u002B\u00E9\uD83D\uDE00/\u0001","n":1.0E+2,"big":123456789012345678901234567890,"neg":-0,"o":{"z":1,"a":[true,null]}},""",
            expected,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RejectNonHttpsEndpoint()
    {
        Assert.Throws<ArgumentException>(() => CreateOutput(
            new RecordingHandler(_ => HttpStatusCode.NoContent),
            new Uri("http://example.ingest.monitor.azure.com")));
    }

    [Fact]
    public async Task Deliver_DefaultConcurrencyOwnsFourReorderedMixedResponses()
    {
        ReorderedHandler handler = new();
        AzureLogsIngestionOutput output = CreateOutput(handler);
        string padding = new('x', 600 * 1024);
        DeliveryResult result = await output.DeliverAsync(
            [Event("one", padding), Event("two", padding), Event("three", padding), Event("four", padding)],
            TestContext.Current.CancellationToken);
        Assert.Equal(["two", "four"], result.AcknowledgedEventIds);
        Assert.Equal(["one", "three"], result.Failures.Select(item => item.EventId).Order());
        Assert.Equal("azure-http-400-isolated", result.Failures.Single(item => item.EventId == "one").Code);
        Assert.True(result.Failures.Single(item => item.EventId == "three").IsDestinationFailure);
        Assert.Equal(4, handler.Count);
    }

    [Fact]
    public async Task Deliver_BoundedIsolationRetainsRejectedSingletonForAuditedRecovery()
    {
        RecordingHandler handler = new(ids => ids.Contains("bad") ? HttpStatusCode.BadRequest : HttpStatusCode.NoContent);
        DeliveryResult result = await CreateOutput(handler).DeliverAsync(
            [Event("good1"), Event("bad"), Event("good2")], TestContext.Current.CancellationToken);
        Assert.Equal(["good1", "good2"], result.AcknowledgedEventIds);
        Assert.Equal("azure-http-400-isolated", Assert.Single(result.Failures).Code);
        Assert.False(Assert.Single(result.Failures).IsRetryable);
        Assert.InRange(handler.Requests.Count, 3, 17);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(429)]
    [InlineData(503)]
    public async Task Deliver_OutagePreservesRecordsAndFinalRetryAfter(int status)
    {
        HeaderHandler handler = new(status, "120");
        AzureLogsIngestionOutput output = CreateOutput(handler);
        DateTimeOffset before = DateTimeOffset.UtcNow;
        DeliveryResult failure = await output.DeliverAsync([Event("valid")], TestContext.Current.CancellationToken);
        Assert.Empty(failure.AcknowledgedEventIds);
        DeliveryFailure item = Assert.Single(failure.Failures);
        Assert.True(item.IsDestinationFailure);
        Assert.True(item.IsRetryable);
        Assert.True(item.RetryAfter >= before.AddSeconds(120));
        Assert.Null(failure.DestinationAcknowledgement);
        handler.Status = 204;
        Assert.Equal(["valid"], (await output.DeliverAsync([Event("valid")], TestContext.Current.CancellationToken)).AcknowledgedEventIds);
    }

    public static TheoryData<string> CredentialFailures => ["authentication-failed", "credential-unavailable"];

    [Theory]
    [MemberData(nameof(CredentialFailures))]
    public async Task Deliver_CredentialFailureKeepsRecordsWithMetadataOnlyCode(string kind)
    {
        // Expired, revoked or disabled credentials and wrong tenants surface as Azure.Identity
        // exceptions whose text can quote request details. Only a fixed code is retained,
        // distinct from a network outage, and nothing is sent without a token.
        const string Secret = "client-secret-value-that-must-never-leak";
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        ThrowingCredential credential = new(kind == "authentication-failed"
            ? new Azure.Identity.AuthenticationFailedException($"AADSTS7000222 expired {Secret}")
            : new Azure.Identity.CredentialUnavailableException($"missing {Secret}"));
        AzureLogsIngestionOutput output = CreateOutput(handler, credential: credential);

        DeliveryResult result = await output.DeliverAsync([Event("a"), Event("b")], TestContext.Current.CancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Empty(handler.Requests);
        Assert.Equal(2, result.Failures.Count);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal(AzureLogsIngestionOutput.CredentialFailedCode, failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
            Assert.DoesNotContain(Secret, failure.Code, StringComparison.Ordinal);
        });

        // Fixing the credential delivers the same records; nothing was dropped.
        credential.Failure = null;
        Assert.Equal(["a", "b"], (await output.DeliverAsync([Event("a"), Event("b")], TestContext.Current.CancellationToken))
            .AcknowledgedEventIds.Order());
    }

    public static TheoryData<string, string> TokenFailureTrees => new()
    {
        // As Azure.Identity reports them (recorded from a live client-secret credential).
        { "dns-proxy-or-firewall", "destination-azure-unavailable" },
        { "identity-service-503", "destination-azure-unavailable" },
        { "invalid-client", AzureLogsIngestionOutput.CredentialFailedCode },
        { "retried-transport-then-rejected", AzureLogsIngestionOutput.CredentialFailedCode },
        { "not-configured", AzureLogsIngestionOutput.CredentialFailedCode }
    };

    [Theory]
    [MemberData(nameof(TokenFailureTrees))]
    public async Task Deliver_ClassifiesTokenFailuresByTheirCause(string tree, string code)
    {
        static Exception Transport() => new Azure.RequestFailedException(0, "send failed",
            new HttpRequestException("connect", new System.Net.Sockets.SocketException(61)));
        Exception failure = tree switch
        {
            "dns-proxy-or-firewall" => new Azure.Identity.AuthenticationFailedException("token",
                new AggregateException(Transport(), Transport())),
            "identity-service-503" => new Azure.Identity.AuthenticationFailedException("token",
                new Microsoft.Identity.Client.MsalServiceException("service_not_available", "busy", 503)),
            "invalid-client" => new Azure.Identity.AuthenticationFailedException("token",
                new Microsoft.Identity.Client.MsalServiceException("invalid_client", "AADSTS7000215", 401)),
            "retried-transport-then-rejected" => new Azure.Identity.AuthenticationFailedException("token",
                new AggregateException(Transport(),
                    new Microsoft.Identity.Client.MsalServiceException("unauthorized_client", "AADSTS700016", 400))),
            _ => new Azure.Identity.CredentialUnavailableException("environment variables are not set")
        };
        RecordingHandler handler = new(_ => HttpStatusCode.NoContent);
        AzureLogsIngestionOutput output = CreateOutput(handler, credential: new ThrowingCredential(failure));

        DeliveryResult result = await output.DeliverAsync([Event("a")], TestContext.Current.CancellationToken);

        DeliveryFailure item = Assert.Single(result.Failures);
        Assert.Equal(code, item.Code);
        Assert.True(item.IsRetryable);
        Assert.True(item.IsDestinationFailure);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Deliver_TransportFailureIsNotReportedAsCredentialFailure()
    {
        ThrowingHandler handler = new();
        AzureLogsIngestionOutput output = CreateOutput(handler);

        DeliveryResult result = await output.DeliverAsync([Event("a")], TestContext.Current.CancellationToken);

        Assert.Equal("destination-azure-unavailable", Assert.Single(result.Failures).Code);
    }

    [Fact]
    public async Task Deliver_PreservesHttpDateRetryAfter()
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMinutes(10);
        HeaderHandler handler = new(429, deadline.ToString("R"));
        DeliveryResult result = await CreateOutput(handler).DeliverAsync([Event("a")], TestContext.Current.CancellationToken);
        Assert.Equal(deadline.ToUnixTimeSeconds(), Assert.Single(result.Failures).RetryAfter!.Value.ToUnixTimeSeconds());
    }

    [Theory]
    [InlineData("Retry-After", "Fri, 01 Jan 2100 00:00:00 GMT")]
    [InlineData("retry-after-ms", "1e300")]
    [InlineData("Retry-After", "999999999999999999")]
    public async Task Deliver_AbsurdRetryAfterReturnsPromptlyWithBoundedDurableDeadline(string name, string value)
    {
        HeaderHandler handler = new(429, value, name);
        DateTimeOffset before = DateTimeOffset.UtcNow;
        DeliveryResult result = await CreateOutput(handler, retries: 3).DeliverAsync([Event("valid")],
            TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.EndsWith(":retry-after-capped", failure.Code, StringComparison.Ordinal);
        Assert.InRange(failure.RetryAfter!.Value, before.AddMinutes(59), DateTimeOffset.UtcNow.AddHours(1));
        Assert.True(failure.IsDestinationFailure);
    }

    [Fact]
    public async Task Deliver_FinalRetryAfterSurvivesExhaustedSdkRetries()
    {
        ExhaustedHandler handler = new();
        DateTimeOffset before = DateTimeOffset.UtcNow;
        DeliveryResult result = await CreateOutput(handler, retries: 2).DeliverAsync([Event("valid")], TestContext.Current.CancellationToken);
        Assert.Equal(3, handler.Calls);
        Assert.True(Assert.Single(result.Failures).RetryAfter >= before.AddSeconds(120));
    }

    private sealed class ExhaustedHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            HttpResponseMessage response = new(HttpStatusCode.TooManyRequests) { Content = new StringContent("{}") };
            response.Headers.TryAddWithoutValidation("Retry-After", Calls == 3 ? "120" : "0");
            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task Deliver_CancellationDuringServerCooldownNeverAcknowledges()
    {
        CancellationHandler handler = new();
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        Task<DeliveryResult> upload = CreateOutput(handler, retries: 2).DeliverAsync([Event("valid")], stop.Token);
        await handler.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        await stop.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => upload);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Deliver_ConfigurationWide400HasBoundedIsolation()
    {
        RecordingHandler handler = new(_ => HttpStatusCode.BadRequest);
        DeliveryResult result = await CreateOutput(handler).DeliverAsync(
            Enumerable.Range(0, 64).Select(index => Event($"event-{index}")).ToArray(), TestContext.Current.CancellationToken);
        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Equal(64, result.Failures.Count);
        Assert.All(result.Failures, item => Assert.True(item.IsDestinationFailure));
        Assert.InRange(handler.Requests.Count, 1, 17);
    }

    private sealed class CancellationHandler : HttpMessageHandler
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            HttpResponseMessage response = new(HttpStatusCode.TooManyRequests) { Content = new StringContent("{}") };
            response.Headers.TryAddWithoutValidation("Retry-After", "1");
            Entered.TrySetResult();
            return Task.FromResult(response);
        }
    }

    private sealed class HeaderHandler(int status, string retryAfter, string headerName = "Retry-After") : HttpMessageHandler
    {
        public int Status { get; set; } = status;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpResponseMessage response = new((HttpStatusCode)Status) { Content = new StringContent("synthetic-secret-response") };
            response.Headers.TryAddWithoutValidation(headerName, retryAfter);
            return Task.FromResult(response);
        }
    }

    private sealed class ReorderedHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource allStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int count;
        public int Count => count;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[] compressed = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            using GZipStream gzip = new(new MemoryStream(compressed), CompressionMode.Decompress);
            using MemoryStream plain = new();
            await gzip.CopyToAsync(plain, cancellationToken);
            Assert.InRange(plain.Length, 1, AzureLogsIngestionOutput.MaximumBatchBytes);
            using JsonDocument document = JsonDocument.Parse(plain.ToArray());
            string id = Assert.Single(document.RootElement.EnumerateArray()).GetProperty("eventId").GetString()!;
            if (Interlocked.Increment(ref count) == 4) allStarted.TrySetResult();
            await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            await Task.Delay(id == "one" ? 80 : id == "three" ? 40 : 1, cancellationToken);
            return new HttpResponseMessage(id == "one" ? HttpStatusCode.BadRequest : id == "three" ? HttpStatusCode.TooManyRequests : HttpStatusCode.NoContent)
            { Content = new StringContent("{}") };
        }
    }

    private static AzureLogsIngestionOutput CreateOutput(HttpMessageHandler handler, Uri? endpoint = null, int retries = 0,
        TokenCredential? credential = null)
    {
        LogsIngestionClientOptions clientOptions = new()
        {
            Transport = new HttpClientTransport(new HttpClient(handler)),
            Retry = { MaxRetries = retries, Delay = TimeSpan.FromMilliseconds(1), MaxDelay = TimeSpan.FromMilliseconds(10) }
        };
        return new AzureLogsIngestionOutput(
            new AzureLogsIngestionOptions
            {
                Id = "azure-logs-ingestion",
                Endpoint = endpoint ?? new Uri("https://example.ingest.monitor.azure.com"),
                DcrImmutableId = "dcr-00000000000000000000000000000000",
                StreamName = "Custom-BowerSecurity"
            },
            credential ?? new StaticCredential(),
            clientOptions);
    }

    private static QueuedEvent Event(string eventId, string padding = "") =>
        new(
            eventId,
            $"sha256:{eventId}",
            JsonSerializer.Serialize(new { eventId, timeGenerated = "2026-10-08T00:00:00Z", padding }),
            TestEvents.Now);

    private sealed class RecordingHandler(Func<IReadOnlyList<string>, HttpStatusCode> respond)
        : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            if (request.Content.Headers.ContentEncoding.Contains("gzip"))
            {
                using GZipStream gzip = new(new MemoryStream(body), CompressionMode.Decompress);
                using MemoryStream plain = new();
                await gzip.CopyToAsync(plain, cancellationToken);
                body = plain.ToArray();
            }

            using JsonDocument document = JsonDocument.Parse(body);
            string[] eventIds = document.RootElement.EnumerateArray()
                .Select(item => item.GetProperty("eventId").GetString()!)
                .ToArray();
            lock (Requests)
            {
                Requests.Add(new RecordedRequest(eventIds, Encoding.UTF8.GetString(body)));
            }

            HttpResponseMessage response = new(respond(eventIds))
            {
                Content = new StringContent("{}")
            };
            response.Headers.Add("x-ms-request-id", Guid.NewGuid().ToString());
            return response;
        }
    }

    private sealed record RecordedRequest(string[] EventIds, string Body);

    private sealed class ThrowingCredential(Exception? failure) : TokenCredential
    {
        public Exception? Failure { get; set; } = failure;

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            Failure is { } failure ? throw failure : new AccessToken("test-token", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("connection refused");
    }

    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("test-token", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}

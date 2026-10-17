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
        Assert.Equal("azure-http-400", failure.Code);
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

    private static AzureLogsIngestionOutput CreateOutput(RecordingHandler handler, Uri? endpoint = null)
    {
        LogsIngestionClientOptions clientOptions = new()
        {
            Transport = new HttpClientTransport(new HttpClient(handler)),
            Retry = { MaxRetries = 0 }
        };
        return new AzureLogsIngestionOutput(
            new AzureLogsIngestionOptions
            {
                Id = "azure-logs-ingestion",
                Endpoint = endpoint ?? new Uri("https://example.ingest.monitor.azure.com"),
                DcrImmutableId = "dcr-00000000000000000000000000000000",
                StreamName = "Custom-BowerSecurity",
                MaximumConcurrency = 1
            },
            new StaticCredential(),
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

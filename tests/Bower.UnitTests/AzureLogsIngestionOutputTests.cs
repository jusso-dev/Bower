using System.IO.Compression;
using System.Net;
using System.Text.Json;
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
            JsonSerializer.Serialize(new { eventId, padding }),
            TestEvents.Now);

    private sealed class RecordingHandler(Func<IReadOnlyList<string>, HttpStatusCode> respond)
        : HttpMessageHandler
    {
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
            HttpResponseMessage response = new(respond(eventIds))
            {
                Content = new StringContent("{}")
            };
            response.Headers.Add("x-ms-request-id", Guid.NewGuid().ToString());
            return response;
        }
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

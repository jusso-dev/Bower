using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core.Pipeline;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Output.AzureLogsIngestion;

namespace Bower.Functions.Collector.Tests;

public sealed class FunctionIngestTests
{
    [Fact]
    public async Task Accepted_event_is_answered_only_after_destination_acknowledgement()
    {
        using Harness harness = new();

        CollectorResponse response = await harness.PostAsync(Harness.Event(), harness.Entra.Token());

        Assert.Equal(202, response.StatusCode);
        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.Equal("event-1", body.RootElement.GetProperty("eventId").GetString());
        Assert.Equal("redactandaccept", body.RootElement.GetProperty("decision").GetString());
        Assert.True(body.RootElement.GetProperty("delivered").GetBoolean());
        Assert.False(body.RootElement.GetProperty("queued").GetBoolean());
        IReadOnlyList<QueuedEvent> batch = Assert.Single(harness.Fake.Batches);
        // The removed password field also raises a privacy alert, delivered in the same request.
        Assert.Equal(2, batch.Count);
        QueuedEvent delivered = Assert.Single(batch, item => item.EventId == "event-1");
        Assert.All(batch, item => Assert.DoesNotContain(Harness.SecretCanary, item.Payload, StringComparison.Ordinal));
        JsonNode payload = JsonNode.Parse(delivered.Payload)!;
        Assert.Equal($"azure-function:{TestEntra.ProducerObjectId}", payload["collector"]!["sourceAdapter"]!.GetValue<string>());
        Assert.Equal("BWR-POL-AUTH-FAILURE", payload["security"]!["policyId"]!.GetValue<string>());
        Assert.DoesNotContain(Harness.SecretCanary, delivered.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain(Harness.SecretCanary, harness.AllLogs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Policy_deny_rejects_without_delivering_anything()
    {
        using Harness harness = new();

        CollectorResponse response = await harness.PostAsync(
            Harness.Event(eventType: "page_view", category: "web_analytics", secret: false), harness.Entra.Token());

        Assert.Equal(422, response.StatusCode);
        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.Equal("reject", body.RootElement.GetProperty("decision").GetString());
        Assert.False(body.RootElement.GetProperty("delivered").GetBoolean());
        Assert.Empty(harness.Fake.Batches);
    }

    [Fact]
    public async Task Policy_denied_event_with_a_secret_delivers_only_the_privacy_alert()
    {
        using Harness harness = new();

        CollectorResponse response = await harness.PostAsync(
            Harness.Event(eventType: "page_view", category: "web_analytics"), harness.Entra.Token());

        Assert.Equal(422, response.StatusCode);
        QueuedEvent alert = Assert.Single(Assert.Single(harness.Fake.Batches));
        Assert.StartsWith("privacy-", alert.EventId, StringComparison.Ordinal);
        Assert.DoesNotContain(Harness.SecretCanary, alert.Payload, StringComparison.Ordinal);
        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.False(body.RootElement.GetProperty("delivered").GetBoolean());
    }

    [Fact]
    public async Task Invalid_event_is_quarantined_with_400_and_not_delivered()
    {
        using Harness harness = new();
        JsonObject candidate = JsonNode.Parse(Harness.Event(secret: false))!.AsObject();
        candidate["schemaVersion"] = "0.9.0";

        CollectorResponse response = await harness.PostAsync(candidate.ToJsonString(), harness.Entra.Token());

        Assert.Equal(400, response.StatusCode);
        Assert.Empty(harness.Fake.Batches);
    }

    [Fact]
    public async Task Uploaded_bytes_are_redacted_by_default_and_custom_privacy_profiles()
    {
        using TemporaryDirectory directory = new();
        string profile = Path.Combine(directory.Path, "profile.yaml");
        File.WriteAllText(profile, """
            apiVersion: bower.security/v1
            kind: PrivacyProfile
            metadata:
              id: function-test-pseudonyms
              version: 1.0.0
            fields:
              - path: actor.username
                action: hmac
            """);
        string key = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(key, Convert.ToBase64String(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()));
        RecordingIngestionHandler handler = new(() => Harness.Status(HttpStatusCode.NoContent));
        FunctionSettings settings = Harness.Settings(privacyProfile: profile, hmacKeyFile: key);
        AzureLogsIngestionOutput output = RealOutput(settings, handler);
        using Harness harness = new(settings, output);
        const string card = "4111111111111111";

        CollectorResponse response = await harness.PostAsync(
            Harness.Event(outcomeReason: $"card {card} declined", username: "alice.private"), harness.Entra.Token());

        Assert.Equal(202, response.StatusCode);
        string uploaded = string.Join('\n', handler.Bodies);
        Assert.NotEmpty(handler.Bodies);
        Assert.DoesNotContain(Harness.SecretCanary, uploaded, StringComparison.Ordinal);
        Assert.DoesNotContain(card, uploaded, StringComparison.Ordinal);
        Assert.DoesNotContain("alice.private", uploaded, StringComparison.Ordinal);
        Assert.Contains("hmac-sha256:k1:", uploaded, StringComparison.Ordinal);
        // The privacy alert generated for the card number is delivered in the same request.
        JsonArray records = new([.. handler.Bodies.SelectMany(body => JsonNode.Parse(body)!.AsArray()).Select(node => node!.DeepClone())]);
        Assert.Contains(records, record => record!["eventType"]!.GetValue<string>() == "sensitive_data_detected");
        Assert.DoesNotContain(card, response.Body, StringComparison.Ordinal);
        Assert.DoesNotContain(card, harness.AllLogs, StringComparison.Ordinal);
        using JsonDocument status = JsonDocument.Parse(
            (await harness.Collector.StatusAsync("Bearer " + harness.Entra.Token(), TestContext.Current.CancellationToken)).Body);
        Assert.Equal("function-test-pseudonyms", status.RootElement.GetProperty("policy").GetProperty("privacyProfile").GetString());
    }

    [Fact]
    public async Task Delivery_failure_answers_503_with_retry_after_and_retains_nothing()
    {
        bool fail = true;
        FakeOutput output = new(events => fail ? FakeOutput.Fail(events, "destination-azure-http-503", true) : null!);
        using Harness harness = new(output: output);

        CollectorResponse first = await harness.PostAsync(Harness.Event("first"), harness.Entra.Token());
        fail = false;
        CollectorResponse second = await harness.PostAsync(Harness.Event("second"), harness.Entra.Token());

        Assert.Equal(503, first.StatusCode);
        Assert.Equal("10", first.Headers["Retry-After"]);
        Assert.DoesNotContain(Harness.SecretCanary, first.Body, StringComparison.Ordinal);
        Assert.Equal(202, second.StatusCode);
        // Nothing from the failed request survives into the next delivery.
        Assert.Equal(2, output.Batches.Count);
        Assert.Contains("first", output.Batches[0].Select(item => item.EventId));
        Assert.DoesNotContain("first", output.Batches[1].Select(item => item.EventId));
        Assert.Contains("second", output.Batches[1].Select(item => item.EventId));
        Assert.Contains("destination-azure-http-503", harness.AllLogs, StringComparison.Ordinal);
        Assert.DoesNotContain(Harness.SecretCanary, harness.AllLogs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Partial_acknowledgement_is_not_success()
    {
        // Event accepted but its privacy alert not: the caller must retry the whole event.
        FakeOutput output = new(events => new DeliveryResult(
            [events[0].EventId],
            [.. events.Skip(1).Select(item => new DeliveryFailure(item.EventId, "destination-azure-unavailable", true, null))],
            null));
        using Harness harness = new(output: output);

        CollectorResponse response = await harness.PostAsync(
            Harness.Event(outcomeReason: "card 4111111111111111 declined"), harness.Entra.Token());

        Assert.Equal(2, Assert.Single(output.Batches).Count);
        Assert.Equal(503, response.StatusCode);
    }

    [Fact]
    public async Task Throttling_answers_429_with_the_destination_retry_after()
    {
        RecordingIngestionHandler handler = new(() => Harness.Status(HttpStatusCode.TooManyRequests, "120"));
        FunctionSettings settings = Harness.Settings();
        using Harness harness = new(settings, RealOutput(settings, handler));

        CollectorResponse response = await harness.PostAsync(Harness.Event(), harness.Entra.Token());

        Assert.Equal(429, response.StatusCode);
        int seconds = int.Parse(response.Headers["Retry-After"], System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(seconds, 110, 121);
    }

    [Fact]
    public async Task Destination_exception_and_timeout_answer_503()
    {
        using Harness throwing = new(output: new ThrowingOutput());
        using Harness slow = new(
            Harness.Settings(deliveryTimeout: TimeSpan.FromSeconds(FunctionSettings.MinimumDeliveryTimeoutSeconds)),
            new HangingOutput());

        CollectorResponse thrown = await throwing.PostAsync(Harness.Event(), throwing.Entra.Token());
        CollectorResponse timedOut = await slow.PostAsync(Harness.Event(), slow.Entra.Token());

        Assert.Equal(503, thrown.StatusCode);
        Assert.Equal(503, timedOut.StatusCode);
        Assert.DoesNotContain("synthetic-credential-detail", throwing.AllLogs, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-credential-detail", thrown.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Permanent_destination_rejection_answers_422_so_producers_stop_retrying()
    {
        FakeOutput output = new(events => FakeOutput.Fail(events, "preflight-string-too-long", false));
        using Harness harness = new(output: output);

        CollectorResponse response = await harness.PostAsync(Harness.Event(), harness.Entra.Token());

        Assert.Equal(422, response.StatusCode);
        Assert.Contains("preflight-string-too-long", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Caller_cancellation_propagates_without_delivery()
    {
        using Harness harness = new();
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            harness.PostAsync(Harness.Event(), harness.Entra.Token(), cancellationToken: cancelled.Token));

        Assert.Empty(harness.Fake.Batches);
    }

    [Theory]
    [InlineData("declared-oversized", 413)]
    [InlineData("streamed-oversized", 413)]
    [InlineData("understated-content-length", 413)]
    [InlineData("malformed-json", 400)]
    [InlineData("truncated-json", 400)]
    [InlineData("invalid-utf8", 400)]
    [InlineData("trailing-garbage", 400)]
    [InlineData("deep-nesting", 400)]
    [InlineData("wrong-content-type", 415)]
    [InlineData("missing-content-type", 415)]
    [InlineData("array-body", 403)]
    [InlineData("scalar-body", 403)]
    [InlineData("duplicate-identity-field", 403)]
    public async Task Malformed_and_oversized_input_is_bounded_and_never_delivered(string scenario, int expected)
    {
        using Harness harness = new();
        string token = harness.Entra.Token();
        byte[] valid = Encoding.UTF8.GetBytes(Harness.Event());
        CollectorResponse response = scenario switch
        {
            "declared-oversized" => await harness.PostAsync(valid, token, contentLength: FunctionCollector.MaximumPayloadBytes + 1L),
            "streamed-oversized" => await harness.PostAsync(
                new byte[FunctionCollector.MaximumPayloadBytes + 1], token, declareLength: false),
            "understated-content-length" => await harness.PostAsync(
                new byte[FunctionCollector.MaximumPayloadBytes + 1], token, contentLength: 10),
            "malformed-json" => await harness.PostAsync("{not json", token),
            "truncated-json" => await harness.PostAsync(Harness.Event()[..40], token),
            "invalid-utf8" => await harness.PostAsync([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d], token),
            "trailing-garbage" => await harness.PostAsync(Harness.Event() + "{}", token),
            "deep-nesting" => await harness.PostAsync(new string('[', 70) + new string(']', 70), token),
            "wrong-content-type" => await harness.PostAsync(Harness.Event(), token, contentType: "text/plain"),
            "missing-content-type" => await harness.PostAsync(Harness.Event(), token, contentType: null),
            "array-body" => await harness.PostAsync("[" + Harness.Event() + "]", token),
            "scalar-body" => await harness.PostAsync("42", token),
            _ => await harness.PostAsync(Harness.Event().Replace(
                "\"application\":{", "\"application\":{\"name\":\"Other\",", StringComparison.Ordinal), token)
        };

        Assert.Equal(expected, response.StatusCode);
        Assert.Empty(harness.Fake.Batches);
        Assert.DoesNotContain(Harness.SecretCanary, response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Exactly_one_mebibyte_is_accepted_for_processing()
    {
        using Harness harness = new();
        string small = Harness.Event();
        string padded = small[..^1] + ",\"eventOutcomeReason2\":\"" + new string('x', FunctionCollector.MaximumPayloadBytes - small.Length - 28) + "\"}";
        Assert.True(Encoding.UTF8.GetByteCount(padded) <= FunctionCollector.MaximumPayloadBytes);

        CollectorResponse response = await harness.PostAsync(padded, harness.Entra.Token());

        Assert.NotEqual(413, response.StatusCode);
    }

    [Fact]
    public async Task Development_bypass_requires_development_environment()
    {
        FunctionSettings production = Harness.Settings() with
        {
            DevelopmentAuthentication = true,
            EntraTenantId = null,
            EntraAudience = null
        };
        Assert.Throws<InvalidOperationException>(production.Validate);
        Assert.Throws<InvalidOperationException>(() => FunctionCollectorServices.CreateAuthenticator(production));

        FunctionSettings development = production with
        {
            Environment = FunctionSettings.DevelopmentEnvironment,
            ProducerScopesJson = Harness.Scopes(DevelopmentProducerAuthenticator.Producer)
        };
        Assert.IsType<DevelopmentProducerAuthenticator>(FunctionCollectorServices.CreateAuthenticator(development));
        using Harness harness = new(development, authenticator: FunctionCollectorServices.CreateAuthenticator(development));
        CollectorResponse response = await harness.PostAsync(Harness.Event(), token: null);
        Assert.Equal(202, response.StatusCode);
    }

    [Fact]
    public async Task Output_bounds_each_request_not_every_concurrent_request_on_the_instance()
    {
        // The host shares one output across up to httpPerInstanceConcurrency (16) requests.
        // Each request keeps its own adaptive bound, as the fixed setting did.
        ConcurrentHoldHandler handler = new(16);
        AzureLogsIngestionOutput output = RealOutput(Harness.Settings(), handler);

        DeliveryResult[] results = await Task.WhenAll(Enumerable.Range(0, 16).Select(index =>
        {
            string eventId = $"concurrent-{index}";
            return output.DeliverAsync(
                [new QueuedEvent(eventId, $"sha256:{eventId}",
                    JsonSerializer.Serialize(new { eventId, timeGenerated = "2026-10-08T00:00:00Z" }), DateTimeOffset.UtcNow)],
                TestContext.Current.CancellationToken);
        }));

        Assert.All(results, result => Assert.Single(result.AcknowledgedEventIds));
        Assert.Equal(16, handler.Peak);
        Assert.Null(output.GetConcurrencySnapshot());
    }

    private sealed class ConcurrentHoldHandler(int hold) : HttpMessageHandler
    {
        private readonly TaskCompletionSource all = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int inFlight;
        private int peak;

        public int Peak => Volatile.Read(ref peak);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int current = Interlocked.Increment(ref inFlight);
            int seen;
            while ((seen = Volatile.Read(ref peak)) < current && Interlocked.CompareExchange(ref peak, current, seen) != seen)
            {
            }

            if (current >= hold) all.TrySetResult();
            try
            {
                // Fails the request (and the test) if the requests cannot all be in flight.
                await all.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.NoContent) { Content = new StringContent("{}") };
            }
            finally
            {
                Interlocked.Decrement(ref inFlight);
            }
        }
    }

    private static AzureLogsIngestionOutput RealOutput(FunctionSettings settings, HttpMessageHandler handler) =>
        FunctionCollectorServices.CreateOutput(settings, new StaticCredential(), new LogsIngestionClientOptions
        {
            Transport = new HttpClientTransport(new HttpClient(handler))
        });

    private sealed class ThrowingOutput : IOutputAdapter
    {
        public string Id => "throwing";

        public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("synthetic-credential-detail");
    }

    private sealed class HangingOutput : IOutputAdapter
    {
        public string Id => "hanging";

        public async Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }
}

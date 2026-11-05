using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Amazon.Runtime;
using Amazon.S3;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Output.S3;
using Bower.Persistence;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

public sealed class S3OutputTests
{
    private static readonly JsonNode Vectors = JsonNode.Parse(File.ReadAllText(
        Path.Combine(AppContext.BaseDirectory, "s3-output", "vectors.json")))!;

    [Fact]
    public void Layout_MatchesSharedVectors()
    {
        foreach (JsonNode? item in Vectors["cases"]!.AsArray())
        {
            JsonNode testCase = item!;
            QueuedEvent[] events = [.. testCase["events"]!.AsArray().Select(node => new QueuedEvent(
                node!["eventId"]!.GetValue<string>(),
                "sha256:x",
                node["payload"]!.GetValue<string>(),
                DateTimeOffset.Parse(node["receivedAt"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture)))];

            (IReadOnlyList<S3PlannedObject> objects, IReadOnlyList<DeliveryFailure> rejected) = S3ObjectLayout.Plan(
                events,
                testCase["prefix"]!.GetValue<string>(),
                testCase["maximumObjectBytes"]!.GetValue<int>(),
                testCase["maximumObjectEvents"]!.GetValue<int>(),
                testCase["gzip"]!.GetValue<bool>());

            JsonArray expectedObjects = testCase["expected"]!["objects"]!.AsArray();
            Assert.Equal(expectedObjects.Count, objects.Count);
            for (int index = 0; index < objects.Count; index++)
            {
                JsonNode expected = expectedObjects[index]!;
                Assert.Equal(expected["key"]!.GetValue<string>(), objects[index].Key);
                Assert.Equal(expected["eventIds"]!.AsArray().Select(id => id!.GetValue<string>()), objects[index].EventIds);
                Assert.Equal(expected["bodyBytes"]!.GetValue<int>(), objects[index].Body.Length);
                Assert.Equal(expected["bodySha256"]!.GetValue<string>(), Convert.ToHexStringLower(SHA256.HashData(objects[index].Body)));
            }

            Assert.Equal(
                testCase["expected"]!["rejected"]!.AsArray().Select(node => (node!["eventId"]!.GetValue<string>(), node["code"]!.GetValue<string>())),
                rejected.Select(failure => (failure.EventId, failure.Code)));
            Assert.All(rejected, failure => Assert.False(failure.IsRetryable));
        }

        foreach (JsonNode? item in Vectors["eventIdsHash"]!.AsArray())
        {
            Assert.Equal(item!["sha256"]!.GetValue<string>(),
                S3ObjectLayout.EventIdsHash([.. item["eventIds"]!.AsArray().Select(id => id!.GetValue<string>())]));
        }
    }

    [Fact]
    public void Classification_AndAcknowledgement_MatchSharedVectors()
    {
        foreach (JsonNode? item in Vectors["classification"]!.AsArray())
        {
            string? code = S3Output.Classify(
                item!["status"]!.GetValue<int>(),
                item["errorCode"]?.GetValue<string>(),
                item["messageNamesKms"]!.GetValue<bool>());
            Assert.Equal(item["expected"]?.GetValue<string>(), code);
            Assert.True(code is null || code.StartsWith("destination-s3-", StringComparison.Ordinal));
        }

        foreach (JsonNode? item in Vectors["acknowledgement"]!.AsArray())
        {
            Assert.Equal(item!["expected"]?.GetValue<string>(), S3Output.Acknowledgement(
                item["bucket"]!.GetValue<string>(),
                [.. item["keys"]!.AsArray().Select(key => key!.GetValue<string>())]));
        }
    }

    [Fact]
    public async Task Deliver_SendsConditionalEncryptedChecksummedGzipObject()
    {
        FakeS3 s3 = new();
        using S3Output output = Create(s3, Options() with { ExpectedBucketOwner = "123456789012" });
        QueuedEvent[] events = Events(3);

        DeliveryResult result = await output.DeliverAsync(events, TestContext.Current.CancellationToken);

        Assert.Equal(events.Select(item => item.EventId), result.AcknowledgedEventIds);
        Assert.Empty(result.Failures);
        CapturedPut put = Assert.Single(s3.Puts);
        string key = S3ObjectLayout.Key("bower", events[0].ReceivedAt, [.. events.Select(item => item.EventId)], gzip: true);
        Assert.Equal($"/bower-test-bucket/{key}", put.Path);
        Assert.Equal($"s3://bower-test-bucket/{key}", result.DestinationAcknowledgement);
        Assert.Equal("*", put.Header("If-None-Match"));
        Assert.Equal("AES256", put.Header("x-amz-server-side-encryption"));
        Assert.Null(put.Header("x-amz-server-side-encryption-aws-kms-key-id"));
        Assert.Equal("123456789012", put.Header("x-amz-expected-bucket-owner"));
        Assert.Equal("gzip", put.Header("Content-Encoding"));
        Assert.Equal("3", put.Header("x-amz-meta-bower-events"));
        Assert.Equal(Convert.ToBase64String(SHA256.HashData(put.Body)), put.Header("x-amz-checksum-sha256"));
        Assert.Equal(string.Concat(events.Select(item => item.Payload + "\n")), Gunzip(put.Body));
        Assert.Null(put.Header("Authorization"));
    }

    [Fact]
    public async Task Deliver_UsesKmsKeyAndPlainNdjsonWhenGzipIsOff()
    {
        FakeS3 s3 = new();
        using S3Output output = Create(s3, Options() with
        {
            ServerSideEncryption = S3OutputOptions.SseKms,
            KmsKeyId = "alias/bower-output",
            Gzip = false
        });
        QueuedEvent[] events = Events(2);

        await output.DeliverAsync(events, TestContext.Current.CancellationToken);

        CapturedPut put = Assert.Single(s3.Puts);
        Assert.EndsWith(".jsonl", put.Path, StringComparison.Ordinal);
        Assert.Equal("aws:kms", put.Header("x-amz-server-side-encryption"));
        Assert.Equal("alias/bower-output", put.Header("x-amz-server-side-encryption-aws-kms-key-id"));
        Assert.Null(put.Header("Content-Encoding"));
        Assert.Equal(string.Concat(events.Select(item => item.Payload + "\n")), Encoding.UTF8.GetString(put.Body));
    }

    [Fact]
    public async Task Deliver_RetryOfSameBatchRewritesSameKey_AndExistingObjectIsSuccess()
    {
        FakeS3 s3 = new();
        using S3Output output = Create(s3, Options());
        QueuedEvent[] events = Events(4);

        DeliveryResult first = await output.DeliverAsync(events, TestContext.Current.CancellationToken);
        s3.Respond = _ => Error(HttpStatusCode.PreconditionFailed, "PreconditionFailed");
        DeliveryResult retry = await output.DeliverAsync(events, TestContext.Current.CancellationToken);

        Assert.Equal(2, s3.Puts.Count);
        Assert.Equal(s3.Puts[0].Path, s3.Puts[1].Path);
        Assert.Equal(s3.Puts[0].Body.Length, s3.Puts[1].Body.Length);
        Assert.Equal(first.AcknowledgedEventIds, retry.AcknowledgedEventIds);
        Assert.Empty(retry.Failures);
        Assert.Equal(first.DestinationAcknowledgement, retry.DestinationAcknowledgement);
    }

    [Fact]
    public async Task Deliver_SplitsUnderCountCap_AndHoldsObjectsAfterFirstFailure()
    {
        FakeS3 s3 = new();
        using S3Output output = Create(s3, Options() with { MaximumObjectEvents = 2 });
        QueuedEvent[] events = Events(5);
        s3.Respond = index => index == 1 ? Error(HttpStatusCode.Forbidden, "AccessDenied") : Ok();

        DeliveryResult result = await output.DeliverAsync(events, TestContext.Current.CancellationToken);

        // Object 1 succeeded; object 2 was denied; object 3 was never sent.
        Assert.Equal(2, s3.Puts.Count);
        Assert.Equal(["s3-0", "s3-1"], result.AcknowledgedEventIds);
        Assert.Equal(["s3-2", "s3-3", "s3-4"], result.Failures.Select(failure => failure.EventId));
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal(S3Output.AccessDeniedCode, failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
        });
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable, "SlowDown", "", "destination-s3-throttled")]
    [InlineData(HttpStatusCode.InternalServerError, "InternalError", "", "destination-s3-http-500")]
    [InlineData(HttpStatusCode.NotFound, "NoSuchBucket", "", "destination-s3-no-such-bucket")]
    [InlineData(HttpStatusCode.Forbidden, "AccessDenied", "not authorized to perform: kms:GenerateDataKey", "destination-s3-kms-denied")]
    [InlineData(HttpStatusCode.Forbidden, "InvalidAccessKeyId", "", "destination-s3-credential-failed")]
    public async Task Deliver_ClassifiesServiceErrorsAsRetryableDestinationFaults(
        HttpStatusCode status, string code, string message, string expected)
    {
        FakeS3 s3 = new() { Respond = _ => Error(status, code, message) };
        using S3Output output = Create(s3, Options());

        DeliveryResult result = await output.DeliverAsync(Events(2), TestContext.Current.CancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Null(result.DestinationAcknowledgement);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal(expected, failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.Null(failure.RetryAfter);
        });
    }

    [Fact]
    public async Task Deliver_NetworkFailureIsUnavailable_AndKeepsNoExceptionText()
    {
        FakeS3 s3 = new() { Throw = () => new HttpRequestException("connection refused secret-looking-text") };
        using S3Output output = Create(s3, Options());

        DeliveryResult result = await output.DeliverAsync(Events(2), TestContext.Current.CancellationToken);

        Assert.All(result.Failures, failure => Assert.Equal(S3Output.UnavailableCode, failure.Code));
    }

    [Fact]
    public async Task Deliver_CancellationKeepsWrittenObjectsAcknowledged()
    {
        using CancellationTokenSource cancellation = new();
        FakeS3 s3 = new();
        s3.Respond = index =>
        {
            if (index == 1)
            {
                cancellation.Cancel();
                cancellation.Token.ThrowIfCancellationRequested();
            }

            return Ok();
        };
        using S3Output output = Create(s3, Options() with { MaximumObjectEvents = 1 });

        DeliveryResult result = await output.DeliverAsync(Events(3), cancellation.Token);

        Assert.Equal(["s3-0"], result.AcknowledgedEventIds);
        Assert.Equal(["s3-1", "s3-2"], result.Failures.Select(failure => failure.EventId));
        Assert.All(result.Failures, failure => Assert.Equal(S3Output.CancelledCode, failure.Code));
    }

    [Fact]
    public async Task Deliver_RejectsPoisonAlone_AndDeliversTheRest()
    {
        FakeS3 s3 = new();
        using S3Output output = Create(s3, Options());
        QueuedEvent[] events = [.. Events(2), new QueuedEvent("bad", "sha256:bad", "{\"eventId\":", TestEvents.Now)];

        DeliveryResult result = await output.DeliverAsync(events, TestContext.Current.CancellationToken);

        Assert.Equal(["s3-0", "s3-1"], result.AcknowledgedEventIds);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal(("bad", "payload-invalid-json", false), (failure.EventId, failure.Code, failure.IsRetryable));
    }

    [Fact]
    public async Task Queue_DestinationFailureKeepsEventsQueued_ThenDeliversOnce()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        foreach (QueuedEvent item in Events(3))
        {
            await store.EnqueueAsync(item, cancellationToken);
        }

        FakeS3 s3 = new() { Respond = _ => Error(HttpStatusCode.Forbidden, "AccessDenied") };
        using S3Output output = Create(s3, Options());
        RecordingLogger logger = new();
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions { MaximumDeliveryAttempts = 1 }, logger);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            await worker.DeliverOnceAsync(cancellationToken);
            clock.Advance(TimeSpan.FromMinutes(5));
        }

        QueueSnapshot held = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal((0, 3, 0, 0), (held.Delivered, held.Retrying, held.DeadLettered, held.Uploading));
        Assert.Contains(logger.Messages, message => message.Contains("destination-s3-access-denied", StringComparison.Ordinal));

        s3.Respond = _ => Ok();
        await worker.DeliverOnceAsync(cancellationToken);

        QueueSnapshot delivered = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal((3, 0, 0), (delivered.Delivered, delivered.Retrying, delivered.DeadLettered));
        Assert.Equal(4, s3.Puts.Count);
        Assert.Single(s3.Puts.Select(put => put.Path).Distinct());
        Assert.DoesNotContain(logger.Messages, message =>
            message.Contains("AKIA", StringComparison.Ordinal) || message.Contains("Authorization", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("BOWER_S3_ACCESS_KEY_ID")]
    [InlineData("BOWER_S3_SECRET_ACCESS_KEY")]
    [InlineData("BOWER_S3_SESSION_TOKEN")]
    [InlineData("BOWER_AWS_ACCESS_KEY_ID")]
    [InlineData("BOWER_AWS_SECRET_ACCESS_KEY")]
    public void Settings_RefuseStaticKeys_WithoutEchoingThem(string name)
    {
        const string Secret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY";
        Dictionary<string, string> environment = S3Environment();
        environment[name] = Secret;

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key)));

        Assert.Contains(name, error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, error.Message, StringComparison.Ordinal);

        // Refused even when another output is selected.
        Dictionary<string, string> other = new() { ["BOWER_OUTPUT"] = "none", [name] = Secret };
        Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(key => other.GetValueOrDefault(key)));
    }

    [Theory]
    [InlineData("BOWER_S3_BUCKET", "Bower-Upper")]
    [InlineData("BOWER_S3_BUCKET", "bower.dotted")]
    [InlineData("BOWER_S3_BUCKET", "ab")]
    [InlineData("BOWER_S3_BUCKET", "-bower")]
    [InlineData("BOWER_S3_BUCKET", "xn--bower")]
    [InlineData("BOWER_S3_BUCKET", "bower-s3alias")]
    [InlineData("BOWER_S3_BUCKET", "bower_under")]
    [InlineData("BOWER_S3_REGION", "Sydney")]
    [InlineData("BOWER_S3_PREFIX", "/bower")]
    [InlineData("BOWER_S3_PREFIX", "bower/")]
    [InlineData("BOWER_S3_PREFIX", "bower//x")]
    [InlineData("BOWER_S3_PREFIX", "bower/../x")]
    [InlineData("BOWER_S3_PREFIX", "bower x")]
    [InlineData("BOWER_S3_SSE", "aws:kms:dsse")]
    [InlineData("BOWER_S3_KMS_KEY_ID", "alias/has space")]
    [InlineData("BOWER_S3_EXPECTED_BUCKET_OWNER", "12345")]
    [InlineData("BOWER_S3_MAX_OBJECT_BYTES", "1024")]
    [InlineData("BOWER_S3_MAX_OBJECT_BYTES", "999999999")]
    [InlineData("BOWER_S3_MAX_OBJECT_EVENTS", "0")]
    [InlineData("BOWER_S3_GZIP", "yes")]
    public void Settings_RejectInvalidValues(string name, string value)
    {
        Dictionary<string, string> environment = S3Environment();
        environment[name] = value;

        Assert.Throws<InvalidOperationException>(() =>
            CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key)));
    }

    [Fact]
    public void Settings_RequireOutputAndBucketTogether_AndHashOnlyNonSecretSettings()
    {
        Dictionary<string, string> environment = S3Environment();
        CollectorSettings settings = CollectorSettings.FromEnvironment(key => environment.GetValueOrDefault(key));
        Assert.Equal("s3", settings.OutputType);
        Assert.Equal(new S3OutputOptions
        {
            Bucket = "bower-test-bucket",
            Region = "ap-southeast-2",
            Prefix = "security/bower",
            ServerSideEncryption = S3OutputOptions.SseKms
        }, settings.S3Output);

        // rust/crates/bower-collector/tests/s3_output.rs pins the same hash.
        Assert.Equal("sha256:a9429d32a9a415445bb25f4290db2a46c94e1667fb3f089fdc7c88429dd54b45", settings.ConfigurationHash());

        // AWS default-chain variables never reach Bower settings or the configuration hash.
        Dictionary<string, string> withChain = new(environment)
        {
            ["AWS_ACCESS_KEY_ID"] = "AKIAEXAMPLEEXAMPLE00",
            ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"
        };
        Assert.Equal(settings.ConfigurationHash(),
            CollectorSettings.FromEnvironment(key => withChain.GetValueOrDefault(key)).ConfigurationHash());
        Assert.NotEqual(settings.ConfigurationHash(), (settings with { S3Output = settings.S3Output! with { Prefix = "other" } }).ConfigurationHash());

        Dictionary<string, string> noBucket = new(environment);
        noBucket.Remove("BOWER_S3_BUCKET");
        noBucket.Remove("BOWER_S3_REGION");
        noBucket.Remove("BOWER_S3_PREFIX");
        noBucket.Remove("BOWER_S3_SSE");
        Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(key => noBucket.GetValueOrDefault(key)));

        Dictionary<string, string> kmsKeyWithSseS3 = new(environment) { ["BOWER_S3_SSE"] = "AES256", ["BOWER_S3_KMS_KEY_ID"] = "alias/key" };
        Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(key => kmsKeyWithSseS3.GetValueOrDefault(key)));

        Dictionary<string, string> wrongOutput = new(environment) { ["BOWER_OUTPUT"] = "ama-spool" };
        Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(key => wrongOutput.GetValueOrDefault(key)));
    }

    [Fact]
    public void ProductionConstructor_ResolvesCredentialsLazilyFromTheDefaultChain()
    {
        // No credential is read at construction: start-up never fails or logs over credentials.
        using S3Output output = new(Options());
        Assert.Equal("s3", output.Id);
    }

    /// <summary>
    /// Live qualification only (skipped unless BOWER_S3_LIVE_BUCKET is set): delivers one
    /// fixed batch twice through the default credential chain. The Rust test
    /// <c>live_same_batch_writes_one_object</c> sends the same batch, so both runtimes and
    /// every retry must land on one key (the second PUT gets 412 and counts as delivered).
    /// </summary>
    [Fact]
    public async Task Live_SameBatchWritesOneObject()
    {
        string? bucket = Environment.GetEnvironmentVariable("BOWER_S3_LIVE_BUCKET");
        Assert.SkipWhen(bucket is null, "Set BOWER_S3_LIVE_BUCKET and BOWER_S3_LIVE_REGION to run against Amazon S3.");
        using S3Output output = new(new S3OutputOptions
        {
            Bucket = bucket,
            Region = Environment.GetEnvironmentVariable("BOWER_S3_LIVE_REGION") ?? "ap-southeast-2",
            Prefix = Environment.GetEnvironmentVariable("BOWER_S3_LIVE_PREFIX") ?? "live/idempotent",
            ExpectedBucketOwner = Environment.GetEnvironmentVariable("BOWER_S3_LIVE_OWNER")
        });
        QueuedEvent[] events =
        [
            .. Enumerable.Range(0, 5).Select(index => new QueuedEvent(
                $"live-idem-{index}",
                $"sha256:{index}",
                $$"""{"eventId":"live-idem-{{index}}","eventType":"authentication_failure","live":true}""",
                new DateTimeOffset(2026, 11, 5, 0, 0, index, TimeSpan.Zero)))
        ];

        DeliveryResult first = await output.DeliverAsync(events, TestContext.Current.CancellationToken);
        DeliveryResult retry = await output.DeliverAsync(events, TestContext.Current.CancellationToken);

        Assert.Empty(first.Failures);
        Assert.Empty(retry.Failures);
        Assert.Equal(events.Select(item => item.EventId), first.AcknowledgedEventIds);
        Assert.Equal(first.DestinationAcknowledgement, retry.DestinationAcknowledgement);
        TestContext.Current.SendDiagnosticMessage($"live acknowledgement: {first.DestinationAcknowledgement}");
    }

    private static Dictionary<string, string> S3Environment() => new()
    {
        ["BOWER_OUTPUT"] = "s3",
        ["BOWER_S3_BUCKET"] = "bower-test-bucket",
        ["BOWER_S3_REGION"] = "ap-southeast-2",
        ["BOWER_S3_PREFIX"] = "security/bower",
        ["BOWER_S3_SSE"] = "aws:kms"
    };

    private static S3OutputOptions Options() => new() { Bucket = "bower-test-bucket", Region = "ap-southeast-2" };

    private static QueuedEvent[] Events(int count) =>
    [
        .. Enumerable.Range(0, count).Select(index => new QueuedEvent(
            $"s3-{index}",
            $"sha256:{index}",
            $$"""{"eventId":"s3-{{index}}","eventType":"authentication_failed","n":{{index}}}""",
            TestEvents.Now.AddSeconds(index)))
    ];

    private static S3Output Create(FakeS3 s3, S3OutputOptions options)
    {
        AmazonS3Config config = new()
        {
            ServiceURL = "https://s3.test.invalid",
            AuthenticationRegion = options.Region,
            ForcePathStyle = true,
            MaxErrorRetry = 0,
            HttpClientFactory = new FakeHttpClientFactory(s3)
        };
        return new S3Output(options, new AmazonS3Client(new AnonymousAWSCredentials(), config), ownsClient: true);
    }

    private static string Gunzip(byte[] content)
    {
        using GZipStream gzip = new(new MemoryStream(content), CompressionMode.Decompress);
        using StreamReader reader = new(gzip, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static HttpResponseMessage Ok()
    {
        HttpResponseMessage response = new(HttpStatusCode.OK) { Content = new ByteArrayContent([]) };
        response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"etag\"");
        return response;
    }

    private static HttpResponseMessage Error(HttpStatusCode status, string code, string message = "denied") => new(status)
    {
        Content = new StringContent(
            $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message><RequestId>r</RequestId></Error>",
            Encoding.UTF8,
            "application/xml")
    };

    private sealed record CapturedPut(string Path, IReadOnlyDictionary<string, string> Headers, byte[] Body)
    {
        public string? Header(string name) => Headers.TryGetValue(name.ToLowerInvariant(), out string? value) ? value : null;
    }

    private sealed class FakeS3 : HttpMessageHandler
    {
        public List<CapturedPut> Puts { get; } = [];

        public Func<int, HttpResponseMessage> Respond { get; set; } = _ => Ok();

        public Func<Exception>? Throw { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Throw is not null)
            {
                throw Throw();
            }

            Dictionary<string, string> headers = new(StringComparer.Ordinal);
            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers.Concat(
                request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>()))
            {
                headers[header.Key.ToLowerInvariant()] = string.Join(',', header.Value);
            }

            byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Assert.Equal(HttpMethod.Put, request.Method);
            Puts.Add(new CapturedPut(Uri.UnescapeDataString(request.RequestUri!.AbsolutePath), headers, body));
            return Respond(Puts.Count - 1);
        }
    }

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : HttpClientFactory
    {
        public override HttpClient CreateHttpClient(IClientConfig clientConfig) => new(handler, disposeHandler: false);

        public override bool UseSDKHttpClientCaching(IClientConfig clientConfig) => false;

        public override bool DisposeHttpClientsAfterUse(IClientConfig clientConfig) => true;
    }

    private sealed class RecordingLogger : ILogger<QueueDeliveryWorker>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception) + (exception?.ToString() ?? string.Empty));
    }
}

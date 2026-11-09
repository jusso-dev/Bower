using System.IO.Compression;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Output.Http;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

/// <summary>
/// HTTP output (Splunk HEC and NDJSON). Request and response vectors in
/// tests/fixtures/http-output pin the wire format.
/// </summary>
public sealed class HttpOutputTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 1, 2, 3, TimeSpan.Zero);

    private static JsonObject Vectors { get; } = (JsonObject)JsonNode.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "http-output-vectors", "vectors.json")))!;

    private static string VectorToken => Vectors["token"]!.GetValue<string>();

    public static TheoryData<string> RequestVectors() =>
        [.. Vectors["requests"]!.AsArray().Select(item => item!["name"]!.GetValue<string>())];

    public static TheoryData<string> ResponseVectors() =>
        [.. Vectors["responses"]!.AsArray().Select(item => item!["name"]!.GetValue<string>())];

    public static TheoryData<string> ScenarioVectors() =>
        [.. Vectors["scenarios"]!.AsArray().Select(item => item!["name"]!.GetValue<string>())];

    public static TheoryData<string, bool> AuthHeaderVectors()
    {
        TheoryData<string, bool> data = [];
        foreach (JsonNode? item in Vectors["authHeaderNames"]!.AsArray())
        {
            data.Add(item!["name"]!.GetValue<string>(), item["allowed"]!.GetValue<bool>());
        }

        return data;
    }

    public static TheoryData<string, bool, bool> EndpointVectors()
    {
        TheoryData<string, bool, bool> data = [];
        foreach (JsonNode? item in Vectors["endpoints"]!.AsArray())
        {
            data.Add(item!["url"]!.GetValue<string>(), item["allowInsecureLoopback"]!.GetValue<bool>(), item["valid"]!.GetValue<bool>());
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(RequestVectors))]
    public async Task RequestVector_MatchesSharedBytesHeadersAndOutcomes(string name)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        JsonObject vector = Vectors["requests"]!.AsArray().Single(item => item!["name"]!.GetValue<string>() == name)!.AsObject();
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        using HttpOutput output = new(Options(vector["options"]!.AsObject(), endpoint.Url()), VectorToken);
        QueuedEvent[] events = [.. vector["events"]!.AsArray().Select(item => new QueuedEvent(
            item!["eventId"]!.GetValue<string>(), item["fingerprint"]!.GetValue<string>(), item["payload"]!.GetValue<string>(), Now))];

        DeliveryResult result = await output.DeliverAsync(events, cancellationToken);

        string[] expectedBodies = [.. vector["expectedBodies"]!.AsArray().Select(item => item!.GetValue<string>())];
        CapturedRequest[] requests = [.. endpoint.Requests];
        Assert.Equal(expectedBodies.Length, requests.Length);
        for (int index = 0; index < requests.Length; index++)
        {
            CapturedRequest request = requests[index];
            byte[] body = request.Headers.GetValueOrDefault("content-encoding") == "gzip" ? Gunzip(request.Body) : request.Body;
            Assert.Equal(expectedBodies[index], Encoding.UTF8.GetString(body));
            Assert.Equal(Encoding.UTF8.GetByteCount(expectedBodies[index]), body.Length);
            foreach ((string header, JsonNode? value) in vector["expectedHeaders"]!.AsObject())
            {
                Assert.Equal(value!.GetValue<string>(), request.Headers.GetValueOrDefault(header));
            }

            // The token travels in exactly one header and nowhere else.
            Assert.Single(request.Headers, header => header.Value.Contains(VectorToken, StringComparison.Ordinal));
            Assert.DoesNotContain(VectorToken, Encoding.UTF8.GetString(body), StringComparison.Ordinal);
        }

        (string, string)[] expectedFailures = [.. vector["expectedFailures"]!.AsArray()
            .Select(item => (item!["eventId"]!.GetValue<string>(), item["code"]!.GetValue<string>()))];
        Assert.Equal(expectedFailures, result.Failures.Select(failure => (failure.EventId, failure.Code)));
        Assert.All(result.Failures, failure => Assert.False(failure.IsRetryable));
        HashSet<string> failed = [.. expectedFailures.Select(item => item.Item1)];
        Assert.Equal(events.Select(item => item.EventId).Where(id => !failed.Contains(id)), result.AcknowledgedEventIds);
        Assert.Equal(vector["expectedAcknowledgement"]?.GetValue<string>(), result.DestinationAcknowledgement);
    }

    [Theory]
    [MemberData(nameof(ResponseVectors))]
    public async Task ResponseVector_ClassifiesAsShared(string name)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        JsonObject vector = Vectors["responses"]!.AsArray().Single(item => item!["name"]!.GetValue<string>() == name)!.AsObject();
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        endpoint.Reply = (_, _) => Task.FromResult(Reply(vector));
        HttpOutputFormat format = vector["format"]!.GetValue<string>() == "ndjson" ? HttpOutputFormat.Ndjson : HttpOutputFormat.SplunkHec;
        using HttpOutput output = new(
            new HttpOutputOptions { Endpoint = endpoint.Url(), AllowInsecureLoopback = true, Format = format, HecHost = "edge-01" },
            VectorToken,
            clock: new FakeClock(Now));

        DeliveryResult result = await output.DeliverAsync(
            [new QueuedEvent("evt-r", "f", """{"eventId":"evt-r","timeGenerated":"2026-11-05T01:02:03Z"}""", Now)], cancellationToken);

        Assert.Single(endpoint.Requests);
        if (vector["accepted"]!.GetValue<bool>())
        {
            Assert.Equal(["evt-r"], result.AcknowledgedEventIds);
            Assert.Empty(result.Failures);
            Assert.Equal(vector["expectedAcknowledgement"]!.GetValue<string>(), result.DestinationAcknowledgement);
            return;
        }

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Null(result.DestinationAcknowledgement);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal("evt-r", failure.EventId);
        Assert.Equal(vector["code"]!.GetValue<string>(), failure.Code);
        Assert.Equal(vector["retryable"]!.GetValue<bool>(), failure.IsRetryable);
        Assert.Equal(vector["destination"]!.GetValue<bool>(), failure.IsDestinationFailure);
        int? seconds = vector["retryAfterSeconds"]?.GetValue<int>();
        Assert.Equal(seconds is null ? null : Now.AddSeconds(seconds.Value), failure.RetryAfter);
        Assert.DoesNotContain("secret", failure.Code, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PayloadTooLargeForTheEndpointSplitsTheBatchUntilAccepted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        // The endpoint takes at most two records per request.
        endpoint.Reply = (request, _) => Task.FromResult(Lines(request) > 2
            ? new EndpointReply(413, """{"text":"Content too large","code":27}"""u8.ToArray())
            : EndpointReply.HecSuccess);
        using HttpOutput output = new(HecOptions(endpoint), "token-1");
        QueuedEvent[] events = Events(7);

        DeliveryResult result = await output.DeliverAsync(events, cancellationToken);

        Assert.Equal(events.Select(item => item.EventId), result.AcknowledgedEventIds);
        Assert.Empty(result.Failures);
        // 7 -> (3: 1 + 2) and (4: 2 + 2): every record sent once in an accepted request, in order.
        string[] accepted = [.. endpoint.Requests.Where(request => Lines(request) <= 2)
            .SelectMany(request => Encoding.UTF8.GetString(request.Body).Split('\n', StringSplitOptions.RemoveEmptyEntries))
            .Select(line => JsonNode.Parse(line)!["fields"]!["bower_event_id"]!.GetValue<string>())];
        Assert.Equal(events.Select(item => item.EventId), accepted);
    }

    [Fact]
    public async Task AlwaysTooLargeEndpointIsHeldWithinTheSplitBudget()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        endpoint.Reply = (_, _) => Task.FromResult(new EndpointReply(413));
        using HttpOutput output = new(HecOptions(endpoint), "token-1");

        DeliveryResult single = await output.DeliverAsync(Events(1), cancellationToken);
        DeliveryFailure held = Assert.Single(single.Failures);
        Assert.Equal("destination-http-413", held.Code);
        Assert.True(held.IsRetryable);

        while (endpoint.Requests.TryDequeue(out _))
        {
        }

        DeliveryResult many = await output.DeliverAsync(Events(200), cancellationToken);

        // One request plus two per split, never more; nothing is poison without a sibling's success.
        Assert.Equal(1 + 2 * HttpOutput.SplitBudget, endpoint.Requests.Count);
        Assert.Empty(many.AcknowledgedEventIds);
        Assert.Equal(200, many.Failures.Count);
        Assert.All(many.Failures, failure =>
        {
            Assert.Equal("destination-http-413", failure.Code);
            Assert.True(failure.IsDestinationFailure);
        });
    }

    [Fact]
    public async Task DestinationFailureStopsLaterBatchesAndKeepsThemRetryable()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        int calls = 0;
        endpoint.Reply = (_, _) => Task.FromResult(Interlocked.Increment(ref calls) == 1
            ? EndpointReply.HecSuccess
            : new EndpointReply(503, """{"text":"Server is busy","code":9}"""u8.ToArray(), new Dictionary<string, string> { ["Retry-After"] = "120" }));
        using HttpOutput output = new(HecOptions(endpoint) with { MaximumBatchEvents = 2 }, "token-1", clock: new FakeClock(Now));
        QueuedEvent[] events = Events(7);

        DeliveryResult result = await output.DeliverAsync(events, cancellationToken);

        Assert.Equal(2, endpoint.Requests.Count);
        Assert.Equal(["e0", "e1"], result.AcknowledgedEventIds);
        Assert.Equal("http:splunk-hec:endpoint-accepted", result.DestinationAcknowledgement);
        Assert.Equal(5, result.Failures.Count);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal("destination-http-503:hec-9", failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.Equal(Now.AddSeconds(120), failure.RetryAfter);
        });
    }

    [Fact]
    public async Task StalledEndpointTimesOutAsDestinationFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        endpoint.Reply = async (_, aborted) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, aborted);
            return EndpointReply.HecSuccess;
        };
        using HttpOutput output = new(HecOptions(endpoint) with { Timeout = TimeSpan.FromSeconds(1) }, "token-1");

        DeliveryResult result = await output.DeliverAsync(Events(3), cancellationToken);

        Assert.Empty(result.AcknowledgedEventIds);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal("destination-http-timeout", failure.Code);
            Assert.True(failure.IsDestinationFailure);
        });
        Assert.Equal(3, result.Failures.Count);
    }

    [Fact]
    public async Task StalledResponseBodyIsBoundedByTheSameDeadline()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using HttpOutput output = new(
            new HttpOutputOptions { Endpoint = new Uri("https://hec.example.test/services/collector/event"), HecHost = "h", Timeout = TimeSpan.FromSeconds(1) },
            "token-1",
            new StalledBodyHandler());

        DeliveryResult result = await output.DeliverAsync(Events(1), cancellationToken);

        Assert.Equal("destination-http-timeout", Assert.Single(result.Failures).Code);
    }

    [Fact]
    public async Task CallerCancellationPropagatesWhenNothingWasAccepted()
    {
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, TestContext.Current.CancellationToken);
        TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        endpoint.Reply = async (_, aborted) =>
        {
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, aborted);
            return EndpointReply.HecSuccess;
        };
        using HttpOutput output = new(HecOptions(endpoint), "token-1");
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        Task<DeliveryResult> delivery = output.DeliverAsync(Events(2), cancellation.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => delivery);
    }

    [Fact]
    public async Task CallerCancellationAfterAnAcceptedBatchKeepsItAndRetriesTheRest()
    {
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, TestContext.Current.CancellationToken);
        TaskCompletionSource second = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        endpoint.Reply = async (_, aborted) =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                return EndpointReply.HecSuccess;
            }

            second.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, aborted);
            return EndpointReply.HecSuccess;
        };
        using HttpOutput output = new(HecOptions(endpoint) with { MaximumBatchEvents = 1 }, "token-1");
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        Task<DeliveryResult> delivery = output.DeliverAsync(Events(3), cancellation.Token);
        await second.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();
        DeliveryResult result = await delivery;

        Assert.Equal(["e0"], result.AcknowledgedEventIds);
        Assert.Equal(["e1", "e2"], result.Failures.Select(failure => failure.EventId));
        Assert.All(result.Failures, failure => Assert.Equal("destination-http-cancelled", failure.Code));
    }

    [Fact]
    public async Task UnboundedChunkedResponseIsNotReadPastTheLimit()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        byte[] body = Encoding.UTF8.GetBytes("{\"code\":0" + new string(' ', HttpOutput.MaximumResponseBytes) + "}");
        endpoint.Reply = (_, _) => Task.FromResult(new EndpointReply(200, body, Chunked: true));
        using HttpOutput output = new(HecOptions(endpoint), "token-1");

        DeliveryResult result = await output.DeliverAsync(Events(1), cancellationToken);

        Assert.Equal("destination-http-response-invalid", Assert.Single(result.Failures).Code);
    }

    [Fact]
    public async Task Tls_UntrustedCertificateIsRefusedAndTheCaBundleTrustsIt()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using TestCertificateAuthority authority = new(directory.Path);
        using System.Security.Cryptography.X509Certificates.X509Certificate2 certificate = authority.Issue("localhost", includeLoopbackAddress: true);
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(certificate, cancellationToken);

        using HttpOutput untrusted = new(new HttpOutputOptions { Endpoint = endpoint.Url("localhost"), HecHost = "h" }, "token-1");
        DeliveryResult refused = await untrusted.DeliverAsync(Events(1), cancellationToken);
        using HttpOutput trusted = new(
            new HttpOutputOptions { Endpoint = endpoint.Url("localhost"), HecHost = "h", CaBundlePath = authority.BundlePath }, "token-1");
        DeliveryResult accepted = await trusted.DeliverAsync(Events(1), cancellationToken);

        Assert.Equal("destination-http-unavailable", Assert.Single(refused.Failures).Code);
        Assert.Equal(["e0"], accepted.AcknowledgedEventIds);
        // The refused handshake never carried the token: only the trusted request arrived.
        Assert.Single(endpoint.Requests);
    }

    [Fact]
    public async Task Tls_CaBundleNeverOverridesAHostNameMismatch()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        using TestCertificateAuthority authority = new(directory.Path);
        using System.Security.Cryptography.X509Certificates.X509Certificate2 certificate = authority.Issue("other.example.test", includeLoopbackAddress: false);
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(certificate, cancellationToken);
        using HttpOutput output = new(
            new HttpOutputOptions { Endpoint = endpoint.Url("localhost"), HecHost = "h", CaBundlePath = authority.BundlePath }, "token-1");

        DeliveryResult result = await output.DeliverAsync(Events(1), cancellationToken);

        Assert.Equal("destination-http-unavailable", Assert.Single(result.Failures).Code);
        Assert.Empty(endpoint.Requests);
    }

    [Theory]
    [MemberData(nameof(EndpointVectors))]
    public void EndpointPolicyVector_AllowsPlainHttpOnlyToLoopbackAddresses(string url, bool allowInsecureLoopback, bool valid)
    {
        HttpOutputOptions options = new() { Endpoint = new Uri(url), HecHost = "h", AllowInsecureLoopback = allowInsecureLoopback };

        if (valid)
        {
            options.Validate();
            return;
        }

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.StartsWith("BOWER_HTTP_URL must be an absolute https:// URL", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://user:pass@splunk.example.test/services/collector/event")]
    [InlineData("https://splunk.example.test/services/collector/event?token=abc")]
    [InlineData("https://splunk.example.test/services/collector/event#x")]
    [InlineData("ftp://splunk.example.test/")]
    public void EndpointPolicy_RefusesCredentialedOrOddUrlsWithoutEchoingThem(string url)
    {
        HttpOutputOptions options = new() { Endpoint = new Uri(url), HecHost = "h", AllowInsecureLoopback = true };

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.DoesNotContain("pass", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("abc", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PlainHttpNeverUsesAProxyAndHttpsKeepsTheStandardProxySettings()
    {
        using SocketsHttpHandler plain = HttpOutput.CreateHandler(
            new HttpOutputOptions { Endpoint = new Uri("http://127.0.0.1:8088/x"), HecHost = "h", AllowInsecureLoopback = true });
        using SocketsHttpHandler secure = HttpOutput.CreateHandler(
            new HttpOutputOptions { Endpoint = new Uri("https://splunk.example.test/x"), HecHost = "h" });

        Assert.False(plain.UseProxy);
        Assert.True(secure.UseProxy);
    }

    [Theory]
    [MemberData(nameof(AuthHeaderVectors))]
    public void AuthHeaderVector_AllowsOnlyNamesThatCanCarryTheToken(string name, bool allowed)
    {
        Assert.Equal(allowed, HttpOutputOptions.IsAllowedHeaderName(name));
        if (allowed)
        {
            // Every allowed name is one .NET adds to request headers, so the token is never dropped.
            using HttpRequestMessage request = new();
            Assert.True(request.Headers.TryAddWithoutValidation(name, "token"));
            using HttpOutput output = new(
                new HttpOutputOptions
                {
                    Endpoint = new Uri("https://intake.example.test/x"),
                    Format = HttpOutputFormat.Ndjson,
                    AuthorizationHeader = name,
                    HecHost = "h"
                },
                "token-1");
        }
    }

    [Theory]
    [InlineData("Content-Disposition")]
    [InlineData("Content-Range")]
    [InlineData("Content-Language")]
    [InlineData("Content-Type")]
    [InlineData("Content-Length")]
    [InlineData("Content-Location")]
    [InlineData("Content-MD5")]
    [InlineData("Content-Encoding")]
    [InlineData("Allow")]
    [InlineData("Expires")]
    [InlineData("Last-Modified")]
    public void AuthHeader_EveryHeaderDotNetRefusesOnRequestsIsRejected(string name)
    {
        using HttpRequestMessage request = new();
        Assert.False(request.Headers.TryAddWithoutValidation(name, "token"));

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => new HttpOutput(
            new HttpOutputOptions
            {
                Endpoint = new Uri("https://intake.example.test/x"),
                Format = HttpOutputFormat.Ndjson,
                AuthorizationHeader = name,
                HecHost = "h"
            },
            "token-1"));
        Assert.StartsWith("BOWER_HTTP_AUTH_HEADER must be an HTTP header name", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Tls_CaBundleWithAnIntermediateIsRefused()
    {
        using TemporaryDirectory directory = new();
        using TestCertificateAuthority authority = new(directory.Path);
        using System.Security.Cryptography.X509Certificates.X509Certificate2 intermediate = authority.IssueIntermediate();
        string bundle = Path.Combine(directory.Path, "with-intermediate.pem");
        File.WriteAllText(bundle, authority.Certificate.ExportCertificatePem() + "\n" + intermediate.ExportCertificatePem());

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => new HttpOutput(
            new HttpOutputOptions { Endpoint = new Uri("https://hec.example.test/x"), HecHost = "h", CaBundlePath = bundle }, "token-1"));

        Assert.Equal("BOWER_HTTP_CA_BUNDLE must hold only self-signed root CA certificates, not intermediates.", error.Message);
    }

    [Fact]
    public void Token_IsNeverEchoedOrPrinted()
    {
        const string secret = "s3cret token with spaces";
        HttpOutputOptions options = new() { Endpoint = new Uri("https://hec.example.test/services/collector/event"), HecHost = "h" };

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => new HttpOutput(options, secret));
        HttpOutputSettings settings = HttpOutputSettings.FromEnvironment(name => name switch
        {
            "BOWER_HTTP_URL" => "https://hec.example.test/services/collector/event",
            "BOWER_HTTP_TOKEN" => "abcdef0123456789",
            _ => null
        })!;

        Assert.DoesNotContain("s3cret", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("abcdef0123456789", settings.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("abcdef0123456789", options.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("abcdef0123456789", settings.HashMaterial(), StringComparison.Ordinal);
        Assert.Equal("abcdef0123456789", settings.ReadToken());
    }

    [Fact]
    public void Settings_ReadValidateAndBuildOptions()
    {
        using TemporaryDirectory directory = new();
        string tokenFile = Path.Combine(directory.Path, "hec-token");
        File.WriteAllText(tokenFile, "11111111-2222-3333-4444-555555555555\n");
        CollectorSettings settings = CollectorSettings.FromEnvironment(Environment(new()
        {
            ["BOWER_HTTP_TOKEN_FILE"] = tokenFile,
            ["BOWER_HTTP_HEC_INDEX"] = "security",
            ["BOWER_HTTP_MAX_BATCH_BYTES"] = "500000",
            ["BOWER_HTTP_GZIP"] = "TRUE"
        }));

        HttpOutputOptions options = settings.HttpOutput!.Options(settings.CollectorId);

        Assert.Equal("http", settings.OutputType);
        Assert.Equal(HttpOutputFormat.SplunkHec, options.Format);
        Assert.Equal("edge-01", options.HecHost);
        Assert.Equal("security", options.HecIndex);
        Assert.Equal("bower:security", options.HecSourceType);
        Assert.Equal(500_000, options.MaximumBatchBytes);
        Assert.True(options.Gzip);
        Assert.Equal("11111111-2222-3333-4444-555555555555", settings.HttpOutput.ReadToken());
    }

    [Theory]
    [InlineData("BOWER_OUTPUT", "none", "BOWER_HTTP_* settings require BOWER_OUTPUT=http.")]
    [InlineData("BOWER_HTTP_URL", "http://splunk.example.test/x", "BOWER_HTTP_URL must be an absolute https:// URL")]
    [InlineData("BOWER_HTTP_URL", "not a url", "BOWER_HTTP_URL must be an absolute https:// URL.")]
    [InlineData("BOWER_HTTP_TOKEN", "also-set", "BOWER_OUTPUT=http requires exactly one of BOWER_HTTP_TOKEN_FILE")]
    [InlineData("BOWER_HTTP_FORMAT", "json", "BOWER_HTTP_FORMAT must be splunk-hec or ndjson.")]
    [InlineData("BOWER_HTTP_AUTH_HEADER", "X-Api-Key", "BOWER_HTTP_AUTH_HEADER applies to BOWER_HTTP_FORMAT=ndjson only")]
    [InlineData("BOWER_HTTP_HEC_INDEX", "Security", "BOWER_HTTP_HEC_INDEX must be")]
    [InlineData("BOWER_HTTP_HEC_CHANNEL", "not-a-guid", "BOWER_HTTP_HEC_CHANNEL must be a GUID")]
    [InlineData("BOWER_HTTP_HEC_SOURCETYPE", "bower\u0001", "BOWER_HTTP_HEC_SOURCETYPE must be 1 to 256 characters")]
    [InlineData("BOWER_HTTP_MAX_BATCH_BYTES", "100", "BOWER_HTTP_MAX_BATCH_BYTES must be between 1024 and 16777216.")]
    [InlineData("BOWER_HTTP_MAX_BATCH_EVENTS", "0", "BOWER_HTTP_MAX_BATCH_EVENTS must be between 1 and 10000.")]
    [InlineData("BOWER_HTTP_TIMEOUT_SECONDS", "301", "BOWER_HTTP_TIMEOUT_SECONDS must be between 1 and 300.")]
    [InlineData("BOWER_HTTP_TIMEOUT_SECONDS", "ten", "BOWER_HTTP_TIMEOUT_SECONDS must be an integer.")]
    [InlineData("BOWER_HTTP_GZIP", "yes", "BOWER_HTTP_GZIP must be true or false.")]
    public void Settings_RefuseInvalidConfiguration(string name, string value, string message)
    {
        Dictionary<string, string> overrides = new() { ["BOWER_HTTP_TOKEN_FILE"] = "/run/secrets/hec-token", [name] = value };

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => CollectorSettings.FromEnvironment(Environment(overrides)));

        Assert.StartsWith(message, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Content-Type")]
    [InlineData("Content-Disposition")]
    [InlineData("Content-Range")]
    [InlineData("host")]
    [InlineData("Proxy-Authorization")]
    [InlineData("X Api")]
    public void Settings_RefuseReservedOrInvalidNdjsonAuthHeaders(string header)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(Environment(new()
        {
            ["BOWER_HTTP_TOKEN_FILE"] = "/run/secrets/token",
            ["BOWER_HTTP_FORMAT"] = "ndjson",
            ["BOWER_HTTP_AUTH_HEADER"] = header
        })));

        Assert.StartsWith("BOWER_HTTP_AUTH_HEADER must be an HTTP header name", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_RequireUrlTokenAndSplunkFormatForHecFields()
    {
        Assert.StartsWith("BOWER_OUTPUT=http requires BOWER_HTTP_URL",
            Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(name => name == "BOWER_OUTPUT" ? "http" : null)).Message,
            StringComparison.Ordinal);
        Assert.StartsWith("BOWER_OUTPUT=http requires exactly one of",
            Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(name => name switch
            {
                "BOWER_OUTPUT" => "http",
                "BOWER_HTTP_URL" => "https://hec.example.test/x",
                _ => null
            })).Message,
            StringComparison.Ordinal);
        Assert.Equal("BOWER_HTTP_HEC_* settings require BOWER_HTTP_FORMAT=splunk-hec.",
            Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(Environment(new()
            {
                ["BOWER_HTTP_TOKEN_FILE"] = "/run/secrets/token",
                ["BOWER_HTTP_FORMAT"] = "ndjson",
                ["BOWER_HTTP_HEC_SOURCE"] = "bower"
            }))).Message);
    }

    [Fact]
    public void ConfigurationHash_ExcludesTheTokenAndIsPinned()
    {
        CollectorSettings first = CollectorSettings.FromEnvironment(Environment(new() { ["BOWER_HTTP_TOKEN"] = "first-token-value" }));
        CollectorSettings second = CollectorSettings.FromEnvironment(Environment(new() { ["BOWER_HTTP_TOKEN"] = "second-token-value" }));
        CollectorSettings file = CollectorSettings.FromEnvironment(Environment(new() { ["BOWER_HTTP_TOKEN_FILE"] = "/run/secrets/hec-token" }));
        CollectorSettings gzip = CollectorSettings.FromEnvironment(Environment(new()
        {
            ["BOWER_HTTP_TOKEN_FILE"] = "/run/secrets/hec-token",
            ["BOWER_HTTP_GZIP"] = "true"
        }));

        Assert.Equal(first.ConfigurationHash(), second.ConfigurationHash());
        Assert.NotEqual(first.ConfigurationHash(), file.ConfigurationHash());
        Assert.NotEqual(file.ConfigurationHash(), gzip.ConfigurationHash());
        Assert.NotEqual(file.ConfigurationHash(), (file with { OutputType = "none", HttpOutput = null }).ConfigurationHash());
        Assert.Equal("sha256:667066988faae4ac1c592a085d9c047006642836ff5209297a32b2b85e4e5c56", PinnedSettings().ConfigurationHash());
    }

    [Theory]
    [InlineData("destination-http-unavailable", true)]
    [InlineData("destination-http-timeout", true)]
    [InlineData("destination-http-cancelled", true)]
    [InlineData("destination-http-response-invalid", true)]
    [InlineData("destination-http-503", true)]
    [InlineData("destination-http-401:hec-2", true)]
    [InlineData("http-400:hec-7", true)]
    [InlineData("http-413:hec-27", true)]
    [InlineData("http-400:hec-07", false)]
    [InlineData("http-400:hec-100", false)]
    [InlineData("http-400:hec-", false)]
    [InlineData("http-400:hec-7;x", false)]
    [InlineData("http-4000", false)]
    [InlineData("http-600", false)]
    [InlineData("destination-http-other", false)]
    public void Worker_PersistsOnlyBoundedHttpOutputCodes(string code, bool known)
    {
        Assert.Equal(known, QueueDeliveryWorker.IsHttpOutputCode(code));
    }

    [Fact]
    public async Task Queue_HoldsUnprovenFailuresAndDeadLettersOnlyIsolatedPoisonWithoutLoggingTheToken()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        const string token = "hec-token-0123456789abcdef";
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        using HttpOutput output = new(HecOptions(endpoint), token, clock: clock);
        using CapturingLoggerProvider logs = new();
        using ILoggerFactory factory = LoggerFactory.Create(builder => builder.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions(), factory.CreateLogger<QueueDeliveryWorker>());

        await store.EnqueueAsync(new QueuedEvent("q1", "sha256:q1", """{"eventId":"q1"}""", Now), cancellationToken);
        endpoint.Reply = (_, _) => Task.FromResult(new EndpointReply(503, """{"text":"Server is busy","code":9}"""u8.ToArray()));
        await worker.DeliverOnceAsync(cancellationToken);
        QueueSnapshot busy = await store.GetSnapshotAsync(cancellationToken);

        // Alone, a 400 is not proof the event is bad: it stays queued.
        clock.Advance(TimeSpan.FromHours(2));
        endpoint.Reply = (request, _) => Task.FromResult(Ids(request).Contains("q1")
            ? new EndpointReply(400, """{"text":"Invalid data format","code":6}"""u8.ToArray())
            : EndpointReply.HecSuccess);
        await worker.DeliverOnceAsync(cancellationToken);
        QueueSnapshot alone = await store.GetSnapshotAsync(cancellationToken);

        // With an accepted sibling in the same request lineage, it is isolated as poison.
        await store.EnqueueAsync(new QueuedEvent("q2", "sha256:q2", """{"eventId":"q2"}""", Now), cancellationToken);
        clock.Advance(TimeSpan.FromHours(2));
        await worker.DeliverOnceAsync(cancellationToken);
        QueueSnapshot isolated = await store.GetSnapshotAsync(cancellationToken);
        DeadLetterRecord record = Assert.Single(await store.ListDeadLetteredAsync(10, cancellationToken));

        Assert.Equal((1, 0L), (busy.Retrying, busy.Delivered));
        Assert.Equal((1, 0L), (alone.Retrying, alone.DeadLettered));
        Assert.Equal((1, 1L, 0L), (isolated.DeadLettered, isolated.Delivered, isolated.Retrying));
        Assert.Equal("q1", record.EventId);
        Assert.Equal("http-400:hec-6", record.FailureCode);
        Assert.Contains(logs.Messages, line => line.Contains("destination-http-503:hec-9", StringComparison.Ordinal));
        Assert.Contains(logs.Messages, line => line.Contains("destination-http-400:hec-6", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Messages, line => line.Contains(token, StringComparison.Ordinal));
        Assert.All(endpoint.Requests, request => Assert.Equal("Splunk " + token, request.Headers["authorization"]));
    }

    [Fact]
    public async Task Queue_SingleEventOnlyEndpointDeliversAllFiveHundredOverPassesWithoutDeadLetters()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        endpoint.Reply = (request, _) => Task.FromResult(Lines(request) > 1 ? new EndpointReply(413) : EndpointReply.HecSuccess);
        using HttpOutput output = new(HecOptions(endpoint), "token-1", clock: clock);
        // A tiny attempt budget: split deferrals must never spend it.
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions { MaximumDeliveryAttempts = 2 },
            Microsoft.Extensions.Logging.Abstractions.NullLogger<QueueDeliveryWorker>.Instance);
        foreach (QueuedEvent item in Events(500))
        {
            await store.EnqueueAsync(item, cancellationToken);
        }

        int passes = 0;
        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);
        while (snapshot.Delivered < 500 && passes++ < 200)
        {
            await worker.DeliverOnceAsync(cancellationToken);
            clock.Advance(TimeSpan.FromMinutes(2));
            snapshot = await store.GetSnapshotAsync(cancellationToken);
        }

        Assert.Equal(500, snapshot.Delivered);
        Assert.Equal(0, snapshot.DeadLettered);
        Assert.True(passes > 1, "the split budget must have forced more than one pass");
    }

    [Fact]
    public async Task Queue_AlwaysTooLargeEndpointNeverDeadLetters()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        SqliteEventStore store = new(Path.Combine(directory.Path, "queue.db"), 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        endpoint.Reply = (_, _) => Task.FromResult(new EndpointReply(413));
        using HttpOutput output = new(HecOptions(endpoint), "token-1", clock: clock);
        QueueDeliveryWorker worker = new(store, output, clock, new QueueDeliveryOptions { MaximumDeliveryAttempts = 2 },
            Microsoft.Extensions.Logging.Abstractions.NullLogger<QueueDeliveryWorker>.Instance);
        foreach (QueuedEvent item in Events(50))
        {
            await store.EnqueueAsync(item, cancellationToken);
        }

        for (int pass = 0; pass < 5; pass++)
        {
            await worker.DeliverOnceAsync(cancellationToken);
            clock.Advance(TimeSpan.FromMinutes(2));
        }

        QueueSnapshot snapshot = await store.GetSnapshotAsync(cancellationToken);
        Assert.Equal(0, snapshot.DeadLettered);
        Assert.Equal(0, snapshot.Delivered);
        Assert.Equal(50, snapshot.Retrying);
    }

    [Theory]
    [MemberData(nameof(ScenarioVectors))]
    public async Task ScenarioVector_IsolatesPoisonAndHoldsEverythingElse(string name)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        JsonObject vector = Vectors["scenarios"]!.AsArray().Single(item => item!["name"]!.GetValue<string>() == name)!.AsObject();
        JsonObject rule = vector["endpoint"]!.AsObject();
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        int requests = 0;
        endpoint.Reply = (request, _) => Task.FromResult(ScenarioReply(rule, Interlocked.Increment(ref requests), Ids(request)));
        HttpOutputOptions options = Options(vector["options"]!.AsObject(), endpoint.Url());
        using HttpOutput output = new(options, "token-1");
        QueuedEvent[] events = [.. Enumerable.Range(0, vector["events"]!.GetValue<int>())
            .Select(index => new QueuedEvent($"s-{index}", "f", $$"""{"eventId":"s-{{index}}"}""", Now))];

        DeliveryResult result = await output.DeliverAsync(events, cancellationToken);

        Assert.Equal(vector["expectedRequests"]!.GetValue<int>(), requests);
        Assert.Equal(vector["expectedAcknowledged"]!.AsArray().Select(item => item!.GetValue<string>()), result.AcknowledgedEventIds);
        Assert.Equal(
            vector["expectedFailures"]!.AsArray().Select(item => (
                item!["eventId"]!.GetValue<string>(), item["code"]!.GetValue<string>(), item["retryable"]!.GetValue<bool>())),
            result.Failures.Select(failure => (failure.EventId, failure.Code, failure.IsRetryable)));
        Assert.All(result.Failures, failure => Assert.Equal(failure.IsRetryable, failure.IsDestinationFailure));
        Assert.Equal(vector["expectedAcknowledgement"]?.GetValue<string>(), result.DestinationAcknowledgement);
    }

    [Fact]
    public async Task Collector_ReportsTheHttpOutputAndRefusedTokenWithoutTheToken()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        const string token = "hec-token-fedcba9876543210";
        const string ingestToken = "http-output-ingest-token-0123456789abcdef";
        using TemporaryDirectory directory = new();
        string tokenFile = Path.Combine(directory.Path, "hec-token");
        File.WriteAllText(tokenFile, token + "\n");
        await using TestHttpEndpoint endpoint = await TestHttpEndpoint.StartAsync(null, cancellationToken);
        endpoint.Reply = (_, _) => Task.FromResult(new EndpointReply(403, """{"text":"Invalid token","code":4}"""u8.ToArray()));
        using CapturingLoggerProvider logs = new();
        CollectorSettings settings = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "collector-test",
            SingleTrustDomain = true,
            IngestToken = ingestToken,
            OutputType = "http",
            HttpOutput = new HttpOutputSettings { Endpoint = endpoint.Url(), TokenFile = tokenFile, AllowInsecureLoopback = true }
        };
        await using WebApplication app = CollectorApplication.Build(settings, builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Logging.AddProvider(logs);
        });
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        HttpClient client = app.GetTestClient();
        using HttpRequestMessage post = new(HttpMethod.Post, "/v1/events")
        {
            Content = JsonContent.Create(TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, "http-e2e-1"), options: BowerJson.Options)
        };
        post.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ingestToken);
        using HttpResponseMessage posted = await client.SendAsync(post, cancellationToken);
        Assert.True(posted.IsSuccessStatusCode);

        string status = string.Empty;
        for (int attempt = 0; attempt < 100 && !status.Contains("destination-http-403", StringComparison.Ordinal); attempt++)
        {
            await Task.Delay(100, cancellationToken);
            using HttpRequestMessage request = new(HttpMethod.Get, "/v1/status");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ingestToken);
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            status = await response.Content.ReadAsStringAsync(cancellationToken);
        }

        await app.StopAsync(cancellationToken);
        Assert.Contains("\"output\":\"http\"", status, StringComparison.Ordinal);
        Assert.Contains("\"lastFailureCode\":\"destination-http-403:hec-4\"", status, StringComparison.Ordinal);
        Assert.Contains("\"retrying\":1", status, StringComparison.Ordinal);
        Assert.DoesNotContain(token, status, StringComparison.Ordinal);
        Assert.DoesNotContain(logs.Messages, line => line.Contains(token, StringComparison.Ordinal));
        Assert.Equal("Splunk " + token, endpoint.Requests.First().Headers["authorization"]);
    }

    internal static Func<string, string?> Environment(Dictionary<string, string> overrides)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal)
        {
            ["BOWER_COLLECTOR_ID"] = "edge-01",
            ["BOWER_OUTPUT"] = "http",
            ["BOWER_HTTP_URL"] = "https://splunk.example.test:8088/services/collector/event"
        };
        foreach ((string name, string value) in overrides)
        {
            values[name] = value;
        }

        return name => values.GetValueOrDefault(name);
    }

    /// <summary>The configuration pinned in the hash tests.</summary>
    internal static CollectorSettings PinnedSettings() => CollectorSettings.FromEnvironment(Environment(new()
    {
        ["BOWER_HTTP_TOKEN_FILE"] = "/run/secrets/hec-token",
        ["BOWER_HTTP_HEC_INDEX"] = "security",
        ["BOWER_HTTP_HEC_SOURCETYPE"] = "bower:security",
        ["BOWER_HTTP_HEC_CHANNEL"] = "0aecaf82-3f0c-4c5d-9e2b-7a1f5d9c2b10",
        ["BOWER_HTTP_CA_BUNDLE"] = "/etc/bower/splunk-ca.pem",
        ["BOWER_HTTP_MAX_BATCH_BYTES"] = "750000",
        ["BOWER_HTTP_MAX_BATCH_EVENTS"] = "250",
        ["BOWER_HTTP_TIMEOUT_SECONDS"] = "20",
        ["BOWER_HTTP_GZIP"] = "true"
    }));

    private static HttpOutputOptions Options(JsonObject options, Uri endpoint) => new()
    {
        Endpoint = endpoint,
        AllowInsecureLoopback = true,
        Format = options["format"]!.GetValue<string>() == "ndjson" ? HttpOutputFormat.Ndjson : HttpOutputFormat.SplunkHec,
        AuthorizationHeader = options["authorizationHeader"]?.GetValue<string>(),
        HecIndex = options["hecIndex"]?.GetValue<string>(),
        HecSource = options["hecSource"]?.GetValue<string>() ?? HttpOutputOptions.DefaultSource,
        HecSourceType = options["hecSourceType"]?.GetValue<string>() ?? HttpOutputOptions.DefaultSourceType,
        HecHost = options["hecHost"]?.GetValue<string>() ?? "edge-01",
        HecChannel = options["hecChannel"]?.GetValue<string>(),
        MaximumBatchBytes = options["maximumBatchBytes"]?.GetValue<int>() ?? HttpOutputOptions.DefaultMaximumBatchBytes,
        MaximumBatchEvents = options["maximumBatchEvents"]?.GetValue<int>() ?? HttpOutputOptions.DefaultMaximumBatchEvents,
        Gzip = options["gzip"]?.GetValue<bool>() ?? false
    };

    private static EndpointReply Reply(JsonObject vector)
    {
        string? body = vector["body"]?.GetValue<string>();
        int padding = vector["bodyPadding"]!.GetValue<int>();
        Dictionary<string, string> headers = new(StringComparer.Ordinal);
        if (vector["retryAfter"]?.GetValue<string>() is { } retryAfter)
        {
            headers["Retry-After"] = retryAfter;
        }

        if (vector["location"]?.GetValue<string>() is { } location)
        {
            headers["Location"] = location;
        }

        return new EndpointReply(
            vector["status"]!.GetValue<int>(),
            body is null ? null : Encoding.UTF8.GetBytes(body + new string(' ', padding)),
            headers);
    }

    private static HttpOutputOptions HecOptions(TestHttpEndpoint endpoint) =>
        new() { Endpoint = endpoint.Url(), AllowInsecureLoopback = true, HecHost = "edge-01" };

    private static QueuedEvent[] Events(int count) => [.. Enumerable.Range(0, count)
        .Select(index => new QueuedEvent($"e{index}", $"f{index}", $$"""{"eventId":"e{{index}}","n":{{index}}}""", Now))];

    private static int Lines(CapturedRequest request) => request.Body.Count(value => value == (byte)'\n');

    /// <summary>Event ids in a request body (HEC <c>fields.bower_event_id</c> or the NDJSON <c>eventId</c>).</summary>
    private static string[] Ids(CapturedRequest request) => [.. Encoding.UTF8.GetString(request.Body)
        .Split('\n', StringSplitOptions.RemoveEmptyEntries)
        .Select(line => JsonNode.Parse(line)!)
        .Select(line => (line["fields"]?["bower_event_id"] ?? line["eventId"])!.GetValue<string>())];

    /// <summary>The shared scenario endpoint: always, then by request number, then a record cap, then rejected ids.</summary>
    private static EndpointReply ScenarioReply(JsonObject rule, int request, string[] ids)
    {
        static EndpointReply Reply(JsonNode reply) => new(
            reply["status"]!.GetValue<int>(),
            reply["body"]?.GetValue<string>() is { } body ? Encoding.UTF8.GetBytes(body) : null);

        if (rule["always"] is { } always)
        {
            return Reply(always);
        }

        if (rule["byRequest"]?[request.ToString(System.Globalization.CultureInfo.InvariantCulture)] is { } byRequest)
        {
            return Reply(byRequest);
        }

        if (rule["maxRecords"] is { } maxRecords && ids.Length > maxRecords.GetValue<int>())
        {
            return new EndpointReply(413);
        }

        return rule["reject"] is { } reject && ids.Any(id => reject["eventIds"]!.AsArray().Any(item => item!.GetValue<string>() == id))
            ? Reply(reject)
            : EndpointReply.HecSuccess;
    }

    private static byte[] Gunzip(byte[] body)
    {
        using GZipStream gzip = new(new MemoryStream(body), CompressionMode.Decompress);
        using MemoryStream plain = new();
        gzip.CopyTo(plain);
        return plain.ToArray();
    }

    private sealed class StalledBodyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StreamContent(new StalledStream()) });
    }

    private sealed class StalledStream : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}

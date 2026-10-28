using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Relay;
using Bower.Contracts;
using Bower.Evidence;
using Bower.Forwarding;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>Relay role and relay output (issue #110): settings, pins, intake and the downstream client.</summary>
public sealed class RelayUnitTests
{
    private static readonly CollectorSettings Base = new()
    {
        ListenUrl = "http://127.0.0.1:4319",
        QueuePath = "queue.db",
        PolicyDirectory = "policies",
        CollectorId = "edge-01"
    };

    [Fact]
    public void Settings_ValidateDownstreamRole()
    {
        CollectorSettings downstream = Base with
        {
            OutputType = "relay",
            RelayUrl = new Uri("https://relay.example.test:4443"),
            RelayClientCertificateFile = "client.crt",
            RelayClientKeyFile = "client.key"
        };
        downstream.Validate();
        (downstream with { RelayCaBundle = "ca.pem" }).Validate();

        // The relay hop is always mutual TLS to an origin.
        Assert.Throws<InvalidOperationException>((downstream with { RelayUrl = null }).Validate);
        Assert.Throws<InvalidOperationException>((downstream with { RelayUrl = new Uri("http://relay.example.test:4443") }).Validate);
        Assert.Throws<InvalidOperationException>((downstream with { RelayUrl = new Uri("https://relay.example.test:4443/path") }).Validate);
        InvalidOperationException credentials = Assert.Throws<InvalidOperationException>(
            (downstream with { RelayUrl = new Uri("https://user:hunter2@relay.example.test:4443") }).Validate);
        Assert.DoesNotContain("hunter2", credentials.Message, StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>((downstream with { RelayClientKeyFile = null }).Validate);
        // Relay client settings without the relay output are a mistake, not ignored.
        Assert.Throws<InvalidOperationException>((Base with { RelayCaBundle = "ca.pem" }).Validate);

        CollectorSettings managed = downstream with
        {
            ManagementEndpoint = new Uri("https://management.example.test"),
            ManagementAuthentication = ManagementAuthenticationModes.Enrolment,
            ManagementViaRelay = true
        };
        managed.Validate();
        // Entra needs a route to Entra ID; a collector behind a relay enrols with a token.
        Assert.Throws<InvalidOperationException>((managed with
        {
            ManagementAuthentication = ManagementAuthenticationModes.Entra,
            ManagementScope = "api://bower/.default"
        }).Validate);
        Assert.Throws<InvalidOperationException>((managed with { ManagementProxy = new Uri("http://proxy:3128") }).Validate);
        Assert.Throws<InvalidOperationException>((managed with { OutputType = "none", RelayUrl = null, RelayClientCertificateFile = null, RelayClientKeyFile = null }).Validate);
    }

    [Fact]
    public void Settings_ValidateRelayRole()
    {
        CollectorSettings relay = Base with
        {
            RelayListenUrl = new Uri("https://0.0.0.0:4443"),
            RelayCertificateFile = "relay.crt",
            RelayKeyFile = "relay.key",
            RelayDownstreamsFile = "downstreams.json"
        };
        relay.Validate();
        Assert.True(relay.IsRelay);
        Assert.Throws<InvalidOperationException>((relay with { RelayDownstreamsFile = null }).Validate);
        Assert.Throws<InvalidOperationException>((relay with { RelayListenUrl = new Uri("http://0.0.0.0:4443") }).Validate);
        Assert.Throws<InvalidOperationException>((relay with { RelayListenUrl = new Uri("https://0.0.0.0") }).Validate);
        Assert.Throws<InvalidOperationException>((Base with { RelayDownstreamsFile = "downstreams.json" }).Validate);
        // One hop: a relay never delivers to another relay.
        Assert.Throws<InvalidOperationException>((relay with
        {
            OutputType = "relay",
            RelayUrl = new Uri("https://upstream.example.test:4443"),
            RelayClientCertificateFile = "c",
            RelayClientKeyFile = "k"
        }).Validate);
        // The tunnel goes only to this relay's own management endpoint, directly.
        Assert.Throws<InvalidOperationException>((relay with { RelayManagementTunnel = true }).Validate);
        CollectorSettings tunnel = relay with
        {
            RelayManagementTunnel = true,
            ManagementEndpoint = new Uri("https://management.example.test"),
            ManagementScope = "api://bower/.default"
        };
        tunnel.Validate();
        Assert.Throws<InvalidOperationException>((tunnel with { ManagementProxy = new Uri("http://proxy:3128") }).Validate);

        Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_RELAY_MANAGEMENT_TUNNEL" => "yes",
            _ => null
        }));
        CollectorSettings fromEnvironment = CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_COLLECTOR_ID" => "relay-01",
            "BOWER_RELAY_LISTEN_URL" => "https://0.0.0.0:4443",
            "BOWER_RELAY_CERTIFICATE_FILE" => "/etc/bower/relay.crt",
            "BOWER_RELAY_KEY_FILE" => "/run/secrets/relay.key",
            "BOWER_RELAY_DOWNSTREAMS_FILE" => "/etc/bower/downstreams.json",
            "BOWER_RELAY_MANAGEMENT_TUNNEL" => "TRUE",
            "BOWER_MANAGEMENT_ENDPOINT" => "https://management.example.test",
            "BOWER_MANAGEMENT_SCOPE" => "api://bower/.default",
            _ => null
        });
        Assert.True(fromEnvironment.RelayManagementTunnel);
        Assert.Equal(new Uri("https://0.0.0.0:4443"), fromEnvironment.RelayListenUrl);
    }

    [Fact]
    public void ConfigurationHash_IsUnchangedWithoutRelaySettingsAndPinned()
    {
        // Unset relay settings leave existing hashes alone; set ones change it.
        CollectorSettings relay = Base with
        {
            RelayListenUrl = new Uri("https://0.0.0.0:4443"),
            RelayCertificateFile = "/etc/bower/relay.crt",
            RelayKeyFile = "/run/secrets/relay.key",
            RelayDownstreamsFile = "/etc/bower/downstreams.json"
        };
        Assert.NotEqual(Base.ConfigurationHash(), relay.ConfigurationHash());
        // Certificate and key paths never enter the hash.
        Assert.Equal(relay.ConfigurationHash(), (relay with { RelayKeyFile = "/other.key", RelayCertificateFile = "/other.crt" }).ConfigurationHash());

        CollectorSettings downstream = Base with
        {
            OutputType = "relay",
            RelayUrl = new Uri("https://relay.example.test:4443"),
            RelayClientCertificateFile = "/etc/bower/client.crt",
            RelayClientKeyFile = "/run/secrets/client.key",
            RelayCaBundle = "/etc/bower/relay-ca.pem",
            ManagementEndpoint = new Uri("https://management.example.test"),
            ManagementAuthentication = ManagementAuthenticationModes.Enrolment,
            ManagementViaRelay = true
        };
        // Pinned in the Rust collector too (rust/crates/bower-collector/tests/relay.rs).
        Assert.Equal("sha256:f7d49a6ca37ccdb7646c42e142cb809b2559d901b45d5c53572db76a7f95a997", relay.ConfigurationHash());
        Assert.Equal("sha256:887f9f1f62c825dbe67b4e257a52bdc8c147c56a2dae0c8a80e936bd271b2ab4", downstream.ConfigurationHash());
    }

    [Fact]
    public void Downstreams_ParseStrictly()
    {
        string pin = new('a', 64);
        string other = new('b', 64);
        RelayDownstreams parsed = RelayDownstreams.Parse(Encoding.UTF8.GetBytes(
            $$"""{"downstreams":[{"collectorId":"edge-01","certificateSha256":"{{pin}}"},{"collectorId":"edge-01","certificateSha256":"{{Colons(other.ToUpperInvariant())}}"}]}"""));
        Assert.Equal(["edge-01"], parsed.CollectorIds);

        string[] invalid =
        [
            "[]",
            """{"downstreams":[]}""",
            $$"""{"downstreams":[{"collectorId":"edge-01","certificateSha256":"{{pin}}"},{"collectorId":"edge-02","certificateSha256":"{{pin}}"}]}""",
            $$"""{"downstreams":[{"collectorId":"edge-01","certificateSha256":"{{pin[..63]}}"}]}""",
            $$"""{"downstreams":[{"collectorId":"edge-01","certificateSha256":"{{new string('g', 64)}}"}]}""",
            $$"""{"downstreams":[{"collectorId":"","certificateSha256":"{{pin}}"}]}""",
            $$"""{"downstreams":[{"collectorId":"edge 01","certificateSha256":"{{pin}}"}]}""",
            $$"""{"downstreams":[{"collectorId":"edge-01","collectorId":"edge-02","certificateSha256":"{{pin}}"}]}""",
            $$"""{"downstreams":[{"collectorId":"edge-01"}]}""",
            "not json"
        ];
        foreach (string json in invalid)
        {
            Assert.Throws<InvalidOperationException>(() => RelayDownstreams.Parse(Encoding.UTF8.GetBytes(json)));
        }

        string tooMany = JsonSerializer.Serialize(new
        {
            downstreams = Enumerable.Range(0, RelayDownstreams.MaximumEntries + 1)
                .Select(index => new { collectorId = $"edge-{index}", certificateSha256 = index.ToString("x64", System.Globalization.CultureInfo.InvariantCulture) })
        });
        Assert.Throws<InvalidOperationException>(() => RelayDownstreams.Parse(Encoding.UTF8.GetBytes(tooMany)));
        Assert.Throws<InvalidOperationException>(() => RelayDownstreams.Load(Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.json")));

        static string Colons(string hex) => string.Join(':', Enumerable.Range(0, hex.Length / 2).Select(index => hex.Substring(index * 2, 2)));
    }

    [Fact]
    public async Task Intake_StoresPayloadBytesUnchangedAndIsIdempotent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (RelayIntake intake, SqliteEventStore store) = await IntakeAsync(directory, ct);
        (string payload, string fingerprint) = Arranged("event-a", "edge-01");

        RelayIntakeOutcome first = await intake.AcceptAsync("edge-01", Batch("edge-01", ("event-a", fingerprint, payload)), ct);
        RelayIntakeOutcome second = await intake.AcceptAsync("edge-01", Batch("edge-01", ("event-a", fingerprint, payload)), ct);

        Assert.Equal(200, first.StatusCode);
        Assert.Equal(RelayEventStatuses.Accepted, Assert.Single(first.Response!.Results).Status);
        Assert.Equal(RelayEventStatuses.Duplicate, Assert.Single(second.Response!.Results).Status);
        Assert.Equal("relay-01", first.Response.RelayId);
        Assert.Equal(1, first.Response.Ledger.Sequence);
        Assert.Equal(first.Response.Ledger, second.Response!.Ledger);
        var row = Assert.Single(RelayHosts.Rows(Path.Combine(directory.Path, "relay.db")));
        // Byte for byte: the relay ledger hashes exactly what the downstream stored.
        Assert.Equal(payload, row.Payload);
        Assert.True((await store.VerifyLedgerAsync(ct)).Intact);
    }

    [Fact]
    public async Task Intake_RefusesAnythingThatIsNotThisDownstreamsDecidedEnvelope()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (RelayIntake intake, _) = await IntakeAsync(directory, ct);
        (string payload, string fingerprint) = Arranged("event-a", "edge-01");
        (string foreign, string foreignFingerprint) = Arranged("event-b", "edge-02");
        (string undecided, string undecidedFingerprint) = Arranged("event-c", "edge-01", decided: false);

        RelayIntakeOutcome outcome = await intake.AcceptAsync("edge-01", Batch("edge-01",
            ("event-a", "sha256:v2:" + new string('0', 64), payload),
            ("event-b", foreignFingerprint, foreign),
            ("event-c", undecidedFingerprint, undecided),
            ("event-x", fingerprint, payload),
            ("event-d", "f", """{"eventId":"event-d"}""")), ct);

        Assert.Equal(200, outcome.StatusCode);
        Assert.Equal(
            [
                RelayRejectCodes.FingerprintMismatch,
                RelayRejectCodes.CollectorMismatch,
                RelayRejectCodes.PolicyDecisionMissing,
                RelayRejectCodes.EventIdMismatch,
                RelayRejectCodes.PayloadInvalid
            ],
            outcome.Response!.Results.Select(result => result.Code));
        Assert.All(outcome.Response.Results, result => Assert.Equal(RelayEventStatuses.Rejected, result.Status));
        Assert.Empty(RelayHosts.Rows(Path.Combine(directory.Path, "relay.db")));

        // The batch itself must name the authenticated downstream.
        RelayIntakeOutcome impersonation = await intake.AcceptAsync("edge-02", Batch("edge-01", ("event-a", fingerprint, payload)), ct);
        Assert.Equal(403, impersonation.StatusCode);

        // Same event id, different content: an identity conflict, never a silent duplicate.
        Assert.Equal(200, (await intake.AcceptAsync("edge-01", Batch("edge-01", ("event-a", fingerprint, payload)), ct)).StatusCode);
        string changed = payload.Replace("InvalidPassword", "LockedOut", StringComparison.Ordinal);
        RelayIntakeOutcome conflict = await intake.AcceptAsync("edge-01", Batch("edge-01", ("event-a", fingerprint, changed)), ct);
        Assert.Equal(RelayRejectCodes.IdentityConflict, Assert.Single(conflict.Response!.Results).Code);
    }

    [Theory]
    [InlineData("""{"schemaVersion":2,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}}]}""")]
    [InlineData("""{"schemaVersion":1,"collectorId":"edge-01","events":[]}""")]
    [InlineData("""{"schemaVersion":1,"collectorId":"edge-01","collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}}]}""")]
    [InlineData("""{"schemaVersion":1,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":{}},{"eventId":"a","fingerprint":"f","payload":{}}]}""")]
    [InlineData("""{"schemaVersion":1,"collectorId":"edge-01","events":[{"eventId":"a","fingerprint":"f","payload":"{}"}]}""")]
    [InlineData("""[1,2,3]""")]
    [InlineData("""{"schemaVersion":1""")]
    public async Task Intake_RefusesMalformedBatches(string body)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (RelayIntake intake, _) = await IntakeAsync(directory, ct);

        RelayIntakeOutcome outcome = await intake.AcceptAsync("edge-01", Encoding.UTF8.GetBytes(body), ct);

        Assert.Equal(400, outcome.StatusCode);
        Assert.Null(outcome.Response);
    }

    [Fact]
    public async Task Intake_RefusesTooManyEvents()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (RelayIntake intake, _) = await IntakeAsync(directory, ct);
        (string payload, string fingerprint) = Arranged("event-a", "edge-01");
        (string, string, string)[] events = [.. Enumerable.Range(0, RelayProtocol.MaximumBatchEvents + 1)
            .Select(index => ($"event-{index}", fingerprint, payload))];

        Assert.Equal(400, (await intake.AcceptAsync("edge-01", Batch("edge-01", events), ct)).StatusCode);
    }

    [Fact]
    public async Task Intake_FullQueueAnswers503AndKeepsCommittedEventsIdempotent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (RelayIntake intake, SqliteEventStore store) = await IntakeAsync(directory, ct, maximumBytes: 1_048_576);
        string padding = new('x', 300_000);
        (string, string, string)[] events = [.. Enumerable.Range(0, 5).Select(index =>
        {
            (string payload, string fingerprint) = Arranged($"event-{index}", "edge-01", padding: padding);
            return ($"event-{index}", fingerprint, payload);
        })];

        RelayIntakeOutcome full = await intake.AcceptAsync("edge-01", Batch("edge-01", events), ct);

        Assert.Equal(503, full.StatusCode);
        int committed = RelayHosts.Rows(Path.Combine(directory.Path, "relay.db")).Count;
        Assert.InRange(committed, 1, 4);

        // Space frees up (the relay delivered); the downstream retries the whole batch.
        foreach (QueuedEvent leased in await store.LeaseAsync(10, TimeSpan.FromMinutes(1), ct))
        {
            await store.MarkDeliveredAsync(leased.EventId, "test", leased.LeaseToken, ct);
        }

        RelayIntakeOutcome retried = await intake.AcceptAsync("edge-01", Batch("edge-01", events[..committed]), ct);
        Assert.All(retried.Response!.Results, result => Assert.Equal(RelayEventStatuses.Duplicate, result.Status));
        Assert.Equal(committed, RelayHosts.Rows(Path.Combine(directory.Path, "relay.db")).Count);
    }

    [Fact]
    public async Task Output_AcknowledgesOnlyCommittedEventsAndSendsPayloadsUnchanged()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        List<JsonDocument> requests = [];
        using FakeRelay relay = new(request =>
        {
            JsonDocument body = JsonDocument.Parse(request);
            requests.Add(body);
            JsonElement[] events = [.. body.RootElement.GetProperty("events").EnumerateArray()];
            return (HttpStatusCode.OK, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                relayId = "relay-01",
                ledger = new { sequence = 41, hash = "abc" },
                results = new object[]
                {
                    new { eventId = events[0].GetProperty("eventId").GetString(), status = "accepted" },
                    new { eventId = events[1].GetProperty("eventId").GetString(), status = "duplicate" },
                    new { eventId = events[2].GetProperty("eventId").GetString(), status = "rejected", code = "collector-mismatch" },
                    new { eventId = events[3].GetProperty("eventId").GetString(), status = "rejected", code = "Not A Code" }
                }
            }), null);
        });
        string payload = """{"eventId":"e1","attributes":{"text":"café \"quoted\""}}""";
        QueuedEvent[] events =
        [
            new("e1", "f1", payload, DateTimeOffset.UtcNow),
            new("e2", "f2", """{"eventId":"e2"}""", DateTimeOffset.UtcNow),
            new("e3", "f3", """{"eventId":"e3"}""", DateTimeOffset.UtcNow),
            new("e4", "f4", """{"eventId":"e4"}""", DateTimeOffset.UtcNow),
            new("e5", "f5", """{"eventId":"e5"}""", DateTimeOffset.UtcNow),
            new("e6", "f6", "not json", DateTimeOffset.UtcNow)
        ];

        DeliveryResult result = await relay.Output("edge-01").DeliverAsync(events, ct);

        Assert.Equal(["e1", "e2"], result.AcknowledgedEventIds);
        Assert.Equal("relay:relay-01:ledger:41", result.DestinationAcknowledgement);
        Assert.Contains(result.Failures, failure => failure is { EventId: "e3", Code: "relay-rejected:collector-mismatch", IsRetryable: false });
        Assert.Contains(result.Failures, failure => failure is { EventId: "e4", Code: "relay-rejected:unknown", IsRetryable: false });
        Assert.Contains(result.Failures, failure => failure is { EventId: "e5", Code: "destination-relay-result-missing", IsRetryable: true, IsDestinationFailure: true });
        Assert.Contains(result.Failures, failure => failure is { EventId: "e6", Code: "payload-invalid-json", IsRetryable: false });
        JsonElement sent = Assert.Single(requests).RootElement;
        Assert.Equal("edge-01", sent.GetProperty("collectorId").GetString());
        Assert.Equal(1, sent.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(payload, sent.GetProperty("events")[0].GetProperty("payload").GetRawText());
        Assert.Equal(5, sent.GetProperty("events").GetArrayLength());
    }

    [Theory]
    [InlineData("not-json", "destination-relay-response-invalid")]
    [InlineData("{\"schemaVersion\":1,\"relayId\":\"r\",\"ledger\":{\"sequence\":1,\"hash\":\"h\"},\"results\":[]}", "destination-relay-result-missing")]
    [InlineData("{\"schemaVersion\":1,\"relayId\":\"r\",\"ledger\":{\"sequence\":1,\"hash\":\"h\"},\"results\":[{\"eventId\":\"e0\",\"status\":\"pending\"}]}", "destination-relay-response-invalid")]
    public async Task Output_MalformedResponsesHoldAllBatchesWithoutSpendingAttempts(string body, string code)
    {
        int calls = 0;
        using FakeRelay relay = new(_ =>
        {
            calls++;
            return (HttpStatusCode.OK, body, null);
        });
        QueuedEvent[] events = [.. Enumerable.Range(0, RelayProtocol.MaximumBatchEvents + 1)
            .Select(index => new QueuedEvent($"e{index}", $"f{index}", $$"""{"eventId":"e{{index}}"}""", DateTimeOffset.UtcNow))];

        DeliveryResult result = await relay.Output("edge-01").DeliverAsync(events, TestContext.Current.CancellationToken);

        Assert.Equal(1, calls);
        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Equal(events.Length, result.Failures.Count);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal(code, failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
        });
    }

    [Theory]
    [InlineData("3601", true)]
    [InlineData("2147483647", true)]
    [InlineData("100000000000000", false)]
    [InlineData("9223372036854775807", false)]
    [InlineData("0", false)]
    [InlineData("-1", false)]
    public async Task Output_RetryAfterIsBoundedOrIgnored(string header, bool hasRetry)
    {
        using FakeRelay relay = new(_ => (HttpStatusCode.ServiceUnavailable, "{}", null), header);
        DateTimeOffset before = DateTimeOffset.UtcNow;
        DeliveryResult result = await relay.Output("edge-01").DeliverAsync(
            [new QueuedEvent("e0", "f0", "{}", before)], TestContext.Current.CancellationToken);
        DeliveryFailure failure = Assert.Single(result.Failures);
        Assert.Equal("destination-relay-http-503", failure.Code);
        Assert.True(failure.IsDestinationFailure);
        if (hasRetry)
        {
            Assert.NotNull(failure.RetryAfter);
            Assert.InRange(failure.RetryAfter.Value, before.AddHours(1), DateTimeOffset.UtcNow.AddHours(1));
        }
        else
        {
            Assert.Null(failure.RetryAfter);
        }
    }

    [Fact]
    public async Task Output_RelayOutageHoldsEveryEventBehindTheDestinationCircuit()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        int calls = 0;
        using FakeRelay unavailable = new(_ =>
        {
            calls++;
            return (HttpStatusCode.ServiceUnavailable, """{"error":"full"}""", TimeSpan.FromSeconds(30));
        });
        QueuedEvent[] events = [.. Enumerable.Range(0, RelayProtocol.MaximumBatchEvents + 10)
            .Select(index => new QueuedEvent($"e{index}", $"f{index}", $$"""{"eventId":"e{{index}}"}""", DateTimeOffset.UtcNow))];

        DeliveryResult result = await unavailable.Output("edge-01").DeliverAsync(events, ct);

        // Two batches were due; after the first refusal the second is never sent.
        Assert.Equal(1, calls);
        Assert.Empty(result.AcknowledgedEventIds);
        Assert.Equal(events.Length, result.Failures.Count);
        Assert.All(result.Failures, failure =>
        {
            Assert.Equal("destination-relay-http-503", failure.Code);
            Assert.True(failure.IsRetryable);
            Assert.True(failure.IsDestinationFailure);
            Assert.NotNull(failure.RetryAfter);
        });

        using FakeRelay refused = new(_ => (HttpStatusCode.BadRequest, "{}", null));
        DeliveryFailure bad = Assert.Single((await refused.Output("edge-01").DeliverAsync(events[..1], ct)).Failures);
        Assert.Equal("relay-http-400", bad.Code);
        Assert.False(bad.IsDestinationFailure);

        using FakeRelay garbage = new(_ => (HttpStatusCode.OK, """{"schemaVersion":1,"relayId":"r","ledger":{"sequence":1,"hash":"h"},"results":[{"eventId":"other","status":"accepted"}]}""", null));
        Assert.Equal("destination-relay-response-invalid", Assert.Single((await garbage.Output("edge-01").DeliverAsync(events[..1], ct)).Failures).Code);

        using FakeRelay broken = new(_ => throw new HttpRequestException("connection refused"));
        Assert.Equal("destination-relay-unavailable", Assert.Single((await broken.Output("edge-01").DeliverAsync(events[..1], ct)).Failures).Code);
    }

    internal static async Task<(RelayIntake Intake, SqliteEventStore Store)> IntakeAsync(
        TemporaryDirectory directory,
        CancellationToken ct,
        long maximumBytes = 64L * 1024 * 1024)
    {
        SqliteEventStore store = new(Path.Combine(directory.Path, "relay.db"), maximumBytes);
        await store.InitializeAsync(ct);
        RelayIntake intake = new(store, Base with { CollectorId = "relay-01" }, new RelayTelemetry(["edge-01"]), TimeProvider.System);
        return (intake, store);
    }

    /// <summary>An envelope as a downstream collector queues it: decided, collector-stamped, fingerprinted.</summary>
    internal static (string Payload, string Fingerprint) Arranged(string eventId, string collectorId, bool decided = true, string? padding = null)
    {
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(TestEvents.Now, eventId: eventId, originalId: "source-" + eventId) with
        {
            Security = decided
                ? new SecurityDecisionContext
                {
                    PolicyId = "BWR-POL-AUTH-FAILURE",
                    PolicyVersion = "1.0.0",
                    PolicyHash = "sha256:test",
                    ValueScore = 80,
                    Decision = DecisionAction.Accept,
                    ClassificationReasons = ["authentication-failure"]
                }
                : null,
            Collector = new CollectorContext
            {
                Id = collectorId,
                Version = "0.1.0",
                SourceAdapter = "local-http:anonymous",
                ConfigurationHash = "sha256:test",
                ReceivedAt = TestEvents.Now
            },
            Attributes = padding is null ? null : new Dictionary<string, JsonElement> { ["padding"] = JsonSerializer.SerializeToElement(padding) }
        };
        return (JsonSerializer.Serialize(envelope, BowerJson.Envelope), EventIdentity.Create(envelope));
    }

    internal static byte[] Batch(string collectorId, params (string EventId, string Fingerprint, string Payload)[] events)
    {
        StringBuilder json = new();
        json.Append("{\"schemaVersion\":1,\"collectorId\":").Append(JsonSerializer.Serialize(collectorId)).Append(",\"events\":[");
        for (int index = 0; index < events.Length; index++)
        {
            if (index > 0)
            {
                json.Append(',');
            }

            json.Append("{\"eventId\":").Append(JsonSerializer.Serialize(events[index].EventId))
                .Append(",\"fingerprint\":").Append(JsonSerializer.Serialize(events[index].Fingerprint))
                .Append(",\"payload\":").Append(events[index].Payload).Append('}');
        }

        return Encoding.UTF8.GetBytes(json.Append("]}").ToString());
    }

    private sealed class FakeRelay(Func<string, (HttpStatusCode Status, string Body, TimeSpan? RetryAfter)> respond, string? rawRetryAfter = null)
        : HttpMessageHandler
    {
        public RelayOutput Output(string collectorId) =>
            new(new HttpClient(this, disposeHandler: false) { BaseAddress = new Uri("https://relay.example.test:4443/") }, collectorId);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/v1/relay/batches", request.RequestUri!.AbsolutePath);
            (HttpStatusCode status, string body, TimeSpan? retryAfter) = respond(await request.Content!.ReadAsStringAsync(cancellationToken));
            HttpResponseMessage response = new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            if (rawRetryAfter is not null)
            {
                response.Headers.TryAddWithoutValidation("Retry-After", rawRetryAfter);
            }
            else if (retryAfter is { } delay)
            {
                response.Headers.RetryAfter = new RetryConditionHeaderValue(delay);
            }

            return response;
        }
    }
}

/// <summary>
/// Downstream collector, relay and destination in one process, over real mutual TLS
/// (issue #110 acceptance: delivery and evidence through one relay, no duplicates on relay restart).
/// </summary>
[Collection(SerialHostTests.Name)]
public sealed class RelayEndToEndTests
{
    [Fact]
    public async Task DeliversThroughOneRelay_WithLedgersThatAgreeEndToEnd()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        RelayPki pki = new(directory.Path);
        var client = pki.CreateClient("edge-01");
        CapturingOutput destination = new();
        await using WebApplication relay = await RelayHosts.StartAsync(
            RelayHosts.Relay(directory.Path, pki, pki.WriteDownstreams(("edge-01", client.Pin)), 0), ct, destination);
        CollectorSettings edgeSettings = RelayHosts.Downstream(directory.Path, pki, client, RelayHosts.RelayPort(relay));
        await using WebApplication edge = await RelayHosts.StartAsync(edgeSettings, ct);
        HttpClient ingest = edge.GetTestClient();

        string[] ids = ["relay-e2e-1", "relay-e2e-2", "relay-e2e-3"];
        foreach (string id in ids)
        {
            using HttpRequestMessage request = Post(RelayHosts.Event(id) with
            {
                Attributes = new Dictionary<string, JsonElement> { ["dbPassword"] = JsonSerializer.SerializeToElement("never-leaves-the-edge") }
            });
            using HttpResponseMessage response = await ingest.SendAsync(request, ct);
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }

        // The edge also queues a privacy alert for each detected secret; it crosses the relay too.
        await RelayHosts.WaitForAsync(() =>
        {
            var rows = RelayHosts.Rows(edgeSettings.QueuePath);
            return Task.FromResult(rows.Count > ids.Length
                && destination.Delivered.Count == rows.Count
                && rows.All(row => row.State == (int)QueueState.Delivered));
        }, ct);

        string relayQueue = RelayHosts.Relay(directory.Path, pki, "unused", 0).QueuePath;
        var edgeRows = RelayHosts.Rows(edgeSettings.QueuePath);
        Assert.Subset(edgeRows.Select(row => row.EventId).ToHashSet(StringComparer.Ordinal), ids.ToHashSet(StringComparer.Ordinal));
        Assert.All(edgeRows, row => Assert.StartsWith("relay:relay-01:ledger:", row.Acknowledgement, StringComparison.Ordinal));
        // The destination gets exactly what the edge stored: redacted at the edge, unchanged by the relay.
        Assert.Equal(
            edgeRows.Select(row => row.Payload),
            destination.Delivered.OrderBy(item => item.EventId, StringComparer.Ordinal).Select(item => item.Payload));
        Assert.All(destination.Delivered, item => Assert.DoesNotContain("never-leaves-the-edge", item.Payload, StringComparison.Ordinal));
        Assert.All(destination.Delivered, item => Assert.Contains("\"id\":\"edge-01\"", item.Payload, StringComparison.Ordinal));
        // The ledger chain continues across the hop: both ledgers commit to the same payload hashes.
        Dictionary<string, string> edgeLedger = RelayHosts.LedgerHashes(edgeSettings.QueuePath);
        Dictionary<string, string> relayLedger = RelayHosts.LedgerHashes(relayQueue);
        Assert.Equal(edgeRows.Count, relayLedger.Count);
        Assert.All(edgeRows, row => Assert.Equal(edgeLedger[row.EventId], relayLedger[row.EventId]));
        Assert.True((await RelayHosts.VerifyAsync(edgeSettings.QueuePath, ct)).Intact);
        Assert.True((await RelayHosts.VerifyAsync(relayQueue, ct)).Intact);

        // Relay status: counters per pinned downstream, metadata only.
        using HttpRequestMessage statusRequest = new(HttpMethod.Get, "/v1/status");
        using HttpResponseMessage status = await relay.GetTestClient().SendAsync(statusRequest, ct);
        string body = await status.Content.ReadAsStringAsync(ct);
        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement downstream = Assert.Single(document.RootElement.GetProperty("relay").GetProperty("downstreams").EnumerateArray());
        Assert.Equal("edge-01", downstream.GetProperty("collectorId").GetString());
        Assert.Equal(edgeRows.Count, downstream.GetProperty("accepted").GetInt64());
        Assert.DoesNotContain("relay-e2e-1", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EvidenceCanary_ThroughOneRelay_IsFoundAtTheDestination()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        RelayPki pki = new(directory.Path);
        var client = pki.CreateClient("edge-01");
        CapturingOutput destination = new();
        await using WebApplication relay = await RelayHosts.StartAsync(
            RelayHosts.Relay(directory.Path, pki, pki.WriteDownstreams(("edge-01", client.Pin)), 0), ct, destination);
        await using WebApplication edge = await RelayHosts.StartAsync(
            RelayHosts.Downstream(directory.Path, pki, client, RelayHosts.RelayPort(relay)), ct);

        EvidenceRunner runner = new(new HttpCanarySender(edge.GetTestClient()), new DestinationQuery(destination), null, TimeProvider.System);
        EvidenceBundle bundle = await runner.RunAsync(new EvidenceOptions
        {
            CollectorUrl = new Uri("http://localhost/"),
            IngestToken = RelayHosts.IngestToken,
            WorkspaceId = "00000000-0000-0000-0000-000000000000",
            Timeout = TimeSpan.FromSeconds(30),
            PollInterval = TimeSpan.FromMilliseconds(100)
        }, ct);

        Assert.Equal(EvidenceModes.Verified, bundle.Mode);
        Assert.True(bundle.Arrival.Found);
        QueuedEvent canary = Assert.Single(destination.Delivered);
        Assert.Equal(bundle.Canary.EventId, canary.EventId);
        Assert.Equal(JsonNode.Parse(canary.Payload)!["security"]!["policyHash"]!.GetValue<string>(), bundle.Arrival.RowPolicyHash);
    }

    [Fact]
    public async Task RelayRestart_NeitherDuplicatesNorLosesEvents()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        RelayPki pki = new(directory.Path);
        var client = pki.CreateClient("edge-01");
        int port = RelayHosts.FreePort();
        CollectorSettings relaySettings = RelayHosts.Relay(directory.Path, pki, pki.WriteDownstreams(("edge-01", client.Pin)), port);
        CollectorSettings edgeSettings = RelayHosts.Downstream(directory.Path, pki, client, port);
        (string, string, string)[] batch = [.. Enumerable.Range(0, 20).Select(index =>
        {
            (string payload, string fingerprint) = RelayUnitTests.Arranged($"restart-{index}", "edge-01");
            return ($"restart-{index}", fingerprint, payload);
        })];
        QueuedEvent[] events = [.. batch.Select(item => new QueuedEvent(item.Item1, item.Item2, item.Item3, DateTimeOffset.UtcNow))];
        using RelayHttp http = new(edgeSettings);
        RelayOutput output = new(new HttpClient(http.CreateBatchHandler()) { BaseAddress = edgeSettings.RelayUrl }, "edge-01");

        // First relay process: commits the batch, then stops before delivering any of it
        // (no output configured), so the events are still in the relay queue.
        WebApplication first = await RelayHosts.StartAsync(relaySettings, ct);
        DeliveryResult delivered = await output.DeliverAsync(events, ct);
        Assert.Equal(events.Length, delivered.AcknowledgedEventIds.Count);
        await first.StopAsync(ct);
        await first.DisposeAsync();
        Assert.All(RelayHosts.Rows(relaySettings.QueuePath), row => Assert.Equal((int)QueueState.Queued, row.State));

        // The relay is gone: the downstream keeps everything (destination circuit, no ack).
        DeliveryResult offline = await output.DeliverAsync(events, ct);
        Assert.Empty(offline.AcknowledgedEventIds);
        Assert.All(offline.Failures, failure => Assert.Equal("destination-relay-unavailable", failure.Code));

        // Second relay process on the same queue. The downstream resends the batch whose
        // response it never saw: every event is a duplicate, nothing is queued twice.
        CapturingOutput up = new();
        await using WebApplication second = await RelayHosts.StartAsync(relaySettings, ct, up);
        DeliveryResult resent = await output.DeliverAsync(events, ct);
        Assert.Equal(events.Length, resent.AcknowledgedEventIds.Count);

        await RelayHosts.WaitForAsync(() => Task.FromResult(up.Delivered.Count >= events.Length
            && RelayHosts.Rows(relaySettings.QueuePath).All(row => row.State == (int)QueueState.Delivered)), ct);
        Assert.Equal(events.Length, RelayHosts.Rows(relaySettings.QueuePath).Count);
        Assert.Equal(
            events.Select(item => item.EventId).Order(StringComparer.Ordinal),
            up.Delivered.Select(item => item.EventId).Order(StringComparer.Ordinal));
        Assert.True((await RelayHosts.VerifyAsync(relaySettings.QueuePath, ct)).Intact);
    }

    [Fact]
    public async Task MutualTls_RefusesUnpinnedCertificatesImpersonationAndUntrustedRelays()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        RelayPki pki = new(directory.Path);
        var pinned = pki.CreateClient("edge-01");
        var unpinned = pki.CreateClient("intruder");
        var expired = pki.CreateClient("expired", notAfter: DateTimeOffset.UtcNow.AddMinutes(-5));
        var serverOnly = pki.CreateClient("server-usage", usage: "1.3.6.1.5.5.7.3.1");
        CapturingOutput destination = new();
        await using WebApplication relay = await RelayHosts.StartAsync(
            RelayHosts.Relay(directory.Path, pki, pki.WriteDownstreams(
                ("edge-01", pinned.Pin), ("expired", expired.Pin), ("server-usage", serverOnly.Pin)), 0),
            ct,
            destination);
        int port = RelayHosts.RelayPort(relay);
        (string payload, string fingerprint) = RelayUnitTests.Arranged("tls-1", "edge-01");
        QueuedEvent[] events = [new("tls-1", fingerprint, payload, DateTimeOffset.UtcNow)];

        Assert.Equal("destination-relay-unavailable", await FailureAsync(unpinned, "edge-01"));
        Assert.Equal("destination-relay-unavailable", await FailureAsync(expired, "expired"));
        Assert.Equal("destination-relay-unavailable", await FailureAsync(serverOnly, "server-usage"));
        // A pinned downstream cannot submit as another collector.
        Assert.Equal("destination-relay-http-403", await FailureAsync(pinned, "edge-02"));
        // The downstream refuses a relay whose certificate it cannot verify.
        Assert.Equal("destination-relay-unavailable", await FailureAsync(pinned, "edge-01", trustRelay: false));
        Assert.Empty(RelayHosts.Rows(RelayHosts.Relay(directory.Path, pki, "unused", 0).QueuePath));

        async Task<string> FailureAsync((string Certificate, string Key, string Pin) client, string collectorId, bool trustRelay = true)
        {
            CollectorSettings settings = RelayHosts.Downstream(directory.Path, pki, client, port, collectorId)
                with
            { RelayCaBundle = trustRelay ? pki.CaBundle : null };
            using RelayHttp http = new(settings);
            RelayOutput output = new(new HttpClient(http.CreateBatchHandler()) { BaseAddress = settings.RelayUrl }, collectorId);
            DeliveryResult result = await output.DeliverAsync(events, ct);
            Assert.Empty(result.AcknowledgedEventIds);
            return Assert.Single(result.Failures).Code;
        }
    }

    [Fact]
    public void ConnectHost_StripsIpv6BracketsOnly()
    {
        Assert.Equal("::1", RelayCertificates.ConnectHost(new Uri("https://[::1]:4443")));
        Assert.Equal("127.0.0.1", RelayCertificates.ConnectHost(new Uri("https://127.0.0.1:4443")));
        Assert.Equal("xn--bcher-kva.example", RelayCertificates.ConnectHost(new Uri("https://bücher.example:4443")));
    }

    [Fact]
    public async Task DeliversToARelayAddressedByIpv6Literal()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        RelayPki pki = new(directory.Path);
        var client = pki.CreateClient("edge-01");
        CapturingOutput destination = new();
        await using WebApplication relay = await RelayHosts.StartAsync(
            RelayHosts.Relay(directory.Path, pki, pki.WriteDownstreams(("edge-01", client.Pin)), 0)
                with
            { RelayListenUrl = new Uri("https://[::1]:0") },
            ct,
            destination);
        CollectorSettings settings = RelayHosts.Downstream(directory.Path, pki, client, 0)
            with
        { RelayUrl = new Uri($"https://[::1]:{RelayHosts.RelayPort(relay)}") };
        (string payload, string fingerprint) = RelayUnitTests.Arranged("ipv6-1", "edge-01");
        using RelayHttp http = new(settings);
        RelayOutput output = new(new HttpClient(http.CreateBatchHandler()) { BaseAddress = settings.RelayUrl }, "edge-01");

        DeliveryResult result = await output.DeliverAsync([new QueuedEvent("ipv6-1", fingerprint, payload, DateTimeOffset.UtcNow)], ct);

        Assert.Equal(["ipv6-1"], result.AcknowledgedEventIds);
        // The tunnel client connects and handshakes with the bare IPv6 address; this relay has
        // no tunnel, so it answers 404 instead of upgrading.
        HttpRequestException refused = await Assert.ThrowsAsync<HttpRequestException>(() => http.OpenTunnelAsync(ct).AsTask());
        Assert.Equal(HttpRequestError.ProxyTunnelError, refused.HttpRequestError);
    }

    [Fact]
    public async Task ManagementTunnel_CarriesManagementTlsEndToEndAndGoesNowhereElse()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        RelayPki pki = new(directory.Path);
        var client = pki.CreateClient("edge-01");
        var unpinned = pki.CreateClient("intruder");
        string? seenAuthorization = null;
        await using WebApplication management = await ManagementAsync(pki, context => seenAuthorization = context.Request.Headers.Authorization, ct);
        int managementPort = new Uri(management.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;
        Uri managementEndpoint = new($"https://localhost:{managementPort}/");
        await using WebApplication relay = await RelayHosts.StartAsync(
            RelayHosts.Relay(directory.Path, pki, pki.WriteDownstreams(("edge-01", client.Pin)), 0) with
            {
                RelayManagementTunnel = true,
                ManagementEndpoint = managementEndpoint,
                ManagementScope = "api://bower/.default"
            },
            ct,
            new CapturingOutput(),
            new StaticTokenCredential());
        int port = RelayHosts.RelayPort(relay);

        // TLS to management runs inside the tunnel: the downstream verifies management's own
        // certificate, and the relay forwards only ciphertext.
        Assert.Equal("pong", await GetThroughTunnelAsync(client));
        Assert.Equal("Bearer downstream-assertion", seenAuthorization);
        RelayTunnelSnapshot tunnels = relay.Services.GetRequiredService<RelayTelemetry>().Snapshot().Tunnels;
        Assert.True(tunnels.Opened >= 1);

        // Unpinned certificates never reach the tunnel.
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => GetThroughTunnelAsync(unpinned));

        // A relay without the tunnel enabled refuses it.
        using TemporaryDirectory other = new();
        await using WebApplication plain = await RelayHosts.StartAsync(
            RelayHosts.Relay(other.Path, pki, pki.WriteDownstreams(("edge-01", client.Pin)), 0), ct, new CapturingOutput());
        port = RelayHosts.RelayPort(plain);
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => GetThroughTunnelAsync(client));

        async Task<string> GetThroughTunnelAsync((string Certificate, string Key, string Pin) identity)
        {
            CollectorSettings settings = RelayHosts.Downstream(directory.Path, pki, identity, port) with
            {
                ManagementEndpoint = managementEndpoint,
                ManagementAuthentication = ManagementAuthenticationModes.Enrolment,
                ManagementViaRelay = true,
                ManagementCaBundle = pki.CaBundle
            };
            using RelayHttp http = new(settings);
            using SocketsHttpHandler handler = ManagementHttp.CreateHandler(settings);
            http.UseTunnel(handler);
            using HttpClient management = new(handler) { BaseAddress = managementEndpoint, Timeout = TimeSpan.FromSeconds(15) };
            using HttpRequestMessage request = new(HttpMethod.Get, "ping");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "downstream-assertion");
            using HttpResponseMessage response = await management.SendAsync(request, ct);
            return await response.Content.ReadAsStringAsync(ct);
        }
    }

    private static async Task<WebApplication> ManagementAsync(RelayPki pki, Action<HttpContext> observe, CancellationToken ct)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Configuration["AllowedHosts"] = "*";
        builder.WebHost.UseKestrelHttpsConfiguration();
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate = RelayCertificates.Load(
            pki.ServerCertificate, pki.ServerKey, "test");
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(certificate)));
        WebApplication app = builder.Build();
        app.MapGet("/ping", (HttpContext context) =>
        {
            observe(context);
            return Results.Text("pong");
        });
        await app.StartAsync(ct);
        return app;
    }

    private static HttpRequestMessage Post(SecurityEventEnvelope candidate)
    {
        HttpRequestMessage request = new(HttpMethod.Post, "/v1/events")
        {
            Content = JsonContent.Create(candidate, options: BowerJson.Options)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", RelayHosts.IngestToken);
        return request;
    }

    /// <summary>Stands in for the Log Analytics query: rows come from what the relay delivered.</summary>
    private sealed class DestinationQuery(CapturingOutput destination) : ILogAnalyticsQuery
    {
        public Task<QueryRows> QueryAsync(string workspaceId, string kql, TimeSpan timespan, CancellationToken cancellationToken)
        {
            List<IReadOnlyDictionary<string, JsonNode?>> rows = [];
            foreach (QueuedEvent item in destination.Delivered)
            {
                if (!kql.Contains($"\"{item.EventId}\"", StringComparison.Ordinal))
                {
                    continue;
                }

                JsonNode payload = JsonNode.Parse(item.Payload)!;
                rows.Add(new Dictionary<string, JsonNode?>(StringComparer.Ordinal)
                {
                    ["TimeGenerated"] = JsonValue.Create(payload["timeGenerated"]!.GetValue<string>()),
                    ["IngestionTime"] = JsonValue.Create(DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture)),
                    ["EventId"] = JsonValue.Create(item.EventId),
                    ["PolicyHash"] = JsonValue.Create(payload["security"]!["policyHash"]!.GetValue<string>())
                });
            }

            return Task.FromResult(new QueryRows(rows, null));
        }
    }
}

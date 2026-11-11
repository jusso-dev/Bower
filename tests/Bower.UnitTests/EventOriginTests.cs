using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Forwarding;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;

namespace Bower.UnitTests;

/// <summary>
/// #228, #253: the table's Origin column records where an event entered Bower, set by Bower and
/// never chosen by the producer. CloudWatch Logs origin comes from the trusted cloud forwarder's
/// X-Bower-Origin header; anything a producer puts in the envelope's collector context is replaced.
/// </summary>
public sealed class EventOriginTests
{
    private const string ForwarderToken = "cloud-forwarder-token-0123456789abcdef0123";
    private const string AppToken = "application-token-0123456789abcdef01234567";

    [Fact]
    public void Header_RoundTripsAndRefusesAnythingElse()
    {
        string value = OriginHeader.Format("/bower/app-events", "i-0abc;def=ghi");
        string[] trusted = ["cloud-forwarder"];

        Assert.Equal(
            new EventOrigin { Kind = "cloudwatch-logs", LogGroup = "/bower/app-events", LogStream = "i-0abc;def=ghi" },
            OriginHeader.Read(value, "cloud-forwarder", trusted));
        Assert.Null(OriginHeader.Read(value, "some-app", trusted));
        Assert.Null(OriginHeader.Read(value, "cloud-forwarder", []));
        Assert.Null(OriginHeader.Read("ama-syslog; host=x", "cloud-forwarder", trusted));
        Assert.Null(OriginHeader.Read("cloudwatch-logs; logGroup=a", "cloud-forwarder", trusted));
        Assert.Null(OriginHeader.Read("cloudwatch-logs; logGroup=%0Aa; logStream=b", "cloud-forwarder", trusted));
        Assert.Null(OriginHeader.Read($"cloudwatch-logs; logGroup={new string('a', 513)}; logStream=b", "cloud-forwarder", trusted));
    }

    [Fact]
    public void Settings_RefuseTrustingTheAnonymousProducer()
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => CollectorSettings.FromEnvironment(name => name switch
        {
            "BOWER_COLLECTOR_ID" => "edge-01",
            "BOWER_ORIGIN_PRODUCERS" => "anonymous",
            _ => null
        }));

        Assert.Contains("anonymous cannot be trusted", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Collector_RecordsOriginOnlyFromATrustedForwarderAndNeverFromTheEnvelope()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string tokens = Path.Combine(directory.Path, "tokens");
        File.WriteAllLines(tokens,
        [
            $"cloud-forwarder sha256:{Sha256(ForwarderToken)}",
            $"some-app sha256:{Sha256(AppToken)}"
        ]);
        CollectorSettings settings = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = "collector-test",
            SingleTrustDomain = true,
            IngestTokensFile = tokens,
            OriginProducers = ["cloud-forwarder"]
        };
        await using WebApplication app = CollectorApplication.Build(settings, builder => builder.WebHost.UseTestServer());
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        HttpClient client = app.GetTestClient();
        string header = OriginHeader.Format("/bower/app-events", "i-0abc");

        // A forged origin inside the envelope must never survive: collector is Bower's own.
        await PostAsync(client, AppToken, "origin-app", header, forgedOriginInEnvelope: true, cancellationToken);
        await PostAsync(client, ForwarderToken, "origin-forwarder", header, forgedOriginInEnvelope: true, cancellationToken);
        await PostAsync(client, ForwarderToken, "origin-none", null, forgedOriginInEnvelope: false, cancellationToken);
        await app.StopAsync(cancellationToken);

        SqliteEventStore store = new(settings.QueuePath, 1_048_576);
        await store.InitializeAsync(cancellationToken);
        Dictionary<string, JsonElement> collector = [];
        foreach (QueuedEvent queued in await store.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken))
        {
            using JsonDocument document = JsonDocument.Parse(queued.Payload);
            collector[queued.EventId] = document.RootElement.GetProperty("collector").Clone();
        }

        // An application's header is ignored, and its forged collector.origin is replaced.
        Assert.False(collector["origin-app"].TryGetProperty("origin", out _));
        // The trusted forwarder's header is recorded; the envelope's forged value is not.
        JsonElement origin = collector["origin-forwarder"].GetProperty("origin");
        Assert.Equal("cloudwatch-logs", origin.GetProperty("kind").GetString());
        Assert.Equal("/bower/app-events", origin.GetProperty("logGroup").GetString());
        Assert.Equal("i-0abc", origin.GetProperty("logStream").GetString());
        Assert.False(collector["origin-none"].TryGetProperty("origin", out _));
    }

    private static async Task PostAsync(
        HttpClient client, string token, string eventId, string? origin, bool forgedOriginInEnvelope, CancellationToken cancellationToken)
    {
        SecurityEventEnvelope envelope = TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, eventId, originalId: "source-" + eventId);
        if (forgedOriginInEnvelope)
        {
            envelope = envelope with
            {
                Collector = new CollectorContext
                {
                    Id = "forged",
                    Version = "0",
                    SourceAdapter = "forged",
                    ConfigurationHash = "forged",
                    ReceivedAt = DateTimeOffset.UtcNow,
                    Origin = new EventOrigin { Kind = "ama-syslog", Host = "forged-host" }
                }
            };
        }

        using HttpRequestMessage post = new(HttpMethod.Post, "/v1/events")
        {
            Content = JsonContent.Create(envelope, options: BowerJson.Options)
        };
        post.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (origin is not null)
        {
            post.Headers.TryAddWithoutValidation(OriginHeader.Name, origin);
        }

        using HttpResponseMessage response = await client.SendAsync(post, cancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"{eventId}: HTTP {(int)response.StatusCode}");
    }

    private static string Sha256(string value) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
}

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.Core;
using Bower.PolicyEngine;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class ProducerAuthorizationTests
{
    private const string Token = "producer-a-synthetic-credential-0123456789";
    private const string Scopes = """
        [
          {"producer":"a","application":{"name":"TestApplication","environment":"test","tenantId":"tenant-a","instance":"instance-a"},"source":{"ipAddress":"192.0.2.10","hostname":"host-a","port":123}},
          {"producer":"a","application":{"name":"OtherApplication","environment":"test","tenantId":"tenant-b","instance":"instance-b"},"source":{"ipAddress":"192.0.2.20","hostname":"host-b","port":456}}
        ]
        """;

    [Fact]
    public async Task ProducerCannotImpersonateOrMixTuplesBeforePolicyAndPersistence()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string scopes = Path.Combine(directory.Path, "scopes.json");
        string tokens = Path.Combine(directory.Path, "tokens");
        await File.WriteAllTextAsync(scopes, Scopes, cancellationToken);
        await File.WriteAllLinesAsync(tokens, [IngestAuthentication.TokensFileLine("a", Token)], cancellationToken);
        CountingEvaluator evaluator = new();
        CollectorSettings settings = Settings(directory.Path) with { ProducerScopesFile = scopes, IngestTokensFile = tokens };
        await using WebApplication app = CollectorApplication.Build(settings, builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton<ITelemetryPolicyEvaluator>(evaluator);
        });
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        HttpClient client = app.GetTestClient();
        JsonObject candidate = Candidate();
        foreach ((string section, string field, JsonNode? replacement) in new (string, string, JsonNode?)[]
        {
            ("application", "name", JsonValue.Create("OtherApplication")),
            ("application", "environment", JsonValue.Create("production")),
            ("application", "tenantId", JsonValue.Create("tenant-b")),
            ("application", "instance", JsonValue.Create("instance-b")),
            ("source", "ipAddress", JsonValue.Create("192.0.2.20")),
            ("source", "hostname", JsonValue.Create("host-b")),
            ("source", "port", JsonValue.Create(456)),
            ("application", "tenantId", null)
        })
        {
            JsonObject altered = candidate.DeepClone().AsObject();
            altered[section]![field] = replacement;
            using HttpResponseMessage denied = await Send(client, altered.ToJsonString(), cancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }

        string duplicate = candidate.ToJsonString().Replace("\"tenantId\":\"tenant-a\"",
            "\"tenantId\":\"tenant-b\",\"tenantId\":\"tenant-a\"", StringComparison.Ordinal);
        using HttpResponseMessage duplicateDenied = await Send(client, duplicate, cancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, duplicateDenied.StatusCode);
        Assert.Equal(0, evaluator.Calls);
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        Assert.Equal(0, (await store.GetSnapshotAsync(cancellationToken)).Queued);
        Assert.Empty(await store.LeaseAsync(100, TimeSpan.FromMinutes(1), cancellationToken));

        using HttpResponseMessage accepted = await Send(client, candidate.ToJsonString(), cancellationToken);
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        Assert.True(evaluator.Calls > 0);
    }

    [Fact]
    public void ScopeDefaultDeniesAndSingleTrustDomainMustBeExplicit()
    {
        using JsonDocument candidate = JsonDocument.Parse(Candidate().ToJsonString());
        Assert.False(new ProducerAuthorization(null).IsAuthorized("default", candidate.RootElement));
        Assert.True(new ProducerAuthorization(null, singleTrustDomain: true).IsAuthorized("default", candidate.RootElement));
        Assert.Throws<InvalidOperationException>(() => new ProducerAuthorization("unused", singleTrustDomain: true));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[{\"producer\":\"a\",\"application\":null}]")]
    [InlineData("[{\"producer\":\"a\",\"application\":{\"name\":\"x\",\"name\":\"y\",\"environment\":\"test\"}}]")]
    [InlineData("[{\"producer\":\"a\",\"application\":{\"name\":\"x\",\"environment\":\"test\"},\"sources\":{}}]")]
    public void InvalidScopeConfigurationFailsClosedWithoutEchoingValues(string json)
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "scopes.json");
        File.WriteAllText(path, json);
        FormatException error = Assert.Throws<FormatException>(() => new ProducerAuthorization(path));
        Assert.Equal("Invalid producer scopes file.", error.Message);
    }

    [Fact]
    public void CredentialOwnerAndAbsentSourceAreExact()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "scopes.json");
        File.WriteAllText(path, """[{"producer":"a","application":{"name":"x","environment":"test"}}]""");
        ProducerAuthorization authorization = new(path);
        using JsonDocument absent = JsonDocument.Parse("""{"application":{"name":"x","environment":"test"}}""");
        using JsonDocument injected = JsonDocument.Parse("""{"application":{"name":"x","environment":"test"},"source":{"hostname":"other"}}""");
        Assert.True(authorization.IsAuthorized("a", absent.RootElement));
        Assert.False(authorization.IsAuthorized("b", absent.RootElement));
        Assert.False(authorization.IsAuthorized("a", injected.RootElement));
    }

    private static JsonObject Candidate()
    {
        JsonObject candidate = JsonNode.Parse(JsonSerializer.Serialize(
            TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow), BowerJson.Envelope))!.AsObject();
        candidate["application"]!["tenantId"] = "tenant-a";
        candidate["application"]!["instance"] = "instance-a";
        candidate["source"]!["hostname"] = "host-a";
        candidate["source"]!["port"] = 123;
        return candidate;
    }

    private static CollectorSettings Settings(string directory) => new()
    {
        ListenUrl = "http://127.0.0.1:4319",
        QueuePath = Path.Combine(directory, "queue.db"),
        PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
        CollectorId = "test"
    };

    private static async Task<HttpResponseMessage> Send(HttpClient client, string json, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "/v1/events") { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return await client.SendAsync(request, cancellationToken);
    }

    private sealed class CountingEvaluator : ITelemetryPolicyEvaluator
    {
        public int Calls { get; private set; }
        public PolicyDecision Evaluate(SecurityEventEnvelope candidate)
        {
            Calls++;
            return new DeterministicPolicyEvaluator([TestEvents.AuthenticationPolicy()]).Evaluate(candidate);
        }
    }
}

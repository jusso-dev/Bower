using System.Text.Json;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Bower.Functions.Collector.Tests;

public sealed class EntraAuthenticationTests
{
    [Theory]
    [InlineData("valid", AuthenticationFailure.None)]
    [InlineData("missing", AuthenticationFailure.Missing)]
    [InlineData("not-bearer", AuthenticationFailure.Invalid)]
    [InlineData("garbage", AuthenticationFailure.Invalid)]
    [InlineData("expired", AuthenticationFailure.Invalid)]
    [InlineData("wrong-audience", AuthenticationFailure.Invalid)]
    [InlineData("resource-uri-audience", AuthenticationFailure.Invalid)]
    [InlineData("wrong-tenant-issuer", AuthenticationFailure.Invalid)]
    [InlineData("wrong-tid-claim", AuthenticationFailure.Invalid)]
    [InlineData("v1-token", AuthenticationFailure.Invalid)]
    [InlineData("wrong-signature", AuthenticationFailure.Invalid)]
    [InlineData("unsigned", AuthenticationFailure.Invalid)]
    [InlineData("oversized", AuthenticationFailure.Invalid)]
    [InlineData("missing-role", AuthenticationFailure.Forbidden)]
    [InlineData("other-role", AuthenticationFailure.Forbidden)]
    [InlineData("delegated-user", AuthenticationFailure.Forbidden)]
    [InlineData("user-idtyp", AuthenticationFailure.Forbidden)]
    [InlineData("missing-oid", AuthenticationFailure.Forbidden)]
    public async Task Entra_v2_token_matrix_fails_closed(string scenario, AuthenticationFailure expected)
    {
        using TestEntra entra = new();
        string? header = scenario switch
        {
            "missing" => null,
            "not-bearer" => "Basic " + entra.Token(),
            "garbage" => "Bearer not.a.jwt",
            "expired" => "Bearer " + entra.Token(expired: true),
            "wrong-audience" => "Bearer " + entra.Token(audience: "33333333-4444-5555-6666-777777777777"),
            "resource-uri-audience" => "Bearer " + entra.Token(audience: "api://" + TestEntra.Audience),
            "wrong-tenant-issuer" => "Bearer " + entra.Token(
                issuer: "https://login.microsoftonline.com/44444444-5555-6666-7777-888888888888/v2.0"),
            "wrong-tid-claim" => "Bearer " + entra.Token(tenant: "44444444-5555-6666-7777-888888888888"),
            "v1-token" => "Bearer " + entra.Token(version: "1.0"),
            "wrong-signature" => "Bearer " + entra.Token(untrustedKey: true),
            "unsigned" => "Bearer " + Unsigned(entra.Token()),
            "oversized" => "Bearer " + new string('a', EntraProducerAuthenticator.MaximumTokenLength + 1),
            "missing-role" => "Bearer " + entra.Token(role: null),
            "other-role" => "Bearer " + entra.Token(role: "Bower.Collector"),
            "delegated-user" => "Bearer " + entra.Token(scope: "Bower.Access"),
            "user-idtyp" => "Bearer " + entra.Token(identityType: "user"),
            "missing-oid" => "Bearer " + entra.Token(objectId: null),
            _ => "Bearer " + entra.Token(identityType: "app")
        };

        AuthenticationOutcome outcome = await entra.Authenticator()
            .AuthenticateAsync(header, TestContext.Current.CancellationToken);

        Assert.Equal(expected, outcome.Failure);
        Assert.Equal(expected == AuthenticationFailure.None, outcome.Caller is not null);
        if (outcome.Caller is not null)
        {
            Assert.Equal(TestEntra.ProducerObjectId, outcome.Caller.Producer);
        }
    }

    [Fact]
    public async Task Producer_can_be_the_client_application_id_when_configured()
    {
        using TestEntra entra = new();

        AuthenticationOutcome outcome = await entra.Authenticator("azp")
            .AuthenticateAsync("Bearer " + entra.Token(), TestContext.Current.CancellationToken);

        Assert.Equal(TestEntra.ProducerClientId, outcome.Caller?.Producer);
    }

    [Fact]
    public async Task Unreachable_signing_metadata_is_retryable_not_a_credential_verdict()
    {
        using TestEntra entra = new();
        EntraProducerAuthenticator authenticator = new(
            TestEntra.Tenant, TestEntra.Audience, "oid", new FailingMetadata());

        AuthenticationOutcome outcome = await authenticator.AuthenticateAsync(
            "Bearer " + entra.Token(), TestContext.Current.CancellationToken);

        Assert.Equal(AuthenticationFailure.Unavailable, outcome.Failure);
    }

    [Fact]
    public void Authenticator_rejects_non_guid_tenant_and_unknown_producer_claim()
    {
        Assert.Throws<ArgumentException>(() => new EntraProducerAuthenticator("common", TestEntra.Audience, "oid"));
        Assert.Throws<ArgumentException>(() => new EntraProducerAuthenticator(TestEntra.Tenant, TestEntra.Audience, "sub"));
        Assert.Equal(TestEntra.Issuer, new EntraProducerAuthenticator(TestEntra.Tenant, TestEntra.Audience, "oid").Issuer);
    }

    [Theory]
    [InlineData("missing", 401)]
    [InlineData("expired", 401)]
    [InlineData("wrong-audience", 401)]
    [InlineData("wrong-tenant", 401)]
    [InlineData("missing-role", 403)]
    [InlineData("no-producer-scope", 403)]
    public async Task Ingest_auth_matrix_denies_before_processing_or_delivery(string scenario, int expected)
    {
        using Harness harness = new(Harness.Settings(
            scopesJson: scenario == "no-producer-scope" ? Harness.Scopes("bbbbbbbb-0000-0000-0000-000000000000") : null));
        string? token = scenario switch
        {
            "missing" => null,
            "expired" => harness.Entra.Token(expired: true),
            "wrong-audience" => harness.Entra.Token(audience: "33333333-4444-5555-6666-777777777777"),
            "wrong-tenant" => harness.Entra.Token(
                tenant: "44444444-5555-6666-7777-888888888888",
                issuer: "https://login.microsoftonline.com/44444444-5555-6666-7777-888888888888/v2.0"),
            "missing-role" => harness.Entra.Token(role: null),
            _ => harness.Entra.Token()
        };

        CollectorResponse response = await harness.PostAsync(Harness.Event(), token);

        Assert.Equal(expected, response.StatusCode);
        Assert.Empty(harness.Fake.Batches);
        Assert.DoesNotContain(Harness.SecretCanary, response.Body, StringComparison.Ordinal);
        if (expected == 401)
        {
            Assert.Equal("Bearer", response.Headers["WWW-Authenticate"]);
        }

        if (token is not null)
        {
            Assert.DoesNotContain(token, response.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(token, harness.AllLogs, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Missing_producer_scopes_configuration_denies_every_event()
    {
        FunctionSettings settings = Harness.Settings() with { ProducerScopesJson = null };
        using Harness harness = new(settings);

        CollectorResponse response = await harness.PostAsync(Harness.Event(), harness.Entra.Token());

        Assert.Equal(403, response.StatusCode);
        Assert.Empty(harness.Fake.Batches);
    }

    [Fact]
    public async Task Health_is_anonymous_without_detail_and_status_requires_a_producer_token()
    {
        using Harness harness = new();
        CancellationToken cancellation = TestContext.Current.CancellationToken;

        CollectorResponse health = FunctionCollector.Health();
        CollectorResponse anonymous = await harness.Collector.StatusAsync(null, cancellation);
        CollectorResponse status = await harness.Collector.StatusAsync("Bearer " + harness.Entra.Token(), cancellation);

        Assert.Equal(200, health.StatusCode);
        Assert.Equal("""{"status":"healthy"}""", health.Body);
        Assert.Equal(401, anonymous.StatusCode);
        Assert.Equal(200, status.StatusCode);
        using JsonDocument document = JsonDocument.Parse(status.Body);
        JsonElement root = document.RootElement;
        Assert.Equal("azure-function", root.GetProperty("mode").GetString());
        Assert.False(root.GetProperty("delivery").GetProperty("durableQueue").GetBoolean());
        Assert.False(root.GetProperty("delivery").GetProperty("ledger").GetBoolean());
        Assert.Equal("managed-identity:system-assigned", root.GetProperty("delivery").GetProperty("credential").GetString());
        Assert.Equal(1, root.GetProperty("producerScopes").GetInt32());
        Assert.StartsWith("sha256:", root.GetProperty("policy").GetProperty("hash").GetString(), StringComparison.Ordinal);
        Assert.DoesNotContain(TestEntra.ProducerObjectId, status.Body, StringComparison.Ordinal);
    }

    private static string Unsigned(string token)
    {
        string[] parts = token.Split('.');
        string header = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT"}""");
        return $"{header}.{parts[1]}.";
    }

    private sealed class FailingMetadata : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) =>
            throw new InvalidOperationException("metadata endpoint unreachable");

        public void RequestRefresh()
        {
        }
    }
}

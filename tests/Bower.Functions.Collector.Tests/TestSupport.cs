using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Bower.Abstractions;
using Bower.Functions.Collector;
using Bower.Packs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Bower.Functions.Collector.Tests;

internal sealed class TemporaryDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"bower-fn-tests-{Guid.NewGuid():N}");

    public TemporaryDirectory() => Directory.CreateDirectory(Path);

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}

/// <summary>Offline Entra: one RSA signing key published through static OIDC metadata.</summary>
internal sealed class TestEntra : IDisposable
{
    public const string Tenant = "22222222-3333-4444-5555-666666666666";
    public const string Audience = "11111111-2222-3333-4444-555555555555";
    public const string ProducerObjectId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    public const string ProducerClientId = "99999999-8888-7777-6666-555555555555";
    public const string Issuer = "https://login.microsoftonline.com/" + Tenant + "/v2.0";

    private readonly RSA trusted = RSA.Create(2048);
    private readonly RSA untrusted = RSA.Create(2048);

    public TestEntra()
    {
        Key = new RsaSecurityKey(trusted) { KeyId = "offline-fixture" };
        OpenIdConnectConfiguration configuration = new() { Issuer = Issuer };
        configuration.SigningKeys.Add(Key);
        Metadata = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
    }

    public RsaSecurityKey Key { get; }

    public IConfigurationManager<OpenIdConnectConfiguration> Metadata { get; }

    public EntraProducerAuthenticator Authenticator(string producerClaim = "oid") =>
        new(Tenant, Audience, producerClaim, Metadata);

    public string Token(
        string? audience = Audience,
        string issuer = Issuer,
        string tenant = Tenant,
        string? role = EntraProducerAuthenticator.ProducerRole,
        bool expired = false,
        bool untrustedKey = false,
        string version = "2.0",
        string? objectId = ProducerObjectId,
        string? scope = null,
        string? identityType = null)
    {
        List<Claim> claims = [new("tid", tenant), new("ver", version), new("azp", ProducerClientId)];
        if (role is not null) claims.Add(new Claim("roles", role));
        if (objectId is not null) claims.Add(new Claim("oid", objectId));
        if (scope is not null) claims.Add(new Claim("scp", scope));
        if (identityType is not null) claims.Add(new Claim("idtyp", identityType));
        DateTime now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = audience,
            Issuer = issuer,
            Subject = new ClaimsIdentity(claims),
            NotBefore = now.AddHours(-2),
            IssuedAt = now.AddHours(-2),
            Expires = expired ? now.AddHours(-1) : now.AddHours(1),
            SigningCredentials = new SigningCredentials(
                untrustedKey ? new RsaSecurityKey(untrusted) { KeyId = Key.KeyId } : Key,
                SecurityAlgorithms.RsaSha256)
        });
    }

    public void Dispose()
    {
        trusted.Dispose();
        untrusted.Dispose();
    }
}

/// <summary>Records exactly what would be uploaded and answers with a scripted result.</summary>
internal sealed class FakeOutput(Func<IReadOnlyList<QueuedEvent>, DeliveryResult>? respond = null) : IOutputAdapter
{
    public List<IReadOnlyList<QueuedEvent>> Batches { get; } = [];

    public string Id => "fake-output";

    public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Batches.Add([.. events]);
        return Task.FromResult(respond?.Invoke(events)
            ?? new DeliveryResult([.. events.Select(item => item.EventId)], [], "fake:accepted"));
    }

    public static DeliveryResult Fail(IReadOnlyList<QueuedEvent> events, string code, bool retryable, DateTimeOffset? retryAfter = null) =>
        new([], [.. events.Select(item => new DeliveryFailure(item.EventId, code, retryable, retryAfter))], null);
}

internal sealed class StaticCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new("synthetic-access-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}

/// <summary>Captures Logs Ingestion request bodies (decompressed) and answers with a status.</summary>
internal sealed class RecordingIngestionHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
{
    public ConcurrentQueue<string> Bodies { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
        if (request.Content.Headers.ContentEncoding.Contains("gzip"))
        {
            using GZipStream gzip = new(new MemoryStream(body), CompressionMode.Decompress);
            using MemoryStream plain = new();
            await gzip.CopyToAsync(plain, cancellationToken);
            body = plain.ToArray();
        }

        Bodies.Enqueue(Encoding.UTF8.GetString(body));
        return respond();
    }
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Messages { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(Messages);

    public void Dispose()
    {
    }

    private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(formatter(state, exception) + (exception is null ? string.Empty : exception.ToString()));
    }
}

internal sealed class Harness : IDisposable
{
    public const string SecretCanary = "payload-secret-canary";

    private readonly ServiceProvider provider;

    public Harness(
        FunctionSettings? settings = null,
        IOutputAdapter? output = null,
        IProducerAuthenticator? authenticator = null)
    {
        Entra = new TestEntra();
        Output = output ?? new FakeOutput();
        ServiceCollection services = new();
        services.AddLogging(logging => logging.AddProvider(Logs).SetMinimumLevel(LogLevel.Trace));
        services.AddBowerFunctionCollector(
            settings ?? Settings(),
            Output,
            authenticator ?? Entra.Authenticator(),
            new StaticCredential());
        provider = services.BuildServiceProvider();
        Collector = provider.GetRequiredService<FunctionCollector>();
    }

    public TestEntra Entra { get; }

    public IOutputAdapter Output { get; }

    public FakeOutput Fake => (FakeOutput)Output;

    public CapturingLoggerProvider Logs { get; } = new();

    public FunctionCollector Collector { get; }

    public static string PolicyDirectory => Path.Combine(AppContext.BaseDirectory, "repo-policies");

    public static string Scopes(string producer = TestEntra.ProducerObjectId) => $$$"""
        [{"producer":"{{{producer}}}","application":{"name":"TestApplication","environment":"test"},
          "source":{"ipAddress":"192.0.2.10"}}]
        """;

    public static FunctionSettings Settings(
        string? scopesJson = null,
        string? privacyProfile = null,
        string? hmacKeyFile = null,
        TimeSpan? deliveryTimeout = null) => new()
        {
            EntraTenantId = TestEntra.Tenant,
            EntraAudience = TestEntra.Audience,
            PolicySources = new PolicyBundleSources
            {
                PolicyDirectory = PolicyDirectory,
                PrivacyProfilePath = privacyProfile,
                PrivacyHmacKeyFile = hmacKeyFile
            },
            ProducerScopesJson = scopesJson ?? Scopes(),
            LogsIngestionEndpoint = new Uri("https://example.ingest.monitor.azure.com"),
            DcrImmutableId = "dcr-00000000000000000000000000000000",
            DeliveryTimeout = deliveryTimeout ?? TimeSpan.FromSeconds(30)
        };

    public static string Event(
        string eventId = "event-1",
        string eventType = "authentication_failure",
        string category = "authentication",
        string? outcomeReason = "InvalidPassword",
        string username = "test-user",
        bool secret = true) =>
        JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["schemaVersion"] = "1.0.0",
            ["eventId"] = eventId,
            ["timeGenerated"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"),
            ["eventCategory"] = category,
            ["eventType"] = eventType,
            ["eventAction"] = "authentication.attempt",
            ["eventResult"] = "failure",
            ["eventOutcomeReason"] = outcomeReason,
            ["application"] = new Dictionary<string, string> { ["name"] = "TestApplication", ["environment"] = "test" },
            ["actor"] = new Dictionary<string, string> { ["username"] = username },
            ["source"] = new Dictionary<string, string> { ["ipAddress"] = "192.0.2.10" },
            ["request"] = new Dictionary<string, string> { ["correlationId"] = "correlation-1" },
            ["attributes"] = secret ? new Dictionary<string, string> { ["dbPassword"] = SecretCanary } : null
        });

    public Task<CollectorResponse> PostAsync(
        string body,
        string? token,
        string? contentType = "application/json",
        long? contentLength = null,
        CancellationToken? cancellationToken = null,
        bool declareLength = true) =>
        PostAsync(Encoding.UTF8.GetBytes(body), token, contentType, contentLength, cancellationToken, declareLength);

    public Task<CollectorResponse> PostAsync(
        byte[] body,
        string? token,
        string? contentType = "application/json",
        long? contentLength = null,
        CancellationToken? cancellationToken = null,
        bool declareLength = true) =>
        Collector.IngestAsync(
            new IngestRequest(
                token is null ? null : "Bearer " + token,
                contentType,
                declareLength ? contentLength ?? body.Length : null,
                new MemoryStream(body)),
            cancellationToken ?? TestContext.Current.CancellationToken);

    public string AllLogs => string.Join('\n', Logs.Messages);

    public void Dispose()
    {
        provider.Dispose();
        Entra.Dispose();
    }

    public static HttpResponseMessage Status(HttpStatusCode status, string? retryAfter = null)
    {
        HttpResponseMessage response = new(status);
        if (retryAfter is not null)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }

        return response;
    }
}

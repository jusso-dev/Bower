using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Azure.Core;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Collector.Relay;
using Bower.Contracts;
using Bower.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

/// <summary>PEM files for a relay test topology: a private CA, the relay server and downstream clients.</summary>
internal sealed class RelayPki
{
    public RelayPki(string directory)
    {
        Directory = directory;
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest caRequest = new("CN=Bower Relay Test CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        CaBundle = Path.Combine(directory, "relay-ca.pem");
        File.WriteAllText(CaBundle, ca.ExportCertificatePem());

        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest server = new("CN=localhost", serverKey, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        names.AddIpAddress(IPAddress.IPv6Loopback);
        server.CertificateExtensions.Add(names.Build());
        server.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        server.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        using X509Certificate2 issued = server.Create(
            ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(8));
        (ServerCertificate, ServerKey) = Write(issued, serverKey, "relay-server");
    }

    public string Directory { get; }

    public string CaBundle { get; }

    public string ServerCertificate { get; }

    public string ServerKey { get; }

    /// <summary>A self-signed client certificate; returns its files and SHA-256 pin.</summary>
    public (string Certificate, string Key, string Pin) CreateClient(
        string name,
        DateTimeOffset? notAfter = null,
        string usage = "1.3.6.1.5.5.7.3.2")
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(usage)], false));
        DateTimeOffset end = notAfter ?? DateTimeOffset.UtcNow.AddDays(7);
        using X509Certificate2 certificate = request.CreateSelfSigned(end.AddDays(-14), end);
        (string certificateFile, string keyFile) = Write(certificate, key, $"client-{name}-{Guid.NewGuid():N}");
        return (certificateFile, keyFile, RelayCertificates.Pin(certificate));
    }

    public string WriteDownstreams(params (string CollectorId, string Pin)[] entries)
    {
        string path = Path.Combine(Directory, $"downstreams-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            downstreams = entries.Select(entry => new { collectorId = entry.CollectorId, certificateSha256 = entry.Pin })
        }));
        return path;
    }

    private (string Certificate, string Key) Write(X509Certificate2 certificate, ECDsa key, string name)
    {
        string certificateFile = Path.Combine(Directory, name + ".crt.pem");
        string keyFile = Path.Combine(Directory, name + ".key.pem");
        File.WriteAllText(certificateFile, certificate.ExportCertificatePem());
        File.WriteAllText(keyFile, key.ExportPkcs8PrivateKeyPem());
        return (certificateFile, keyFile);
    }
}

/// <summary>Destination double for the relay: records every delivered payload.</summary>
internal sealed class CapturingOutput : IOutputAdapter
{
    private readonly ConcurrentQueue<QueuedEvent> delivered = new();

    public string Id => "capture";

    public IReadOnlyList<QueuedEvent> Delivered => [.. delivered];

    public Task<DeliveryResult> DeliverAsync(IReadOnlyList<QueuedEvent> events, CancellationToken cancellationToken = default)
    {
        foreach (QueuedEvent item in events)
        {
            delivered.Enqueue(item);
        }

        return Task.FromResult(new DeliveryResult([.. events.Select(item => item.EventId)], [], "capture:accepted"));
    }
}

internal sealed class StaticTokenCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new("test-management-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}

/// <summary>Hosts relays and downstream collectors in-process. The relay listener binds a real loopback port.</summary>
internal static class RelayHosts
{
    public const string IngestToken = "relay-test-ingest-token-0123456789abcdef";

    public static int FreePort()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public static CollectorSettings Relay(string directory, RelayPki pki, string downstreams, int port) => new()
    {
        ListenUrl = "http://127.0.0.1:4319",
        QueuePath = Path.Combine(directory, "relay", "queue.db"),
        PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
        CollectorId = "relay-01",
        SingleTrustDomain = true,
        RelayListenUrl = new Uri($"https://127.0.0.1:{port}"),
        RelayCertificateFile = pki.ServerCertificate,
        RelayKeyFile = pki.ServerKey,
        RelayDownstreamsFile = downstreams
    };

    public static CollectorSettings Downstream(
        string directory,
        RelayPki pki,
        (string Certificate, string Key, string Pin) client,
        int relayPort,
        string collectorId = "edge-01") => new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory, collectorId, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = collectorId,
            SingleTrustDomain = true,
            IngestToken = IngestToken,
            OutputType = "relay",
            RelayUrl = new Uri($"https://localhost:{relayPort}"),
            RelayClientCertificateFile = client.Certificate,
            RelayClientKeyFile = client.Key,
            RelayCaBundle = pki.CaBundle
        };

    public static async Task<WebApplication> StartAsync(
        CollectorSettings settings,
        CancellationToken cancellationToken,
        IOutputAdapter? output = null,
        TokenCredential? credential = null)
    {
        WebApplication app = CollectorApplication.Build(
            settings,
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Services.AddSingleton(new QueueDeliveryOptions { IdleDelay = TimeSpan.FromMilliseconds(50) });
            },
            output,
            credential);
        await CollectorApplication.InitializeAsync(app, cancellationToken);
        await app.StartAsync(cancellationToken);
        return app;
    }

    public static int RelayPort(WebApplication relay) =>
        relay.Services.GetRequiredService<RelayListener>().Addresses[0].Port;

    public static SecurityEventEnvelope Event(string eventId) =>
        TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow, eventId: eventId, originalId: "source-" + eventId);

    public static async Task WaitForAsync(Func<Task<bool>> condition, CancellationToken cancellationToken, int seconds = 30)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (!await condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("Condition not met in time.");
            }

            await Task.Delay(50, cancellationToken);
        }
    }

    /// <summary>Queue rows read straight from SQLite (event id, state, acknowledgement, payload).</summary>
    public static List<(string EventId, int State, string? Acknowledgement, string Payload)> Rows(string queuePath)
    {
        using SqliteConnection connection = new($"Data Source={queuePath};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT event_id, state, acknowledgement, payload FROM queue_events_v5 ORDER BY event_id;";
        using SqliteDataReader reader = command.ExecuteReader();
        List<(string, int, string?, string)> rows = [];
        while (reader.Read())
        {
            rows.Add((reader.GetString(0), reader.GetInt32(1), reader.IsDBNull(2) ? null : reader.GetString(2), reader.GetString(3)));
        }

        return rows;
    }

    /// <summary>Ledger payload hashes by event id.</summary>
    public static Dictionary<string, string> LedgerHashes(string queuePath)
    {
        using SqliteConnection connection = new($"Data Source={queuePath};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT event_id, payload_sha256 FROM queue_ledger;";
        using SqliteDataReader reader = command.ExecuteReader();
        Dictionary<string, string> hashes = new(StringComparer.Ordinal);
        while (reader.Read())
        {
            hashes[reader.GetString(0)] = reader.GetString(1);
        }

        return hashes;
    }

    public static async Task<LedgerVerification> VerifyAsync(string queuePath, CancellationToken cancellationToken)
    {
        SqliteEventStore store = new(queuePath, 1024L * 1024 * 1024);
        return await store.VerifyLedgerAsync(cancellationToken);
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;
using Bower.AppHost;

namespace Bower.AppHost.Tests;

/// <summary>
/// End to end through the Aspire harness: one synthetic canary per collector reaches its
/// local stand-in destination (S3 emulator, NDJSON HTTP endpoint, syslog datagram socket).
/// Proves local receipt, policy acceptance and delivery to the stand-in only; never
/// Sentinel delivery.
/// </summary>
public sealed class AppHostPipelineTests
{
    private const string EnableVariable = "BOWER_ASPIRE_TESTS";
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DeliveryTimeout = TimeSpan.FromMinutes(1);

    [Fact]
    public async Task CanaryReachesEveryLocalOutput()
    {
        Assert.SkipUnless(
            Environment.GetEnvironmentVariable(EnableVariable) == "1",
            $"Set {EnableVariable}=1 to boot the Aspire AppHost (needs a container runtime).");

        string work = Directory.CreateTempSubdirectory("bower-aspire-test-").FullName;
        // Short path: macOS caps Unix socket paths at 103 bytes and temp paths are long.
        string socket = Path.Combine("/tmp", $"bower-aspire-test-{Environment.ProcessId}", "log.sock");
        string token = Convert.ToHexString(Guid.NewGuid().ToByteArray()) + Convert.ToHexString(Guid.NewGuid().ToByteArray());
        try
        {
            using CancellationTokenSource startup = new(StartupTimeout);
            await using IDistributedApplicationTestingBuilder builder = await DistributedApplicationTestingBuilder.CreateAsync(
                typeof(CanaryEvent),
                [
                    $"--BowerAspire:StateDirectory={work}",
                    $"--BowerAspire:SyslogSocket={socket}",
                    $"--Parameters:ingest-token={token}",
                    $"--Parameters:http-sink-token={Convert.ToHexString(Guid.NewGuid().ToByteArray())}"
                ],
                startup.Token);
            await using DistributedApplication app = await builder.BuildAsync(startup.Token);
            await app.StartAsync(startup.Token);

            string[] collectors = OperatingSystem.IsWindows()
                ? ["collector-s3", "collector-http"]
                : ["collector-s3", "collector-http", "collector-syslog"];
            await app.ResourceNotifications.WaitForResourceHealthyAsync("devsinks", startup.Token);
            foreach (string collector in collectors)
            {
                await app.ResourceNotifications.WaitForResourceHealthyAsync(collector, startup.Token);
            }

            using HttpClient sinks = app.CreateHttpClient("devsinks", "http");
            foreach (string collector in collectors)
            {
                using HttpClient client = app.CreateHttpClient(collector, "http");
                (string eventId, string json) = CanaryEvent.Create();
                using HttpRequestMessage request = new(HttpMethod.Post, "/v1/events")
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using HttpResponseMessage accepted = await client.SendAsync(request, startup.Token);
                Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);

                await WaitForDeliveryAsync(sinks, collector, eventId);
            }
        }
        finally
        {
            Directory.Delete(work, recursive: true);
            // Only the Unix syslog listener creates it; absent on Windows or after an early failure.
            string socketDirectory = Path.GetDirectoryName(socket)!;
            if (Directory.Exists(socketDirectory))
            {
                Directory.Delete(socketDirectory, recursive: true);
            }
        }
    }

    private static async Task WaitForDeliveryAsync(HttpClient sinks, string collector, string eventId)
    {
        using CancellationTokenSource timeout = new(DeliveryTimeout);
        while (true)
        {
            if (collector == "collector-s3")
            {
                using HttpResponseMessage refresh = await sinks.PostAsync("/api/s3/refresh", null, timeout.Token);
                refresh.EnsureSuccessStatusCode();
            }

            using HttpResponseMessage found = await sinks.GetAsync($"/api/events/{eventId}", timeout.Token);
            if (found.StatusCode == HttpStatusCode.OK)
            {
                return;
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), timeout.Token);
            }
            catch (OperationCanceledException)
            {
                Assert.Fail($"{collector} did not deliver canary {eventId} to its stand-in within {DeliveryTimeout}.");
            }
        }
    }
}

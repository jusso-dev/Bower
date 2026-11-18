using System.Diagnostics;
using Bower.ServiceDefaults;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Bower.UnitTests;

/// <summary>Production behaviour is unchanged unless an OTLP endpoint opts in (Aspire harness).</summary>
public sealed class ServiceDefaultsTests
{
    [Fact]
    public void NoOtlpEndpointRegistersNothing()
    {
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        int before = builder.Services.Count;

        builder.AddBowerServiceDefaults();

        Assert.Equal(before, builder.Services.Count);
        using IHost host = builder.Build();
        Assert.Null(host.Services.GetService<TracerProvider>());
        Assert.Null(host.Services.GetService<MeterProvider>());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankOtlpEndpointIsNotAnOptIn(string value)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection([new(BowerServiceDefaults.OtlpEndpointSetting, value)])
            .Build();

        Assert.False(BowerServiceDefaults.IsEnabled(configuration));
    }

    [Fact]
    public void OtlpEndpointEnablesTracingAndMetrics()
    {
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Configuration.AddInMemoryCollection([new(BowerServiceDefaults.OtlpEndpointSetting, "http://127.0.0.1:4317")]);

        builder.AddBowerServiceDefaults();

        using IHost host = builder.Build();
        Assert.NotNull(host.Services.GetService<TracerProvider>());
        Assert.NotNull(host.Services.GetService<MeterProvider>());
    }

    [Fact]
    public void SpansKeepOnlyApprovedMetadata()
    {
        using Activity activity = new("Microsoft.AspNetCore.Hosting.HttpRequestIn");
        activity.Start();
        activity.SetTag("http.request.method", "POST");
        activity.SetTag("http.route", "/v1/events");
        activity.SetTag("http.response.status_code", 202);
        activity.SetTag("user_agent.original", "synthetic-private-marker");
        activity.SetTag("url.query", "?token=synthetic-private-marker");
        activity.SetTag("url.full", "http://127.0.0.1/health?private=synthetic-private-marker");
        activity.SetTag("client.address", "192.0.2.1");
        activity.SetStatus(ActivityStatusCode.Error, "synthetic-private-marker");
        activity.TraceStateString = "bower=synthetic-private-marker";
        activity.Stop();

        new MetadataOnlyActivityProcessor().OnEnd(activity);

        Assert.Equal(["http.request.method", "http.response.status_code", "http.route"],
            activity.TagObjects.Select(tag => tag.Key).Order(StringComparer.Ordinal));
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.Null(activity.StatusDescription);
        Assert.Null(activity.TraceStateString);
        Assert.DoesNotContain("synthetic-private-marker", string.Concat(activity.TagObjects.Select(tag => tag.Value)), StringComparison.Ordinal);
    }

    [Fact]
    public void RequestLogsReachTheExporterAtWarningOnly()
    {
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Configuration.AddInMemoryCollection([new(BowerServiceDefaults.OtlpEndpointSetting, "http://127.0.0.1:4317")]);

        builder.AddBowerServiceDefaults();

        using IHost host = builder.Build();
        LoggerFilterOptions filters = host.Services.GetRequiredService<IOptions<LoggerFilterOptions>>().Value;
        foreach (string category in BowerServiceDefaults.RequestLogCategories)
        {
            LoggerFilterRule rule = Assert.Single(filters.Rules, rule =>
                rule.CategoryName == category && rule.ProviderName == typeof(OpenTelemetryLoggerProvider).FullName);
            Assert.Equal(LogLevel.Warning, rule.LogLevel);
        }
    }

    [Fact]
    public async Task ExportedRequestSpansCarryNoRequestMarkers()
    {
        const string Marker = "synthetic-private-marker";
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        List<Activity> exported = [];
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection([new(BowerServiceDefaults.OtlpEndpointSetting, "http://127.0.0.1:4317")]);
        builder.AddBowerServiceDefaults();
        // Registered after the defaults, as an exporter would be: it sees the allowlisted span.
        builder.Services.ConfigureOpenTelemetryTracerProvider(tracing =>
            tracing.AddProcessor(new SimpleActivityExportProcessor(new CapturingExporter(exported))));

        await using WebApplication app = builder.Build();
        // A route no other test serves: the ASP.NET Core activity source is process-wide, so
        // parallel tests' hosts also produce server spans this tracer sees.
        app.MapGet("/service-defaults-probe/{name}", (string name) => Results.Ok());
        await app.StartAsync(cancellationToken);

        using HttpRequestMessage request = new(HttpMethod.Get, $"/service-defaults-probe/{Marker}?private={Marker}");
        request.Headers.UserAgent.ParseAdd(Marker);
        request.Headers.Add("X-Forwarded-For", "192.0.2.10");
        request.Headers.Add("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        request.Headers.Add("tracestate", "bower=" + Marker);
        using HttpResponseMessage response = await app.GetTestClient().SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        // The server span ends after TestServer hands back the response; wait for its export.
        Activity? span = null;
        using (CancellationTokenSource exportWait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            exportWait.CancelAfter(TimeSpan.FromSeconds(10));
            while (span is null)
            {
                lock (exported)
                {
                    span = exported.FirstOrDefault(activity => activity.Kind == ActivityKind.Server
                        && Equals(activity.GetTagItem("http.route"), "/service-defaults-probe/{name}"));
                }

                if (span is null)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(20), exportWait.Token);
                }
            }
        }

        await app.StopAsync(cancellationToken);

        Assert.Equal("GET", span.GetTagItem("http.request.method"));
        Assert.All(span.TagObjects, tag => Assert.Contains(tag.Key, MetadataOnlyActivityProcessor.AllowedTags));
        Assert.Null(span.TraceStateString);
        string exportedText = string.Concat(span.TagObjects.Select(tag => tag.Key + "=" + tag.Value))
            + span.DisplayName + span.StatusDescription + span.TraceStateString;
        Assert.DoesNotContain(Marker, exportedText, StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2.10", exportedText, StringComparison.Ordinal);
    }

    private sealed class CapturingExporter(List<Activity> exported) : BaseExporter<Activity>
    {
        public override ExportResult Export(in Batch<Activity> batch)
        {
            lock (exported)
            {
                foreach (Activity activity in batch)
                {
                    exported.Add(activity);
                }
            }

            return ExportResult.Success;
        }
    }
}

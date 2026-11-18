using System.Diagnostics;
using Bower.ServiceDefaults;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
        activity.Stop();

        new MetadataOnlyActivityProcessor().OnEnd(activity);

        Assert.Equal(["http.request.method", "http.response.status_code", "http.route"],
            activity.TagObjects.Select(tag => tag.Key).Order(StringComparer.Ordinal));
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.Null(activity.StatusDescription);
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
}

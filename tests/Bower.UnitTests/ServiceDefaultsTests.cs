using Bower.ServiceDefaults;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
}

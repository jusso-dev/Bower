using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Bower.ServiceDefaults;

/// <summary>
/// Opt-in host defaults for the Aspire local harness (<c>Bower.AppHost</c>). Production
/// behaviour is unchanged: nothing is registered unless <c>OTEL_EXPORTER_OTLP_ENDPOINT</c>
/// is set, which Aspire sets for every resource it starts and no shipped deployment sets.
/// </summary>
/// <remarks>
/// Exported telemetry is framework metadata only (request routes and status codes, runtime
/// and HTTP client metrics, log records). It never adds request or response bodies, headers
/// or query strings. HTTP client resilience and service discovery are not applied here: Bower
/// owns retries through the durable queue, and the management client's one-time enrolment
/// token must not be retried by a generic handler. Use
/// <see cref="AddBowerHttpClientDefaults"/> for a named client that explicitly wants them.
/// </remarks>
public static class BowerServiceDefaults
{
    /// <summary>The standard OpenTelemetry exporter endpoint variable; its presence opts in.</summary>
    public const string OtlpEndpointSetting = "OTEL_EXPORTER_OTLP_ENDPOINT";

    /// <summary>Meter names Bower code may publish; listed so the exporter picks them up.</summary>
    public const string MeterPrefix = "Bower.";

    /// <summary>True when an OTLP endpoint is configured (the opt-in signal).</summary>
    public static bool IsEnabled(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return !string.IsNullOrWhiteSpace(configuration[OtlpEndpointSetting]);
    }

    /// <summary>
    /// Adds OpenTelemetry logging, metrics and tracing with the OTLP exporter when
    /// <see cref="IsEnabled"/>; otherwise a no-op. Health is not added here: every Bower host
    /// already serves its own metadata-free health routes, which the AppHost probes.
    /// </summary>
    public static TBuilder AddBowerServiceDefaults<TBuilder>(this TBuilder builder)
        where TBuilder : IHostApplicationBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (!IsEnabled(builder.Configuration))
        {
            return builder;
        }

        builder.Logging.AddOpenTelemetry(logging =>
        {
            logging.IncludeFormattedMessage = true;
            // Scopes can carry request paths with query strings; keep records to the message.
            logging.IncludeScopes = false;
        });

        builder.Services.AddOpenTelemetry()
            .WithMetrics(metrics => metrics
                .AddMeter("Microsoft.AspNetCore.Hosting")
                .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
                .AddMeter("System.Net.Http")
                .AddMeter("System.Runtime")
                .AddMeter(MeterPrefix + "*"))
            .WithTracing(tracing => tracing
                .AddSource(builder.Environment.ApplicationName)
                .AddSource("Microsoft.AspNetCore")
                .AddSource("System.Net.Http")
                .AddSource(MeterPrefix + "*"))
            .UseOtlpExporter();

        return builder;
    }

    /// <summary>
    /// Standard resilience and service discovery for one named HTTP client. Opt-in per client;
    /// never apply it to clients that send single-use credentials or own their retry policy.
    /// </summary>
    public static IHttpClientBuilder AddBowerHttpClientDefaults(this IHttpClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddServiceDiscoveryCore();
        builder.AddServiceDiscovery();
        builder.AddStandardResilienceHandler();
        return builder;
    }
}

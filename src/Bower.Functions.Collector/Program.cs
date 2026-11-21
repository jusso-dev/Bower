using Bower.Functions.Collector;
using Bower.ServiceDefaults;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.Hosting;

// Settings, policies, privacy profile and producer scopes are validated before the worker
// accepts traffic; any failure stops start-up instead of running a fail-open collector.
FunctionsApplicationBuilder builder = FunctionsApplication.CreateBuilder(args);
// OpenTelemetry export for the Aspire local harness; a no-op unless OTEL_EXPORTER_OTLP_ENDPOINT
// is set. The Bicep template never sets it.
builder.AddBowerServiceDefaults();
builder.Services.AddBowerFunctionCollector(FunctionSettings.FromEnvironment());
builder.Build().Run();

using Bower.Functions.Collector;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.Hosting;

// Settings, policies, privacy profile and producer scopes are validated before the worker
// accepts traffic; any failure stops start-up instead of running a fail-open collector.
FunctionsApplicationBuilder builder = FunctionsApplication.CreateBuilder(args);
builder.Services.AddBowerFunctionCollector(FunctionSettings.FromEnvironment());
builder.Build().Run();

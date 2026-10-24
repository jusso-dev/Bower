using Azure.Core;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Core;
using Bower.Output.AzureLogsIngestion;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Bower.Functions.Collector;

/// <summary>
/// Composition shared by <c>Program</c> and tests. Everything is loaded once at start-up;
/// invalid policy, privacy profile, packs or producer scopes stop the worker.
/// </summary>
public static class FunctionCollectorServices
{
    public static IServiceCollection AddBowerFunctionCollector(
        this IServiceCollection services,
        FunctionSettings settings,
        IOutputAdapter? output = null,
        IProducerAuthenticator? authenticator = null,
        TokenCredential? credential = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();

        PolicyBundle bundle = PolicyBundle.Load(settings.PolicySources);
        DeterministicPolicyEvaluator evaluator = new(bundle.Policies);
        // Same redaction path as the HTTP collector: privacy profile (including custom
        // detectors) through JsonEventRedactor, then signed pack detections.
        IEventRedactor redactor = new PackDetectionRedactor(
            new JsonEventRedactor(bundle.Privacy), evaluator,
            bundle.LoadedPacks.SelectMany(pack => pack.Detections).ToArray());
        ProducerAuthorization authorization = settings.ProducerScopesJson is not null
            ? ProducerAuthorization.FromJson(settings.ProducerScopesJson)
            : new ProducerAuthorization(settings.ProducerScopesFile);

        services.AddSingleton(settings);
        services.AddSingleton(bundle);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ITelemetryPolicyEvaluator>(evaluator);
        services.AddSingleton(redactor);
        services.AddSingleton(authorization);
        services.AddSingleton(authenticator ?? CreateAuthenticator(settings));
        services.AddSingleton(output ?? CreateOutput(settings, credential ?? FunctionCredentialFactory.Create(settings)));
        services.AddSingleton(provider => new FunctionCollector(
            settings,
            bundle,
            redactor,
            evaluator,
            authorization,
            provider.GetRequiredService<IProducerAuthenticator>(),
            provider.GetRequiredService<IOutputAdapter>(),
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<ILogger<FunctionCollector>>()));
        return services;
    }

    public static IProducerAuthenticator CreateAuthenticator(FunctionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();
        return settings.DevelopmentAuthentication
            ? new DevelopmentProducerAuthenticator()
            : new EntraProducerAuthenticator(settings.EntraTenantId!, settings.EntraAudience!, settings.ProducerClaim);
    }

    public static AzureLogsIngestionOutput CreateOutput(
        FunctionSettings settings,
        TokenCredential credential,
        LogsIngestionClientOptions? clientOptions = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        clientOptions ??= new LogsIngestionClientOptions();
        // The caller is waiting: keep SDK retries short and bounded; the producer retries.
        clientOptions.Retry.MaxRetries = 2;
        clientOptions.Retry.Delay = TimeSpan.FromMilliseconds(500);
        clientOptions.Retry.MaxDelay = TimeSpan.FromSeconds(4);
        clientOptions.Retry.NetworkTimeout = TimeSpan.FromSeconds(20);
        return new AzureLogsIngestionOutput(
            new AzureLogsIngestionOptions
            {
                Id = "azure-logs-ingestion",
                Endpoint = settings.LogsIngestionEndpoint!,
                DcrImmutableId = settings.DcrImmutableId!,
                StreamName = settings.StreamName
            },
            credential,
            clientOptions);
    }
}

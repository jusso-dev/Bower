using Microsoft.Extensions.DependencyInjection;

namespace Bower.Sdk;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddBower(
        this IServiceCollection services,
        Action<BowerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        BowerOptions options = new();
        configure(options);
        options.Validate();
        services.AddSingleton(options);
        services.AddSingleton<IBowerTelemetry, BufferedBowerClient>();
        return services;
    }
}

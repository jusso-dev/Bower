namespace Bower.Sdk;

public sealed class BowerOptions
{
    public BowerApplicationOptions Application { get; } = new();

    public BowerTransport Transport { get; set; } = BowerTransport.LocalCollector;

    public LocalCollectorOptions LocalCollector { get; } = new();

    public bool FailApplicationOnTelemetryFailure { get; set; }

    public int BufferCapacity { get; set; } = 1_024;

    public TimeSpan ShutdownFlushTimeout { get; set; } = TimeSpan.FromSeconds(5);

    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Application.Name);
        ArgumentException.ThrowIfNullOrWhiteSpace(Application.Environment);
        if (BufferCapacity is < 1 or > 1_000_000)
        {
            throw new ArgumentOutOfRangeException(nameof(BufferCapacity));
        }

        if (Transport != BowerTransport.LocalCollector)
        {
            throw new NotSupportedException(
                $"Transport '{Transport}' is not implemented in this release.");
        }

        if (!Uri.TryCreate(LocalCollector.Endpoint, UriKind.Absolute, out Uri? endpoint)
            || endpoint.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("Local collector endpoint must be an absolute HTTP URI.");
        }
    }
}

public sealed class BowerApplicationOptions
{
    public string Name { get; set; } = string.Empty;

    public string Environment { get; set; } = string.Empty;

    public string? Version { get; set; }

    public string Instance { get; set; } = System.Environment.MachineName;

    public string? TenantId { get; set; }
}

public sealed class LocalCollectorOptions
{
    public string Endpoint { get; set; } = "http://127.0.0.1:4319";

    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(2);
}

public enum BowerTransport
{
    LocalCollector,
    FileSpool,
    NamedPipe,
    UnixSocket
}

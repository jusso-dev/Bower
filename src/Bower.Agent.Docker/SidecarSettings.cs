using System.Globalization;

namespace Bower.Agent.Docker;

/// <summary>Sidecar configuration from environment variables, validated before start.</summary>
public sealed record SidecarSettings
{
    public required string SidecarId { get; init; }

    public required Uri CollectorUrl { get; init; }

    public string? IngestToken { get; init; }

    public string DockerRoot { get; init; } = "/var/lib/docker/containers";

    public string OptInLabel { get; init; } = "bower.collect";

    public string StatePath { get; init; } = "/var/lib/bower-sidecar/cursors.db";

    public string HeartbeatPath { get; init; } = "/tmp/bower-sidecar/heartbeat";

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(5);

    public bool ReadExistingLogs { get; init; }

    public string Environment { get; init; } = "production";

    public static SidecarSettings FromEnvironment(Func<string, string?>? read = null)
    {
        read ??= System.Environment.GetEnvironmentVariable;
        string? tokenFile = read("BOWER_INGEST_TOKEN_FILE");
        string? token = string.IsNullOrWhiteSpace(tokenFile)
            ? read("BOWER_INGEST_TOKEN")
            : File.ReadAllText(tokenFile).Trim();
        string collector = read("BOWER_COLLECTOR_URL") ?? "http://bower-collector:4319";
        SidecarSettings settings = new()
        {
            SidecarId = read("BOWER_SIDECAR_ID") ?? System.Environment.MachineName,
            CollectorUrl = new Uri(collector.EndsWith('/') ? collector : collector + "/", UriKind.Absolute),
            IngestToken = string.IsNullOrWhiteSpace(token) ? null : token,
            DockerRoot = read("BOWER_DOCKER_ROOT") ?? "/var/lib/docker/containers",
            OptInLabel = read("BOWER_DOCKER_LABEL") ?? "bower.collect",
            StatePath = read("BOWER_SIDECAR_STATE") ?? "/var/lib/bower-sidecar/cursors.db",
            HeartbeatPath = read("BOWER_SIDECAR_HEARTBEAT") ?? "/tmp/bower-sidecar/heartbeat",
            PollInterval = TimeSpan.FromSeconds(ReadInt(read, "BOWER_POLL_SECONDS", 5)),
            ReadExistingLogs = string.Equals(read("BOWER_DOCKER_READ_EXISTING"), "true", StringComparison.OrdinalIgnoreCase),
            Environment = read("BOWER_ENVIRONMENT") ?? "production"
        };
        settings.Validate();
        return settings;
    }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(SidecarId);
        if (SidecarId.Length > 128)
        {
            throw new InvalidOperationException("BOWER_SIDECAR_ID cannot exceed 128 characters.");
        }

        if (CollectorUrl.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException("BOWER_COLLECTOR_URL must be an HTTP(S) URL.");
        }

        // The ingest token is a bearer secret. Cleartext HTTP is allowed only for loopback
        // or a single-label host (a Compose service name on a private Docker network).
        if (IngestToken is not null
            && CollectorUrl.Scheme == Uri.UriSchemeHttp
            && !CollectorUrl.IsLoopback
            && CollectorUrl.Host.Contains('.', StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "BOWER_COLLECTOR_URL must use HTTPS when it is not loopback or a Compose service name.");
        }

        if (PollInterval < TimeSpan.FromSeconds(1) || PollInterval > TimeSpan.FromMinutes(10))
        {
            throw new InvalidOperationException("BOWER_POLL_SECONDS must be between 1 and 600.");
        }

        if (string.IsNullOrWhiteSpace(OptInLabel))
        {
            throw new InvalidOperationException("BOWER_DOCKER_LABEL cannot be empty.");
        }
    }

    private static int ReadInt(Func<string, string?> read, string name, int fallback)
    {
        string? value = read(name);
        return string.IsNullOrWhiteSpace(value)
            ? fallback
            : int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
                ? parsed
                : throw new InvalidOperationException($"{name} must be an integer.");
    }
}

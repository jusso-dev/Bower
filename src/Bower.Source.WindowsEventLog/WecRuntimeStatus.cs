using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Bower.Source.WindowsEventLog;

/// <summary>Per-forwarder runtime state from <c>wecutil gr &lt;subscription&gt;</c>. Metadata only.</summary>
public sealed record WecEventSourceRuntimeStatus(
    string Machine,
    string State,
    DateTimeOffset? LastHeartbeatAt,
    int? LastErrorCode);

/// <summary>
/// Runtime summary of one Windows Event Collector subscription (<c>wecutil gr</c>),
/// reported in <c>/v1/status</c> and management heartbeats. Metadata only: never carries
/// event content.
/// </summary>
public sealed record WecSubscriptionRuntimeStatus(
    string SubscriptionId,
    string State,
    int ActiveClients,
    int InactiveClients,
    int ErrorClients,
    DateTimeOffset CapturedAt,
    IReadOnlyList<WecEventSourceRuntimeStatus> Sources,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ErrorCode = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Truncated = false);

/// <summary>Reads WEC runtime status for one named subscription. Mocked in cross-platform tests.</summary>
public interface IWecRuntimeReader
{
    Task<WecSubscriptionRuntimeStatus> ReadAsync(string subscriptionId, CancellationToken cancellationToken);
}

/// <summary>Parses <c>wecutil gr &lt;subscription&gt;</c> output into bounded metadata.</summary>
public static partial class WecRuntimeStatusParser
{
    public const int DefaultMaximumSources = 500;

    public static bool IsValidSubscriptionName(string? value) =>
        value is { Length: >= 1 and <= 128 } && ValidName().IsMatch(value);

    public static WecSubscriptionRuntimeStatus Parse(
        string subscriptionId,
        string output,
        DateTimeOffset capturedAt,
        int maximumSources = DefaultMaximumSources)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subscriptionId);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumSources, 1);

        string subscriptionState = "unknown";
        bool inEventSources = false;
        List<WecEventSourceRuntimeStatus> sources = [];
        int active = 0;
        int inactive = 0;
        int errors = 0;
        bool truncated = false;

        string? currentMachine = null;
        string currentState = "unknown";
        DateTimeOffset? currentHeartbeat = null;
        int? currentError = null;

        void CommitCurrent()
        {
            if (currentMachine is null)
            {
                return;
            }

            switch (currentState)
            {
                case "active":
                    active++;
                    break;
                case "inactive":
                    inactive++;
                    break;
                case "error":
                    errors++;
                    break;
                default:
                    inactive++;
                    break;
            }

            if (sources.Count < maximumSources)
            {
                sources.Add(new WecEventSourceRuntimeStatus(currentMachine, currentState, currentHeartbeat, currentError));
            }
            else
            {
                truncated = true;
            }

            currentMachine = null;
            currentState = "unknown";
            currentHeartbeat = null;
            currentError = null;
        }

        foreach (string rawLine in output.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(rawLine))
            {
                continue;
            }

            string trimmed = rawLine.Trim();

            if (!inEventSources)
            {
                if (TryKeyValue(trimmed, out string key, out string value))
                {
                    if (key.Equals("RunTimeStatus", StringComparison.OrdinalIgnoreCase))
                    {
                        subscriptionState = NormaliseState(value);
                    }
                    else if (key.Equals("EventSources", StringComparison.OrdinalIgnoreCase))
                    {
                        inEventSources = true;
                    }
                }
                else if (trimmed.Equals("EventSources:", StringComparison.OrdinalIgnoreCase))
                {
                    inEventSources = true;
                }

                continue;
            }

            // Inside EventSources: machine headers appear with shallow indentation and no key/value colon,
            // while properties (RunTimeStatus, LastError, LastHeartbeatTime) are deeper or carry key: value.
            if (TryKeyValue(trimmed, out string propKey, out string propValue))
            {
                if (currentMachine is null)
                {
                    continue;
                }

                if (propKey.Equals("RunTimeStatus", StringComparison.OrdinalIgnoreCase))
                {
                    currentState = NormaliseState(propValue);
                }
                else if (propKey.Equals("LastError", StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(propValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out int code))
                    {
                        currentError = code;
                        if (code != 0 && currentState is "unknown" or "active")
                        {
                            currentState = "error";
                        }
                    }
                }
                else if (propKey.Equals("LastHeartbeatTime", StringComparison.OrdinalIgnoreCase))
                {
                    if (DateTimeOffset.TryParse(
                            propValue,
                            CultureInfo.InvariantCulture,
                            DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal,
                            out DateTimeOffset heartbeat))
                    {
                        currentHeartbeat = heartbeat.ToUniversalTime();
                    }
                }
            }
            else
            {
                CommitCurrent();
                currentMachine = trimmed.Length > 255 ? trimmed[..255] : trimmed;
            }
        }

        CommitCurrent();
        return new WecSubscriptionRuntimeStatus(
            subscriptionId,
            subscriptionState,
            active,
            inactive,
            errors,
            capturedAt,
            sources,
            ErrorCode: null,
            Truncated: truncated);
    }

    private static bool TryKeyValue(string line, out string key, out string value)
    {
        int colon = line.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0)
        {
            key = string.Empty;
            value = string.Empty;
            return false;
        }

        key = line[..colon].Trim();
        value = line[(colon + 1)..].Trim();
        return key.Length > 0 && !key.Contains(' ', StringComparison.Ordinal);
    }

    private static string NormaliseState(string raw) =>
        raw.Trim().ToLowerInvariant() switch
        {
            "active" => "active",
            "inactive" => "inactive",
            "disabled" => "disabled",
            "error" or "trying" or "failed" => "error",
            _ => "unknown"
        };

    [GeneratedRegex("^[A-Za-z0-9._-]{1,128}$")]
    private static partial Regex ValidName();
}

/// <summary>Executes <c>wecutil.exe gr &lt;subscription&gt;</c> with validated fixed arguments on Windows.</summary>
public sealed class WindowsWecRuntimeReader(TimeProvider? clock = null) : IWecRuntimeReader
{
    private const int MaximumOutputBytes = 1_048_576;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);
    private readonly TimeProvider clock = clock ?? TimeProvider.System;

    public async Task<WecSubscriptionRuntimeStatus> ReadAsync(string subscriptionId, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (!WecRuntimeStatusParser.IsValidSubscriptionName(subscriptionId))
        {
            return new WecSubscriptionRuntimeStatus(subscriptionId, "error", 0, 0, 0, now, [], "wec-subscription-invalid");
        }

        if (!OperatingSystem.IsWindows())
        {
            return new WecSubscriptionRuntimeStatus(subscriptionId, "unavailable", 0, 0, 0, now, [], "wec-platform-unsupported");
        }

        (int exitCode, string stdout) = await RunFixedProcessAsync("wecutil.exe", ["gr", subscriptionId], CommandTimeout, MaximumOutputBytes, cancellationToken);
        if (exitCode == -2)
        {
            return new WecSubscriptionRuntimeStatus(subscriptionId, "error", 0, 0, 0, now, [], "wec-command-timeout");
        }

        if (exitCode != 0)
        {
            return new WecSubscriptionRuntimeStatus(subscriptionId, "error", 0, 0, 0, now, [], "wec-query-failed");
        }

        return WecRuntimeStatusParser.Parse(subscriptionId, stdout, now);
    }

    internal static async Task<(int ExitCode, string Stdout)> RunFixedProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo start = new(fileName)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = new() { StartInfo = start };
        try
        {
            if (!process.Start())
            {
                return (-1, string.Empty);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return (-1, string.Empty);
        }

        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(timeout);

        Task<string> stdoutTask = ReadBoundedAsync(process.StandardOutput, maximumBytes, linked.Token);
        Task<string> stderrTask = ReadBoundedAsync(process.StandardError, 16_384, linked.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token);
            string stdout = await stdoutTask;
            _ = await stderrTask;
            return (process.ExitCode, stdout);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // Best effort on timeout.
            }

            return (-2, string.Empty);
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maximumBytes, CancellationToken cancellationToken)
    {
        char[] buffer = new char[4096];
        StringBuilder output = new();
        int remaining = maximumBytes;
        while (remaining > 0)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Append(buffer, 0, read);
            remaining -= read;
        }

        return output.ToString();
    }
}

/// <summary>Caches the latest WEC runtime status per configured WEC subscription for /v1/status and heartbeats.</summary>
public sealed class WecRuntimeStatusTracker
{
    private readonly string[] subscriptions;
    private readonly IWecRuntimeReader reader;
    private volatile IReadOnlyList<WecSubscriptionRuntimeStatus> latest = [];

    public WecRuntimeStatusTracker(IReadOnlyList<string> subscriptions, IWecRuntimeReader reader)
    {
        ArgumentNullException.ThrowIfNull(subscriptions);
        ArgumentNullException.ThrowIfNull(reader);
        this.subscriptions = subscriptions
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        this.reader = reader;
    }

    public bool HasSubscriptions => subscriptions.Length > 0;

    public IReadOnlyList<WecSubscriptionRuntimeStatus> Snapshot() => latest;

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (subscriptions.Length == 0)
        {
            return;
        }

        List<WecSubscriptionRuntimeStatus> updated = new(subscriptions.Length);
        foreach (string subscription in subscriptions)
        {
            updated.Add(await reader.ReadAsync(subscription, cancellationToken));
        }

        latest = updated;
    }
}

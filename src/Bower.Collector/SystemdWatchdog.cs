using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace Bower.Collector;

/// <summary>Sends systemd <c>sd_notify</c> state messages. Swapped in tests.</summary>
public interface ISystemdNotifier
{
    bool Notify(string state);
}

/// <summary>
/// Reads <c>NOTIFY_SOCKET</c> and <c>WATCHDOG_USEC</c> from the systemd unit environment.
/// Inert when <c>NOTIFY_SOCKET</c> is unset.
/// </summary>
public sealed record SystemdWatchdogOptions(string? NotifySocket, TimeSpan? WatchdogInterval)
{
    public static readonly TimeSpan MinimumInterval = TimeSpan.FromSeconds(1);

    public bool IsEnabled => !string.IsNullOrWhiteSpace(NotifySocket);

    public static SystemdWatchdogOptions FromEnvironment(Func<string, string?>? read = null)
    {
        read ??= Environment.GetEnvironmentVariable;
        string? socket = read("NOTIFY_SOCKET");
        if (string.IsNullOrWhiteSpace(socket))
        {
            return new SystemdWatchdogOptions(null, null);
        }

        TimeSpan? interval = null;
        if (long.TryParse(read("WATCHDOG_USEC"), NumberStyles.Integer, CultureInfo.InvariantCulture, out long usec)
            && usec > 0)
        {
            // Keepalive at half the configured WatchdogSec, clamped to at least 1 second.
            TimeSpan half = TimeSpan.FromMicroseconds(usec / 2.0);
            interval = half < MinimumInterval ? MinimumInterval : half;
        }

        return new SystemdWatchdogOptions(socket, interval);
    }
}

/// <summary>
/// Pure-.NET Unix domain datagram <c>sd_notify</c> sender (no native libsystemd dependency).
/// Supports both filesystem paths (<c>/run/systemd/notify</c>) and Linux abstract sockets
/// (<c>@...</c>). Never throws on delivery failure.
/// </summary>
public sealed class UnixSystemdNotifier(string? socketPath) : ISystemdNotifier
{
    public bool Notify(string state)
    {
        if (string.IsNullOrWhiteSpace(socketPath) || string.IsNullOrWhiteSpace(state) || OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            string address = socketPath[0] == '@' ? "\0" + socketPath[1..] : socketPath;
            using Socket socket = new(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            socket.SendTo(Encoding.UTF8.GetBytes(state), SocketFlags.None, new UnixDomainSocketEndPoint(address));
            return true;
        }
        catch (Exception exception) when (exception is SocketException or IOException or PlatformNotSupportedException or ArgumentException)
        {
            return false;
        }
    }
}

/// <summary>
/// Sends <c>READY=1</c> on startup, periodic <c>WATCHDOG=1</c> keepalives when
/// <c>WATCHDOG_USEC</c> is set, and <c>STOPPING=1</c> on graceful shutdown. No-op when
/// <c>NOTIFY_SOCKET</c> is unset.
/// </summary>
public sealed class SystemdWatchdogService(
    SystemdWatchdogOptions options,
    ISystemdNotifier notifier,
    IHostApplicationLifetime lifetime,
    TimeProvider clock) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.IsEnabled)
        {
            return;
        }

        using CancellationTokenRegistration started = lifetime.ApplicationStarted.Register(() => notifier.Notify("READY=1"));
        using CancellationTokenRegistration stopping = lifetime.ApplicationStopping.Register(() => notifier.Notify("STOPPING=1"));

        if (options.WatchdogInterval is not { } interval)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // Stopping.
            }

            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, clock, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            notifier.Notify("WATCHDOG=1");
        }
    }
}

using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace Bower.Source.WindowsEventLog;

/// <summary>One check produced by <see cref="WecDoctorEvaluator"/>, matching <c>bower doctor</c> output.</summary>
public sealed record WecDoctorFinding(string Status, string Area, string Detail);

public sealed record WecDoctorSubscriptionSnapshot(
    string Name,
    bool Exists,
    bool Enabled,
    WecSubscriptionRuntimeStatus? Runtime,
    string? ErrorCode = null);

public sealed record WecChannelSnapshot(
    string Name,
    bool Exists,
    bool Enabled,
    long? MaxSizeBytes,
    long? FileSizeBytes,
    string? ErrorCode = null);

public sealed record WecWinRmListenerSnapshot(
    bool HasHttpsListener,
    int? Port,
    string? CertificateThumbprint,
    bool CertificateFound,
    DateTimeOffset? CertificateNotAfter,
    string? ErrorCode = null);

public sealed record WecHostSnapshot(
    bool IsWindows,
    string ServiceState,
    IReadOnlyList<WecDoctorSubscriptionSnapshot> Subscriptions,
    WecChannelSnapshot Channel,
    WecWinRmListenerSnapshot WinRmHttps);

/// <summary>Collects read-only WEC host state for <c>bower doctor</c>.</summary>
public interface IWecHostProbe
{
    Task<WecHostSnapshot> ProbeAsync(
        IReadOnlyList<string> subscriptions,
        string channelName,
        CancellationToken cancellationToken);
}

/// <summary>
/// Evaluates WEC host readiness for <c>bower doctor</c>: Wecsvc service, subscriptions
/// present and enabled, active forwarding clients, ForwardedEvents sizing and fill, and the
/// WinRM HTTPS 5986 listener and certificate expiry.
/// </summary>
public static class WecDoctorEvaluator
{
    public const long RecommendedChannelMinimumBytes = 1L * 1024 * 1024 * 1024;
    public const double ChannelFillWarningRatio = 0.80;
    public const int DefaultCertificateWarningDays = 30;

    public static IReadOnlyList<WecDoctorFinding> Evaluate(
        WecHostSnapshot snapshot,
        DateTimeOffset now,
        int certificateWarningDays = DefaultCertificateWarningDays)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        List<WecDoctorFinding> findings = [];

        if (!snapshot.IsWindows)
        {
            findings.Add(new("FAIL", "wec", "WEC host checks require Windows (Wecsvc, wecutil, wevtutil, WinRM)."));
            return findings;
        }

        // 1. Windows Event Collector service (Wecsvc).
        if (string.Equals(snapshot.ServiceState, "Running", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new("PASS", "wec", "Windows Event Collector service (Wecsvc) is running."));
        }
        else
        {
            findings.Add(new("FAIL", "wec", $"Windows Event Collector service (Wecsvc) is {snapshot.ServiceState}; run 'wecutil qc /q' and start Wecsvc."));
        }

        // 2 & 3. Subscriptions present/enabled and active clients via wecutil gr.
        foreach (WecDoctorSubscriptionSnapshot subscription in snapshot.Subscriptions)
        {
            if (subscription.ErrorCode is not null)
            {
                findings.Add(new("FAIL", "wec", $"Subscription '{subscription.Name}' could not be read ({subscription.ErrorCode})."));
                continue;
            }

            if (!subscription.Exists)
            {
                findings.Add(new("FAIL", "wec", $"Subscription '{subscription.Name}' is not registered; create it with 'wecutil cs'."));
                continue;
            }

            if (!subscription.Enabled)
            {
                findings.Add(new("FAIL", "wec", $"Subscription '{subscription.Name}' exists but is disabled."));
            }
            else
            {
                findings.Add(new("PASS", "wec", $"Subscription '{subscription.Name}' is present and enabled."));
            }

            if (subscription.Runtime is null || subscription.Runtime.ErrorCode is not null)
            {
                findings.Add(new("FAIL", "wec", $"Subscription '{subscription.Name}' runtime status unavailable ({subscription.Runtime?.ErrorCode ?? "unknown"})."));
            }
            else if (subscription.Runtime.ActiveClients > 0 && subscription.Runtime.ErrorClients == 0)
            {
                findings.Add(new("PASS", "wec",
                    $"Subscription '{subscription.Name}' has {subscription.Runtime.ActiveClients} active client(s), {subscription.Runtime.InactiveClients} inactive."));
            }
            else if (subscription.Runtime.ActiveClients > 0)
            {
                findings.Add(new("WARN", "wec",
                    $"Subscription '{subscription.Name}' has {subscription.Runtime.ActiveClients} active client(s), {subscription.Runtime.ErrorClients} in error."));
            }
            else if (subscription.Runtime.ErrorClients > 0)
            {
                findings.Add(new("FAIL", "wec",
                    $"Subscription '{subscription.Name}' has 0 active clients and {subscription.Runtime.ErrorClients} client(s) in error."));
            }
            else
            {
                findings.Add(new("WARN", "wec",
                    $"Subscription '{subscription.Name}' has 0 active clients ({subscription.Runtime.InactiveClients} inactive)."));
            }
        }

        // 4. ForwardedEvents log size and fill.
        WecChannelSnapshot channel = snapshot.Channel;
        if (channel.ErrorCode is not null || !channel.Exists)
        {
            findings.Add(new("FAIL", "wec", $"Channel '{channel.Name}' is missing or unreadable ({channel.ErrorCode ?? "not-found"})."));
        }
        else if (!channel.Enabled)
        {
            findings.Add(new("FAIL", "wec", $"Channel '{channel.Name}' is disabled."));
        }
        else if (channel.MaxSizeBytes is null or <= 0)
        {
            findings.Add(new("WARN", "wec", $"Channel '{channel.Name}' maxSize could not be determined."));
        }
        else
        {
            long maxBytes = channel.MaxSizeBytes.Value;
            long fileBytes = Math.Max(0, channel.FileSizeBytes ?? 0);
            double fillRatio = (double)fileBytes / maxBytes;
            double maxMiB = maxBytes / (1024.0 * 1024.0);
            double fillPercent = Math.Min(100.0, fillRatio * 100.0);

            if (maxBytes < RecommendedChannelMinimumBytes)
            {
                findings.Add(new("WARN", "wec",
                    $"Channel '{channel.Name}' maxSize is {maxMiB:F0} MiB (recommended >= 1024 MiB to absorb collector outages); fill {fillPercent:F1}%."));
            }
            else if (fillRatio >= ChannelFillWarningRatio)
            {
                findings.Add(new("WARN", "wec",
                    $"Channel '{channel.Name}' is {fillPercent:F1}% full ({maxMiB:F0} MiB maxSize)."));
            }
            else
            {
                findings.Add(new("PASS", "wec",
                    $"Channel '{channel.Name}' is enabled ({maxMiB:F0} MiB maxSize, {fillPercent:F1}% full)."));
            }
        }

        // 5. WinRM HTTPS 5986 listener and certificate expiry.
        WecWinRmListenerSnapshot winrm = snapshot.WinRmHttps;
        if (winrm.ErrorCode is not null)
        {
            findings.Add(new("FAIL", "wec", $"WinRM listener check failed ({winrm.ErrorCode})."));
        }
        else if (!winrm.HasHttpsListener)
        {
            findings.Add(new("FAIL", "wec", "No WinRM HTTPS listener found on port 5986; configure HTTPS (5986) for WEF."));
        }
        else if (winrm.Port != 5986)
        {
            findings.Add(new("WARN", "wec", $"WinRM HTTPS listener is on port {winrm.Port} instead of standard port 5986."));
        }
        else if (!winrm.CertificateFound || winrm.CertificateNotAfter is null)
        {
            findings.Add(new("FAIL", "wec", "WinRM HTTPS listener certificate was not found in LocalMachine\\My."));
        }
        else
        {
            TimeSpan remaining = winrm.CertificateNotAfter.Value - now;
            if (remaining <= TimeSpan.Zero)
            {
                findings.Add(new("FAIL", "wec",
                    $"WinRM HTTPS listener certificate expired on {winrm.CertificateNotAfter.Value:yyyy-MM-dd}."));
            }
            else if (remaining.TotalDays < certificateWarningDays)
            {
                findings.Add(new("WARN", "wec",
                    $"WinRM HTTPS listener certificate expires in {Math.Floor(remaining.TotalDays):F0} day(s) ({winrm.CertificateNotAfter.Value:yyyy-MM-dd})."));
            }
            else
            {
                findings.Add(new("PASS", "wec",
                    $"WinRM HTTPS listener active on port 5986; certificate valid for {Math.Floor(remaining.TotalDays):F0} day(s)."));
            }
        }

        return findings;
    }

    public static string ParseServiceState(string scQueryOutput)
    {
        ArgumentNullException.ThrowIfNull(scQueryOutput);
        foreach (string line in scQueryOutput.Split('\n'))
        {
            string trimmed = line.Trim();
            if (!trimmed.StartsWith("STATE", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (trimmed.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            {
                return "Running";
            }

            if (trimmed.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
            {
                return "Stopped";
            }

            if (trimmed.Contains("START_PENDING", StringComparison.OrdinalIgnoreCase))
            {
                return "Starting";
            }
        }

        return "Unknown";
    }

    public static bool ParseSubscriptionEnabled(string wecutilGsOutput)
    {
        ArgumentNullException.ThrowIfNull(wecutilGsOutput);
        foreach (string line in wecutilGsOutput.Split('\n'))
        {
            string trimmed = line.Trim();
            int colon = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0 && trimmed[..colon].Trim().Equals("Enabled", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[(colon + 1)..].Trim().Equals("true", StringComparison.OrdinalIgnoreCase);
            }
        }

        return false;
    }

    public static (bool Enabled, long? MaxSizeBytes, long? FileSizeBytes) ParseChannelProperties(
        string wevtutilGlOutput,
        string wevtutilGliOutput)
    {
        ArgumentNullException.ThrowIfNull(wevtutilGlOutput);
        ArgumentNullException.ThrowIfNull(wevtutilGliOutput);
        bool enabled = false;
        long? maxSize = null;
        long? fileSize = null;

        foreach (string line in wevtutilGlOutput.Split('\n'))
        {
            string trimmed = line.Trim();
            int colon = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            string key = trimmed[..colon].Trim();
            string value = trimmed[(colon + 1)..].Trim();
            if (key.Equals("enabled", StringComparison.OrdinalIgnoreCase))
            {
                enabled = value.Equals("true", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("maxSize", StringComparison.OrdinalIgnoreCase)
                && long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed))
            {
                maxSize = parsed;
            }
        }

        foreach (string line in wevtutilGliOutput.Split('\n'))
        {
            string trimmed = line.Trim();
            int colon = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            string key = trimmed[..colon].Trim();
            string value = trimmed[(colon + 1)..].Trim();
            if (key.Equals("fileSize", StringComparison.OrdinalIgnoreCase)
                && long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed))
            {
                fileSize = parsed;
            }
        }

        return (enabled, maxSize, fileSize);
    }

    public static (bool HasHttps, int? Port, string? Thumbprint) ParseWinRmListeners(string winrmOutput)
    {
        ArgumentNullException.ThrowIfNull(winrmOutput);
        bool inListener = false;
        bool isHttps = false;
        bool enabled = true;
        int? port = null;
        string? thumbprint = null;

        (bool, int?, string?)? found = null;
        void Commit()
        {
            if (inListener && isHttps && enabled)
            {
                found = (true, port, thumbprint);
            }

            isHttps = false;
            enabled = true;
            port = null;
            thumbprint = null;
        }

        foreach (string rawLine in winrmOutput.Split('\n'))
        {
            string trimmed = rawLine.Trim();
            if (trimmed.Equals("Listener", StringComparison.OrdinalIgnoreCase))
            {
                Commit();
                inListener = true;
                continue;
            }

            if (!inListener)
            {
                continue;
            }

            int equals = trimmed.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            string key = trimmed[..equals].Trim();
            string value = trimmed[(equals + 1)..].Trim();
            if (key.Equals("Transport", StringComparison.OrdinalIgnoreCase))
            {
                isHttps = value.Equals("HTTPS", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("Enabled", StringComparison.OrdinalIgnoreCase))
            {
                enabled = value.Equals("true", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("Port", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedPort))
            {
                port = parsedPort;
            }
            else if (key.Equals("CertificateThumbprint", StringComparison.OrdinalIgnoreCase) && value.Length > 0)
            {
                thumbprint = value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
            }
        }

        Commit();
        return found ?? (false, null, null);
    }
}

/// <summary>Live Windows implementation of <see cref="IWecHostProbe"/> using fixed-argument system utilities.</summary>
public sealed class WindowsWecHostProbe(TimeProvider? clock = null) : IWecHostProbe
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);
    private readonly WindowsWecRuntimeReader runtimeReader = new(clock);

    public async Task<WecHostSnapshot> ProbeAsync(
        IReadOnlyList<string> subscriptions,
        string channelName,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new WecHostSnapshot(
                IsWindows: false,
                ServiceState: "Unsupported",
                Subscriptions: [],
                Channel: new WecChannelSnapshot(channelName, false, false, null, null, "wec-platform-unsupported"),
                WinRmHttps: new WecWinRmListenerSnapshot(false, null, null, false, null, "wec-platform-unsupported"));
        }

        (int scExit, string scOutput) = await WindowsWecRuntimeReader.RunFixedProcessAsync(
            "sc.exe", ["query", "Wecsvc"], Timeout, 65_536, cancellationToken);
        string serviceState = scExit == 0 ? WecDoctorEvaluator.ParseServiceState(scOutput) : "Missing";

        List<WecDoctorSubscriptionSnapshot> subscriptionSnapshots = [];
        foreach (string name in subscriptions)
        {
            if (!WecRuntimeStatusParser.IsValidSubscriptionName(name))
            {
                subscriptionSnapshots.Add(new WecDoctorSubscriptionSnapshot(name, false, false, null, "wec-subscription-invalid"));
                continue;
            }

            (int gsExit, string gsOutput) = await WindowsWecRuntimeReader.RunFixedProcessAsync(
                "wecutil.exe", ["gs", name], Timeout, 131_072, cancellationToken);
            if (gsExit != 0)
            {
                subscriptionSnapshots.Add(new WecDoctorSubscriptionSnapshot(name, false, false, null));
                continue;
            }

            bool enabled = WecDoctorEvaluator.ParseSubscriptionEnabled(gsOutput);
            WecSubscriptionRuntimeStatus runtime = await runtimeReader.ReadAsync(name, cancellationToken);
            subscriptionSnapshots.Add(new WecDoctorSubscriptionSnapshot(name, true, enabled, runtime));
        }

        WecChannelSnapshot channel = await ProbeChannelAsync(channelName, cancellationToken);
        WecWinRmListenerSnapshot winrm = await ProbeWinRmAsync(cancellationToken);
        return new WecHostSnapshot(true, serviceState, subscriptionSnapshots, channel, winrm);
    }

    private static async Task<WecChannelSnapshot> ProbeChannelAsync(string channelName, CancellationToken cancellationToken)
    {
        if (!WindowsEventLogSourceConfigurationLoader.IsName(channelName, allowSlash: true))
        {
            return new WecChannelSnapshot(channelName, false, false, null, null, "wec-channel-invalid");
        }

        (int glExit, string glOutput) = await WindowsWecRuntimeReader.RunFixedProcessAsync(
            "wevtutil.exe", ["gl", channelName], Timeout, 65_536, cancellationToken);
        if (glExit != 0)
        {
            return new WecChannelSnapshot(channelName, false, false, null, null, "wec-channel-unreadable");
        }

        (int gliExit, string gliOutput) = await WindowsWecRuntimeReader.RunFixedProcessAsync(
            "wevtutil.exe", ["gli", channelName], Timeout, 65_536, cancellationToken);
        (bool enabled, long? maxSize, long? fileSize) = WecDoctorEvaluator.ParseChannelProperties(
            glOutput, gliExit == 0 ? gliOutput : string.Empty);
        return new WecChannelSnapshot(channelName, true, enabled, maxSize, fileSize);
    }

    private static async Task<WecWinRmListenerSnapshot> ProbeWinRmAsync(CancellationToken cancellationToken)
    {
        (int exit, string output) = await WindowsWecRuntimeReader.RunFixedProcessAsync(
            "winrm.cmd", ["enumerate", "winrm/config/listener"], Timeout, 131_072, cancellationToken);
        if (exit != 0)
        {
            return new WecWinRmListenerSnapshot(false, null, null, false, null, "winrm-query-failed");
        }

        (bool hasHttps, int? port, string? thumbprint) = WecDoctorEvaluator.ParseWinRmListeners(output);
        if (!hasHttps)
        {
            return new WecWinRmListenerSnapshot(false, port, null, false, null);
        }

        if (string.IsNullOrEmpty(thumbprint))
        {
            return new WecWinRmListenerSnapshot(true, port, null, false, null);
        }

        try
        {
            using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            if (matches.Count == 0)
            {
                return new WecWinRmListenerSnapshot(true, port, thumbprint, false, null);
            }

            DateTimeOffset notAfter = new DateTimeOffset(matches[0].NotAfter.ToUniversalTime(), TimeSpan.Zero);
            foreach (X509Certificate2 certificate in matches)
            {
                certificate.Dispose();
            }

            return new WecWinRmListenerSnapshot(true, port, thumbprint, true, notAfter);
        }
        catch (Exception)
        {
            return new WecWinRmListenerSnapshot(true, port, thumbprint, false, null, "winrm-cert-store-unreadable");
        }
    }
}

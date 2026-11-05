using Bower.Collector.Relay;
using Bower.Core;
using Bower.Packs;
using Bower.Source.File;
using Bower.Source.Syslog;
using Bower.Source.WindowsEventLog;

namespace Bower.Collector;

/// <summary>
/// Every file a collector start reads besides the policy bundle, loaded and checked the
/// same way for start-up (<see cref="CollectorApplication.Build"/>) and for the signed
/// <c>reload</c> pre-check: source expectations, producer scopes and ingest tokens, the
/// syslog, Windows Event Log and file tail configurations and their routes to the loaded packs, the
/// syslog TLS material, and the relay's pins and certificates. A reload is therefore
/// refused for exactly the files that would stop a restart.
/// </summary>
/// <remarks>
/// Environment variables are read once when the process starts. A changed supervisor
/// environment (systemd <c>EnvironmentFile</c>, the Windows service environment) is not
/// visible to the running process, so it is not checked here; apply it with a supervisor
/// restart. <c>BOWER_SETTINGS_FILE</c> and <c>collector-id</c> are read by the collector
/// itself, so the reload pre-check rebuilds the settings from them first
/// (<see cref="CollectorSettingsFile.RestartReader"/>).
/// </remarks>
public sealed record CollectorStartupSources(
    SourceExpectations? Expectations,
    SyslogSourceConfiguration? Syslog,
    WindowsEventLogSourceConfiguration? WindowsEventLog,
    ProducerAuthorization Producers,
    IngestAuthentication Ingest,
    RelayDownstreams? RelayDownstreams,
    FileTailSourceConfiguration? FileTail = null)
{
    public static CollectorStartupSources Load(CollectorSettings settings, PolicyBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(bundle);
        SourceExpectations? expectations = settings.SourceExpectationsPath is null
            ? null
            : SourceExpectationsLoader.LoadFile(settings.SourceExpectationsPath);
        SyslogSourceConfiguration? syslog = null;
        if (settings.SyslogConfigPath is not null)
        {
            syslog = SyslogSourceConfigurationLoader.LoadFile(settings.SyslogConfigPath);
            SyslogRoutes.Validate(syslog, bundle);
            SyslogSource.ValidateTls(syslog);
        }

        WindowsEventLogSourceConfiguration? windowsEventLog = null;
        if (settings.WindowsEventLogConfigPath is not null)
        {
            windowsEventLog = WindowsEventLogSourceConfigurationLoader.LoadFile(settings.WindowsEventLogConfigPath);
            WindowsEventLogRoutes.Validate(windowsEventLog, bundle);
        }

        FileTailSourceConfiguration? fileTail = null;
        if (settings.FileTailConfigPath is not null)
        {
            fileTail = FileTailSourceConfigurationLoader.LoadFile(settings.FileTailConfigPath);
            FileTailRoutes.Validate(fileTail, bundle);
        }

        RelayDownstreams? downstreams = null;
        if (settings.IsRelay)
        {
            downstreams = RelayDownstreams.Load(settings.RelayDownstreamsFile!);
            using (RelayCertificates.Load(
                settings.RelayCertificateFile!,
                settings.RelayKeyFile!,
                "BOWER_RELAY_CERTIFICATE_FILE and BOWER_RELAY_KEY_FILE"))
            {
            }
        }

        if (string.Equals(settings.OutputType, "relay", StringComparison.Ordinal))
        {
            // The client certificate, key and CA bundle the relay output reads at start.
            using (new RelayHttp(settings))
            {
            }
        }

        return new CollectorStartupSources(
            expectations,
            syslog,
            windowsEventLog,
            new ProducerAuthorization(settings.ProducerScopesFile, settings.SingleTrustDomain),
            new IngestAuthentication(settings.IngestToken, settings.IngestTokensFile),
            downstreams,
            fileTail);
    }
}

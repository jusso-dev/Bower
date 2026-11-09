namespace Bower.Cli.Commands;

/// <summary>
/// <c>bower --help</c>. Also the source of <c>docs/reference/cli.md</c>
/// (<c>tools/docs/generate_cli_reference.py</c>); <c>CliHelpTests</c> fails when they differ.
/// </summary>
internal static class CliHelp
{
    public const string Text =
        """
        Bower security telemetry

        Commands:
          bower validate [--policy-directory PATH]
          bower pipeline validate --file PATH
          bower pipeline template [--id sentinel-app|aws-security]
          bower queue inspect [--database PATH]
          bower test emit [--endpoint URL]      (sends BOWER_INGEST_TOKEN when set)
          bower token generate [--id PRODUCER] (new ingest token; --id prints a tokens-file line)

          bower doctor [--policy-directory DIR] [--pack FILE --trusted-key PUB] [--privacy-profile FILE]
                       [--hmac-key-file FILE] [--collector-url URL] [--database FILE]
                       [--ingestion-endpoint URL] [--dcr-resource-id ID] [--workspace-resource-id ID]
                       [--credential azure-cli|managed-identity|workload-identity|environment] [--json]

          bower dcr generate [--out FILE] [--rule-name NAME] [--retention-days N] [--total-retention-days N]
          bower dcr diff (--rule FILE | --dcr-resource-id ID) [--table FILE | --workspace-resource-id ID]

          bower keys generate --out-dir DIR [--name NAME]
          bower pack build DIR --key PRIVATE.pem [--out DIR]
          bower pack verify|inspect|test FILE --trusted-key PUBLIC.pem
                [--hmac-key-file FILE] [--parser NAME] [--report FILE [--report-format json|junit]] (test)
          bower pack diff OLD.bowerpack NEW.bowerpack --trusted-key PUBLIC.pem

          bower evidence run --collector-url URL [--workspace-id ID --workspace-resource-id ID]
                             [--table NAME] [--signing-key PRIVATE.pem] [--out FILE]
                             [--probe-profile generic|parser:PACK:INDEX]
          bower evidence verify FILE --trusted-key PUBLIC.pem

          bower queue dead-letters --database FILE
          bower queue replay --database FILE (--code PREFIX | --event ID ...)
          bower queue verify --database FILE [--expect-head SEQUENCE:HASH]
          bower queue backup --database FILE --output BACKUP [--collector-id ID]
          bower queue restore --backup BACKUP --database FILE [--allow-damaged]
          bower developer init [--path PATH]
          bower privacy validate FILE [--hmac-key-file FILE] [--sample FILE]
          bower policy test EVENT.json... [--policy-directory DIR] [--pack FILE --trusted-key PUB]
                [--privacy-profile FILE --hmac-key-file FILE] [--expect DECISION]
          bower policy diff --baseline DIR --candidate DIR EVENT.json... [--fail-on-change]
                [--baseline-pack FILE --baseline-trusted-key PUB] [--baseline-privacy-profile FILE]
                [--baseline-hmac-key-file FILE] [--baseline-hmac-key-id ID] (same for --candidate-*) [--at ISO]
          bower archive create --archive DIR [--database FILE] [--collector-id ID]
          bower archive verify --archive DIR [--anchor SEQUENCE:HASH]
          bower archive replay --archive DIR --collector-url URL [--from ISO] [--to ISO]
                               [--event-type TYPE]... [--collector-id ID] [--dry-run]
          bower sources check --expectations FILE [--database FILE]
          bower wec subscription generate --config FILE --subscription ID [--mode MinLatency|Normal|MinBandwidth|Custom]
                [--max-items N --max-latency-seconds N] [--heartbeat-seconds N] [--read-existing] [--subscription-id NAME]
                [--allowed-domain-computers SDDL] [--issuer-ca THUMBPRINT]... [--log-file CHANNEL] [--out FILE]
          bower tap [--collector URL] [--stage redacted|decided|queued] [--source APP] [--event-type TYPE]
                    [--limit N] [--duration SECONDS] [--sample N]   (post-redaction JSON lines on stdout)
          bower top [--collector URL] [--interval SECONDS] [--once] [--iterations N]
          bower version | bower --version
        """;
}

using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Bower.Management.Api.SourceSetupRegistry;

namespace Bower.Management.Api;

/// <summary>
/// Bounded, allow-listed systemd journald source (src/Bower.Source.Journald,
/// docs/deployment/journald-source.md). Enforces explicit systemd unit or
/// SYSLOG_IDENTIFIER allow-lists (no empty list, no wildcards) and durable cursor tracking.
/// </summary>
internal sealed partial class JournaldSourceSetup : SourceSetupType
{
    public override string Id => "journald";

    public override string Title => "Linux systemd journald";

    public override string Summary =>
        "Reads allow-listed systemd units or syslog identifiers directly from the local journal with durable cursors.";

    public override string Why =>
        "Modern Linux hosts record SSH, sudo and authentication telemetry in systemd-journald. Naming explicit units or identifiers keeps general host noise out while preserving durable resume across restarts.";

    public override IReadOnlyList<string> Needs =>
    [
        "A Linux host running systemd-journald with the collector user in the systemd-journal group.",
        "Explicit systemd unit names (for example ssh.service) or SYSLOG_IDENTIFIER values (for example sshd, sudo).",
        "A signed journald parser pack such as linux-journald-ssh loaded on the collector."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "subscriptionName", "Subscription name", SourceFieldKinds.Text, true,
                "Stable cursor name for this journald subscription. Keep it unchanged across restarts.",
                "linux-journald-ssh", MaximumLength: 64),
            IdentifierPattern(),
            "Use letters, digits, dots, hyphens and underscores only."),
        new(
            new SourceFieldDefinition(
                "units", "Allowed systemd units", SourceFieldKinds.NameList, false,
                "Explicit systemd unit names, comma- or space-separated (for example ssh.service, sshd.service). Wildcards are refused.",
                "ssh.service,sshd.service", Placeholder: "ssh.service, sshd.service", MaximumLength: 512),
            JournaldEntryPattern(),
            "Use explicit unit names (letters, digits, '.', '_', '-', '@', ':') with no wildcards."),
        new(
            new SourceFieldDefinition(
                "identifiers", "Allowed SYSLOG_IDENTIFIER values", SourceFieldKinds.NameList, false,
                "Optional explicit SYSLOG_IDENTIFIER values (for example sshd, sudo). Wildcards are refused.",
                Placeholder: "sshd, sudo", MaximumLength: 512),
            JournaldEntryPattern(),
            "Use explicit identifier names (letters, digits, '.', '_', '-', '@', ':') with no wildcards."),
        new(new SourceFieldDefinition(
            "maxBatchSize", "Maximum batch size", SourceFieldKinds.Number, true,
            "Maximum journal entries read per poll cycle (1 to 500).",
            "128", Minimum: 1, Maximum: 500, MaximumLength: 4)),
        Application("linux-journald-ssh", "The application name events carry in Sentinel."),
        SourceSetupRegistry.Environment(),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the application and environment above. It turns green when the collector reports journald events.";

    public override string Guide => "docs/deployment/journald-source.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        IReadOnlyList<string> units = List(values, "units");
        IReadOnlyList<string> identifiers = List(values, "identifiers");
        if (units.Count == 0 && identifiers.Count == 0)
        {
            checks.Add(Fail(
                "units",
                "Journald requires at least one explicit systemd unit or SYSLOG_IDENTIFIER.",
                "Enter at least one unit such as ssh.service or identifier such as sshd."));
            return;
        }

        if (units.Count + identifiers.Count > 64)
        {
            checks.Add(Fail(
                "units",
                "Combined units and SYSLOG_IDENTIFIER entries cannot exceed 64.",
                "List at most 64 explicit units and identifiers in total."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        IReadOnlyList<string> units = List(values, "units");
        IReadOnlyList<string> identifiers = List(values, "identifiers");
        int maxBatchSize = int.Parse(values["maxBatchSize"], CultureInfo.InvariantCulture);

        JsonObject config = new()
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "JournaldSource",
            ["subscriptionName"] = values["subscriptionName"],
            ["units"] = new JsonArray([.. units.Select(u => JsonValue.Create(u))]),
            ["identifiers"] = new JsonArray([.. identifiers.Select(i => JsonValue.Create(i))]),
            ["maxRecordBytes"] = 32_768,
            ["maxBatchSize"] = maxBatchSize,
            ["application"] = values["application"],
            ["environment"] = values["environment"]
        };

        SourceSetupFile journaldFile = new(
            "journald.json",
            "/etc/bower/journald.json",
            "Allow-listed systemd journald source settings. Bower reads only the listed units and identifiers.",
            Json(config));

        string systemdDropIn =
            "[Service]\n" +
            "SupplementaryGroups=systemd-journal\n" +
            "Environment=BOWER_JOURNALD_CONFIG=/etc/bower/journald.json\n";

        return new SourceSetupBuild(
            [journaldFile, Expectations(values["application"], values["environment"], values["maximumSilenceMinutes"])],
            [
                new("collector", "BOWER_JOURNALD_CONFIG", "/etc/bower/journald.json"),
                ExpectationsVariable()
            ],
            [new SourceSetupSnippet(
                "systemd: read-only journal access drop-in",
                "Place in /etc/systemd/system/bower-collector.service.d/journald.conf so the collector reads the journal without root privileges.",
                "ini",
                systemdDropIn)],
            ApplicationVerification(values["application"], values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values)
    {
        IReadOnlyList<string> units = List(values, "units");
        IReadOnlyList<string> identifiers = List(values, "identifiers");
        string unit = units.Count > 0
            ? units[0]
            : identifiers.Count > 0
                ? identifiers[0]
                : "sshd.service";
        return new JsonObject
        {
            ["eventType"] = "ssh_login_failed",
            ["eventAction"] = "auth.ssh.failed",
            ["eventResult"] = "failure",
            ["application"] = new JsonObject { ["name"] = values["application"], ["environment"] = values["environment"] },
            ["actor"] = new JsonObject { ["username"] = "ops.user@example.org" },
            ["source"] = new JsonObject { ["ipAddress"] = "198.51.100.42" },
            ["attributes"] = new JsonObject
            {
                ["journald.subscription"] = values["subscriptionName"],
                ["journald.unit"] = unit,
                ["auth.note"] = "Failed password for ops.user@example.org (TFN 123 456 782)"
            }
        };
    }

    [GeneratedRegex("^[A-Za-z0-9._@:-]{1,128}$")]
    private static partial Regex JournaldEntryPattern();
}

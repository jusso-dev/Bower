using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Bower.Management.Api.SourceSetupRegistry;

namespace Bower.Management.Api;

/// <summary>The shipped narrow Windows network-logon parser; no arbitrary channels or XPath.</summary>
internal sealed partial class WindowsEventLogSourceSetup : SourceSetupType
{
    public override string Id => "windows-eventlog";
    public override string Title => "Windows Event Log";
    public override string Summary => "Collect failed network sign-ins (Security event 4625, logon type 3) on a Windows collector.";
    public override string Why => "A narrow, signed parser selects security decisions without forwarding the whole Windows log.";
    public override IReadOnlyList<string> Needs =>
    [
        "The C# Bower collector installed as the Bower Windows service. The Rust collector does not support this reader.",
        "The windows-security-logon pack installed, signed by a key the collector trusts, with parser 0 active.",
        "Windows auditing enabled for failed logons, and the Bower service identity granted access to the Security channel.",
        "An administrator to install the approved files and restart the service. Central WEC forwarding is a separate deployment step."
    ];
    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(new SourceFieldDefinition("subscriptionId", "Subscription name", SourceFieldKinds.Text, true,
            "A unique name for this narrow reader. Keep it stable so its durable bookmark can resume.", "security-logon", MaximumLength: 63),
            SubscriptionPattern(), "Use lowercase letters, digits and hyphens; start with a letter or digit."),
        new(new SourceFieldDefinition("directory", "Configuration directory", SourceFieldKinds.FilePath, true,
            "An existing Windows directory readable by the Bower service. The generated files are installed here.",
            @"C:\ProgramData\Bower", MaximumLength: 200)),
        new(new SourceFieldDefinition("readExisting", "Read existing matching events", SourceFieldKinds.Boolean, true,
            "Yes reads historical matching events on first start. No starts with new events. Existing bookmarks always resume.", "false", MaximumLength: 5)),
        Silence()
    ];
    public override string CheckDescription => "Checks the heartbeat for windows-security/production and a newly accepted event after approval. This does not prove Sentinel delivery.";
    public override string Guide => "docs/deployment/windows-event-log-source.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        if (values["directory"].StartsWith('/'))
        {
            checks.Add(Fail("directory", "This reader needs a Windows directory.", @"Use a path such as C:\ProgramData\Bower on the Windows collector."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        string directory = values["directory"].TrimEnd('\\');
        string configurationPath = directory + @"\windows-event-log.json";
        string expectationsPath = directory + @"\source-expectations.json";
        SourceSetupFile configuration = new("windows-event-log.json", configurationPath,
            "Reads only Security event 4625 from Microsoft-Windows-Security-Auditing. The signed pack further selects network logons. Merge into an existing subscriptions list rather than replacing other readers.",
            Json(new JsonObject
            {
                ["apiVersion"] = "bower.security/v1",
                ["kind"] = "WindowsEventLogSource",
                ["subscriptions"] = new JsonArray(new JsonObject
                {
                    ["id"] = values["subscriptionId"],
                    ["channel"] = "Security",
                    ["eventIds"] = new JsonArray(4625),
                    ["providers"] = new JsonArray("Microsoft-Windows-Security-Auditing"),
                    ["pack"] = "windows-security-logon",
                    ["parser"] = 0,
                    ["readExisting"] = values["readExisting"] == "true",
                    ["includeMessage"] = false
                })
            }));
        return new SourceSetupBuild(
            [configuration, Expectations("windows-security", "production", values["maximumSilenceMinutes"]) with { InstallPath = expectationsPath }],
            [new("collector", "BOWER_WINDOWS_EVENTLOG_CONFIG", configurationPath), new("collector", "BOWER_SOURCE_EXPECTATIONS", expectationsPath)],
            [new SourceSetupSnippet("Windows: apply approved settings",
                "After a different approver approves the request, install or merge the files at the paths above. Run this in an elevated PowerShell session after checking pack trust and channel permissions.",
                "powershell",
                $"[Environment]::SetEnvironmentVariable('BOWER_WINDOWS_EVENTLOG_CONFIG', '{configurationPath}', 'Machine')\n"
                + $"[Environment]::SetEnvironmentVariable('BOWER_SOURCE_EXPECTATIONS', '{expectationsPath}', 'Machine')\n"
                + "Restart-Service -Name Bower\n")],
            ApplicationVerification("windows-security", "production"));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "authentication_failure",
        ["eventAction"] = "authentication.attempt",
        ["eventResult"] = "failure",
        ["application"] = new JsonObject { ["name"] = "windows-security", ["environment"] = "production" },
        ["actor"] = new JsonObject { ["username"] = "casey.example@example.com" },
        ["source"] = new JsonObject { ["ipAddress"] = "192.0.2.10" },
        ["eventOutcomeReason"] = "InvalidCredentials"
    };

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,62}$")]
    private static partial Regex SubscriptionPattern();
}

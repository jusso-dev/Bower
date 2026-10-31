using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Bower.Management.Api.SourceSetupRegistry;

namespace Bower.Management.Api;

/*
 * The guided source types. Each one turns validated values into the exact configuration the
 * component already reads (docs/deployment/*), plus the source expectation that makes the
 * collector report the source on its heartbeat, which is how the server proves it works.
 * Snippets constrain identifiers and quote file paths with a JSON writer (also valid C# literals).
 */

/// <summary>RFC 5424/3164 syslog listener (docs/deployment/syslog-source.md).</summary>
internal sealed partial class SyslogSourceSetup : SourceSetupType
{
    private static readonly SourceFieldOption[] Protocols =
    [
        new("tls", "TLS (recommended)"),
        new("tcp", "TCP, this host only"),
        new("udp", "UDP, this host only")
    ];

    private static readonly string[] TlsOnly = ["tls"];

    public override string Id => "syslog";

    public override string Title => "Syslog";

    public override string Summary =>
        "Network appliances and Linux services send syslog to a listener on the collector. Only messages a signed pack parser selects become events.";

    public override string Why =>
        "Syslog carries sign-in failures and firewall decisions from systems that cannot run an SDK. Bower keeps only the messages a pack understands.";

    public override IReadOnlyList<string> Needs =>
    [
        "An approved collector that loads the signed pack for these messages (for example linux-ssh-gateway).",
        "For TLS: a server certificate and private key file on the collector host, and the CA that issued it on each sender.",
        "The addresses or ranges of the senders that may connect.",
        "Someone who can edit the sender's rsyslog configuration."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(new SourceFieldDefinition(
            "protocol", "Protocol", SourceFieldKinds.Choice, true,
            "TLS works across the network. Plain TCP and UDP are offered only on this host (loopback).",
            "tls", Options: Protocols, MaximumLength: 8)),
        new(
            new SourceFieldDefinition(
                "listenerId", "Listener name", SourceFieldKinds.Text, true,
                "A short name for this listener: lowercase letters, digits and hyphens.", "edge-tls", MaximumLength: 63),
            ListenerPattern(),
            "Use lowercase letters, digits and hyphens only."),
        new(new SourceFieldDefinition(
            "address", "Listen address", SourceFieldKinds.Text, true,
            "The collector address to listen on. 0.0.0.0 listens on every interface; TCP and UDP need 127.0.0.1 or ::1.",
            "0.0.0.0", MaximumLength: 45)),
        new(new SourceFieldDefinition(
            "port", "Port", SourceFieldKinds.Number, true,
            "6514 is the standard syslog-over-TLS port. 1 to 65535.", "6514", Minimum: 1, Maximum: 65_535, MaximumLength: 5)),
        new(new SourceFieldDefinition(
            "handshakeStartTimeoutSeconds", "TLS handshake start timeout (seconds)", SourceFieldKinds.Number, true,
            "Maximum wait for the first TLS handshake byte. Check lazy sender reconnects; a custom value requires an updated collector.",
            "60", Minimum: 1, Maximum: 3_600, MaximumLength: 4, ShownWhenField: "protocol", ShownWhenValues: TlsOnly)),
        new(new SourceFieldDefinition(
            "allowedSenders", "Allowed senders", SourceFieldKinds.AddressList, true,
            "IP addresses or CIDR ranges that may connect, one per line (at most 64). Everything else is refused.",
            Placeholder: "10.20.0.0/24", MaximumLength: 4096)),
        new(new SourceFieldDefinition(
            "certificateFile", "Server certificate file", SourceFieldKinds.FilePath, true,
            "Path of the PEM certificate on the collector host.", Placeholder: "/etc/bower/syslog/server.pem",
            MaximumLength: 260, ShownWhenField: "protocol", ShownWhenValues: TlsOnly)),
        new(new SourceFieldDefinition(
            "privateKeyFile", "Server private key file", SourceFieldKinds.SecretReference, true,
            "Path of the PEM private key on the collector host. Enter the path, never the key.",
            Placeholder: "/etc/bower/syslog/server-key.pem", MaximumLength: 260,
            ShownWhenField: "protocol", ShownWhenValues: TlsOnly)),
        new(new SourceFieldDefinition(
            "clientCertificateAuthorityFile", "Sender CA file (optional)", SourceFieldKinds.FilePath, false,
            "Set it to require mutual TLS: senders must present a certificate from this CA.",
            Placeholder: "/etc/bower/syslog/senders-ca.pem", MaximumLength: 260,
            ShownWhenField: "protocol", ShownWhenValues: TlsOnly)),
        new(
            new SourceFieldDefinition(
                "appName", "Program name to accept", SourceFieldKinds.Text, false,
                "Only messages from this program (syslog app-name) reach the parser, for example sshd.", "sshd", MaximumLength: 48),
            AppNamePattern(),
            "Use letters, digits, dots, hyphens, underscores and slashes only."),
        new(
            new SourceFieldDefinition(
                "hostname", "Sender host name to accept (optional)", SourceFieldKinds.Text, false,
                "Only messages that claim this host name reach the parser.", Placeholder: "fw01", MaximumLength: 255),
            HostPattern(),
            "Use letters, digits, dots, hyphens and colons only."),
        new(
            new SourceFieldDefinition(
                "pack", "Pack", SourceFieldKinds.Text, true,
                "The signed pack whose parser reads these messages. The collector refuses to start if it is not loaded.",
                "linux-ssh-gateway", MaximumLength: 64),
            PackPattern(),
            "Use the pack id: lowercase letters, digits and hyphens."),
        new(new SourceFieldDefinition(
            "parser", "Parser number", SourceFieldKinds.Number, true,
            "The position of the parser in the pack, starting at 0.", "0", Minimum: 0, Maximum: 63, MaximumLength: 2)),
        Application(
            "ssh-gateway",
            "Must match the parser's applicationName (ssh-gateway for linux-ssh-gateway parser 0), so the collector can report it."),
        SourceSetupRegistry.Environment(),
        Silence(),
        new(
            new SourceFieldDefinition(
                "collectorHost", "Collector name senders use", SourceFieldKinds.Text, true,
                "The DNS name or IP address senders connect to. With TLS it must match the server certificate.",
                Placeholder: "collector.example.org", MaximumLength: 253),
            HostPattern(),
            "Use letters, digits, dots, hyphens and colons only.")
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the application and environment above. It turns green when the collector reports events from it.";

    public override string Guide => "docs/deployment/syslog-source.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        if (!IPAddress.TryParse(values["address"], out IPAddress? address) || values["address"].Contains('%', StringComparison.Ordinal))
        {
            checks.Add(Fail("address", "Listen address must be an IP address such as 0.0.0.0 or 127.0.0.1.", "Enter an IP address, not a host name."));
            return;
        }

        if (values["protocol"] != "tls" && !IPAddress.IsLoopback(address))
        {
            checks.Add(Fail(
                "protocol",
                "Plain TCP and UDP are unencrypted, so Bower offers them only on this host.",
                "Choose TLS, or listen on 127.0.0.1. The documented override for isolated networks is a manual change."));
        }

        if (Optional(values, "appName") is null && Optional(values, "hostname") is null)
        {
            checks.Add(Warn(
                "route",
                "Every message from an allowed sender will reach the parser.",
                "Enter a program name or host name so only the messages you expect are parsed."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        string protocol = values["protocol"];
        JsonObject route = [];
        if (Optional(values, "hostname") is { } hostname)
        {
            route["hostname"] = hostname;
        }

        if (Optional(values, "appName") is { } appName)
        {
            route["appName"] = appName;
        }

        route["pack"] = values["pack"];
        route["parser"] = int.Parse(values["parser"], System.Globalization.CultureInfo.InvariantCulture);
        JsonObject listener = new()
        {
            ["id"] = values["listenerId"],
            ["protocol"] = protocol,
            ["address"] = IPAddress.Parse(values["address"]).ToString(),
            ["port"] = int.Parse(values["port"], System.Globalization.CultureInfo.InvariantCulture),
            ["allowedSenders"] = new JsonArray([.. List(values, "allowedSenders").Select(item => (JsonNode)item)])
        };
        if (protocol == "tls")
        {
            int handshakeStartTimeout = int.Parse(values["handshakeStartTimeoutSeconds"], System.Globalization.CultureInfo.InvariantCulture);
            // The default is implicit so plans continue to load on older collectors that
            // reject unknown settings. A custom value requires the updated collector.
            if (handshakeStartTimeout != 60) listener["handshakeStartTimeoutSeconds"] = handshakeStartTimeout;
            JsonObject tls = new()
            {
                ["certificateFile"] = values["certificateFile"],
                ["privateKeyFile"] = values["privateKeyFile"]
            };
            if (Optional(values, "clientCertificateAuthorityFile") is { } authority)
            {
                tls["clientCertificateAuthorityFile"] = authority;
            }

            listener["tls"] = tls;
        }

        listener["routes"] = new JsonArray(route);
        SourceSetupFile syslog = new(
            "syslog.json",
            "/etc/bower/syslog.json",
            "The syslog listener. If the collector already has a BOWER_SYSLOG_CONFIG file, add this listener to its listeners list instead.",
            Json(new JsonObject
            {
                ["apiVersion"] = "bower.security/v1",
                ["kind"] = "SyslogSource",
                ["listeners"] = new JsonArray(listener)
            }));

        return new SourceSetupBuild(
            [syslog, Expectations(values["application"], values["environment"], values["maximumSilenceMinutes"])],
            [new("collector", "BOWER_SYSLOG_CONFIG", "/etc/bower/syslog.json"), ExpectationsVariable()],
            [Rsyslog(values)],
            ApplicationVerification(values["application"], values["environment"]));
    }

    private static SourceSetupSnippet Rsyslog(IReadOnlyDictionary<string, string> values)
    {
        string protocol = values["protocol"];
        string target = values["collectorHost"];
        string port = values["port"];
        StringBuilder text = new();
        text.Append("# /etc/rsyslog.d/60-bower-").Append(values["listenerId"]).Append(".conf: forward selected messages to the Bower collector.\n");
        if (protocol == "tls")
        {
            text.Append("# The CA that issued the collector's server certificate:\n");
            text.Append("global(DefaultNetstreamDriverCAFile=\"/etc/rsyslog.d/bower-collector-ca.pem\")\n");
            if (Optional(values, "clientCertificateAuthorityFile") is not null)
            {
                text.Append("# Mutual TLS: this sender's certificate (issued by the sender CA) and key:\n");
                text.Append("global(DefaultNetstreamDriverCertFile=\"/etc/rsyslog.d/bower-sender.pem\"\n");
                text.Append("       DefaultNetstreamDriverKeyFile=\"/etc/rsyslog.d/bower-sender-key.pem\")\n");
            }
        }

        List<string> conditions = [];
        if (Optional(values, "appName") is { } appName)
        {
            conditions.Add($"$programname == '{appName}'");
        }

        if (Optional(values, "hostname") is { } hostname)
        {
            conditions.Add($"$hostname == '{hostname}'");
        }

        string indent = conditions.Count > 0 ? "  " : string.Empty;
        if (protocol == "tls")
        {
            text.Append("# A .NET collector sends TLS 1.3 session tickets that rsyslog never reads, which hides a\n");
            text.Append("# closed connection from rsyslog. TLS 1.2 is pinned below; remove that line only when the\n");
            text.Append("# collector runs with OPENSSL_CONF NumTickets = 0 (docs/production-readiness/01).\n");
        }

        if (conditions.Count > 0)
        {
            text.Append("if ").Append(string.Join(" and ", conditions)).Append(" then {\n");
        }

        text.Append(indent).Append("action(type=\"omfwd\" target=\"").Append(target).Append("\" port=\"").Append(port).Append('"');
        if (protocol == "udp")
        {
            text.Append(" protocol=\"udp\"\n");
        }
        else
        {
            text.Append(" protocol=\"tcp\" TCP_Framing=\"octet-counted\"\n");
            if (protocol == "tls")
            {
                text.Append(indent).Append("       StreamDriver=\"gtls\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"x509/name\"\n");
                text.Append(indent).Append("       StreamDriverPermittedPeers=\"").Append(target).Append("\"\n");
                text.Append(indent).Append("       gnutlsPriorityString=\"NORMAL:-VERS-TLS1.3:-VERS-TLS1.1:-VERS-TLS1.0\"\n");
            }

            // One persistent connection; keepalive finds a dead one before the next write.
            text.Append(indent).Append("       RebindInterval=\"0\" ResendLastMSGOnReconnect=\"on\"\n");
            text.Append(indent).Append("       KeepAlive=\"on\" KeepAlive.Time=\"60\" KeepAlive.Interval=\"10\" KeepAlive.Probes=\"6\"\n");
            text.Append(indent).Append("       queue.type=\"LinkedList\" queue.filename=\"bower_forward_").Append(values["listenerId"]).Append("\" queue.saveOnShutdown=\"on\"\n");
            text.Append(indent).Append("       queue.maxDiskSpace=\"2g\" action.resumeRetryCount=\"-1\" action.resumeInterval=\"5\" action.reportSuspension=\"on\"\n");
        }

        text.Append(indent).Append("       template=\"RSYSLOG_SyslogProtocol23Format\")\n");
        if (conditions.Count > 0)
        {
            text.Append("}\n");
        }

        return new SourceSetupSnippet(
            "Sender: rsyslog",
            protocol == "udp"
                ? "Add this to the sender, then restart rsyslog. UDP is best effort: messages can be lost."
                : "Add this to the sender, then restart rsyslog. The disk-assisted queue keeps messages while the collector is unreachable.",
            "rsyslog",
            text.ToString());
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "authentication_failure",
        ["eventAction"] = "authentication.attempt",
        ["eventResult"] = "failure",
        ["application"] = new JsonObject { ["name"] = values["application"], ["environment"] = values["environment"] },
        ["actor"] = new JsonObject { ["username"] = "alex.citizen@example.com" },
        ["source"] = new JsonObject { ["ipAddress"] = "203.0.113.24" },
        ["attributes"] = new JsonObject
        {
            ["syslog.listener"] = values["listenerId"],
            ["syslog.appName"] = Optional(values, "appName") ?? "sshd",
            ["message"] = "Failed password for alex.citizen@example.com from 203.0.113.24 port 52144 ssh2"
        }
    };

    [GeneratedRegex("^[a-z0-9-]{1,63}$")]
    private static partial Regex ListenerPattern();

    [GeneratedRegex("^[A-Za-z0-9._/-]{1,48}$")]
    private static partial Regex AppNamePattern();

    [GeneratedRegex("^[A-Za-z0-9._:-]{1,255}$")]
    internal static partial Regex HostPattern();

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,63}$")]
    private static partial Regex PackPattern();
}

/// <summary>Docker sidecar for opted-in containers (docs/deployment/docker-sidecar.md).</summary>
internal sealed partial class DockerSourceSetup : SourceSetupType
{
    public override string Id => "docker";

    public override string Title => "Docker containers";

    public override string Summary =>
        "A sidecar container reads the logs of containers you label and forwards only security events to the collector.";

    public override string Why =>
        "Older applications in containers often log sign-in failures but cannot send events. The sidecar picks those lines out without shipping whole logs.";

    public override IReadOnlyList<string> Needs =>
    [
        "A Docker or Compose host whose containers use the json-file log driver.",
        "The collector ingest token in a file on that host, readable by the sidecar (uid 1654).",
        "The collector's producer scopes allowing the sidecar's events, or a collector that is one trust domain (docs/security/producer-scopes.md).",
        "Permission to add a label to the container and start one more container."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "service", "Container to read", SourceFieldKinds.Text, true,
                "The Compose service (or container) name whose logs Bower should read.", Placeholder: "ssh-gateway", MaximumLength: 63),
            ServicePattern(),
            "Use lowercase letters, digits, dots, hyphens and underscores."),
        Application("ssh-gateway", "The name events carry. The label below sets it; it defaults to the container name."),
        SourceSetupRegistry.Environment(),
        CollectorUrl("http://bower-collector:4319"),
        IngestTokenFile(),
        new(
            new SourceFieldDefinition(
                "image", "Sidecar image", SourceFieldKinds.Text, true,
                "Pin a version or digest in production.", "ghcr.io/jusso-dev/bower-sidecar:edge", MaximumLength: 256),
            ImagePattern(),
            "Use an image reference such as ghcr.io/jusso-dev/bower-sidecar:1.2.0."),
        AgentId("A name for this sidecar on forwarded events. Defaults to docker-sidecar."),
        new(new SourceFieldDefinition(
            "readExisting", "Read existing log history", SourceFieldKinds.Boolean, true,
            "Yes replays the container's existing logs the first time. No reads new lines only.", "false", MaximumLength: 5)),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the application and environment above. It turns green when the collector reports events from the container.";

    public override string Guide => "docs/deployment/docker-sidecar.md";

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        string sidecarId = Optional(values, "agentId") ?? "docker-sidecar";
        StringBuilder compose = new();
        compose.Append("# Bower sidecar, generated by guided source setup. Use instead of deploy/docker/compose.sidecar.yaml:\n");
        compose.Append("#   docker compose -f compose.yaml -f compose.bower-sidecar.yaml up -d\n");
        compose.Append("services:\n");
        compose.Append("  bower-sidecar:\n");
        compose.Append("    image: \"").Append(values["image"]).Append("\"\n");
        compose.Append("    restart: unless-stopped\n");
        compose.Append("    read_only: true\n");
        compose.Append("    environment:\n");
        compose.Append("      BOWER_COLLECTOR_URL: \"").Append(values["collectorUrl"]).Append("\"\n");
        compose.Append("      BOWER_INGEST_TOKEN_FILE: /run/secrets/bower-ingest-token\n");
        compose.Append("      BOWER_SIDECAR_ID: \"").Append(sidecarId).Append("\"\n");
        compose.Append("      BOWER_ENVIRONMENT: \"").Append(values["environment"]).Append("\"\n");
        compose.Append("      BOWER_DOCKER_READ_EXISTING: \"").Append(values["readExisting"]).Append("\"\n");
        compose.Append("    volumes:\n");
        compose.Append("      - /var/lib/docker/containers:/var/lib/docker/containers:ro\n");
        compose.Append("      - bower-sidecar-state:/var/lib/bower-sidecar\n");
        compose.Append("      - ").Append(Quoted(values["ingestTokenFile"] + ":/run/secrets/bower-ingest-token:ro")).Append('\n');
        compose.Append("    tmpfs:\n");
        compose.Append("      - /tmp:size=8m,mode=1777\n");
        compose.Append("    cap_drop:\n");
        compose.Append("      - ALL\n");
        compose.Append("    cap_add:\n");
        compose.Append("      - DAC_READ_SEARCH\n");
        compose.Append("    logging:\n");
        compose.Append("      driver: json-file\n");
        compose.Append("      options:\n");
        compose.Append("        max-size: 10m\n");
        compose.Append("        max-file: \"3\"\n");
        compose.Append('\n');
        compose.Append("volumes:\n");
        compose.Append("  bower-sidecar-state:\n");

        string labels =
            "# Add to the service in your compose.yaml, then recreate it:\n"
            + "services:\n"
            + $"  {values["service"]}:\n"
            + "    labels:\n"
            + "      bower.collect: \"true\"\n"
            + $"      bower.application: \"{values["application"]}\"\n"
            + $"      bower.environment: \"{values["environment"]}\"\n";

        return new SourceSetupBuild(
            [
                new SourceSetupFile(
                    "compose.bower-sidecar.yaml",
                    "next to your compose.yaml",
                    "The sidecar service with the token mounted from a file. It keeps the hardening of the shipped Compose file.",
                    compose.ToString()),
                Expectations(values["application"], values["environment"], values["maximumSilenceMinutes"])
            ],
            [ExpectationsVariable()],
            [new SourceSetupSnippet("Container labels", "Opt the container in. Unlabelled containers are never read.", "yaml", labels)],
            ApplicationVerification(values["application"], values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "authentication_failure",
        ["eventAction"] = "authentication.attempt",
        ["eventResult"] = "failure",
        ["application"] = new JsonObject { ["name"] = values["application"], ["environment"] = values["environment"] },
        ["actor"] = new JsonObject { ["username"] = "sam.example@example.org" },
        ["source"] = new JsonObject { ["ipAddress"] = "198.51.100.7" },
        ["attributes"] = new JsonObject
        {
            ["docker.container"] = values["service"],
            ["docker.image"] = "example/legacy-app:1.0",
            ["support.phone"] = "0412 345 678"
        }
    };

    [GeneratedRegex("^[a-z0-9][a-z0-9_.-]{0,62}$")]
    private static partial Regex ServicePattern();

    [GeneratedRegex("^[a-z0-9][a-z0-9./:@_-]{0,255}$")]
    private static partial Regex ImagePattern();
}

/// <summary>AWS security signal through SQS and the cloud forwarder (docs/deployment/aws.md).</summary>
internal sealed partial class AwsSourceSetup : SourceSetupType
{
    public override string Id => "aws";

    public override string Title => "Amazon Web Services";

    public override string Summary =>
        "CloudTrail, GuardDuty and Security Hub findings arrive in an SQS queue; the cloud forwarder reads it and sends events to the collector.";

    public override string Why =>
        "Changes to cloud accounts and threat findings are high-value security signal. Bower keeps the security-relevant ones and drops raw records.";

    public override IReadOnlyList<string> Needs =>
    [
        "The bower-aws-security CloudFormation stack deployed (its QueueUrl output).",
        "A host or task with an IAM role that may read that queue (no long-lived access keys).",
        "The collector ingest token in a file on that host.",
        "The aws-security signed pack on the collector, and producer scopes allowing the forwarder's events."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "queueUrl", "SQS queue URL", SourceFieldKinds.Text, true,
                "The QueueUrl output of the bower-aws-security stack.",
                Placeholder: "https://sqs.ap-southeast-2.amazonaws.com/123456789012/bower-security", MaximumLength: 200),
            QueuePattern(),
            "Copy the QueueUrl stack output, for example https://sqs.ap-southeast-2.amazonaws.com/123456789012/bower-security."),
        new(
            new SourceFieldDefinition(
                "s3Buckets", "S3 buckets to read (optional)", SourceFieldKinds.NameList, false,
                "Buckets whose object notifications may be read, separated by commas. Others are ignored.",
                MaximumLength: 2048),
            BucketPattern(),
            "Use bucket names: lowercase letters, digits, dots and hyphens."),
        new(new SourceFieldDefinition(
            "requireAuRegion", "Keep data in Australia", SourceFieldKinds.Boolean, true,
            "Yes refuses a queue outside ap-southeast-2 (Sydney) or ap-southeast-4 (Melbourne).", "true", MaximumLength: 5)),
        SourceSetupRegistry.Environment(),
        CollectorUrl(string.Empty),
        IngestTokenFile(),
        AgentId("A name for this forwarder on its events. Defaults to the host name."),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for aws-security in the environment above. It turns green when the collector reports AWS events.";

    public override string Guide => "docs/deployment/aws.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        string region = QueuePattern().Match(values["queueUrl"]).Groups["region"].Value;
        if (values["requireAuRegion"] == "true" && region is not ("ap-southeast-2" or "ap-southeast-4"))
        {
            checks.Add(Fail(
                "queueUrl",
                $"The queue is in {region}, outside Australia.",
                "Deploy the stack in ap-southeast-2 or ap-southeast-4, or choose not to keep data in Australia."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        string region = QueuePattern().Match(values["queueUrl"]).Groups["region"].Value;
        List<SourceSetupVariable> variables =
        [
            new("cloud-forwarder", "BOWER_AWS_SQS_QUEUE_URL", values["queueUrl"]),
            new("cloud-forwarder", "BOWER_REQUIRE_AU_REGION", values["requireAuRegion"]),
            new("cloud-forwarder", "BOWER_COLLECTOR_URL", values["collectorUrl"]),
            new("cloud-forwarder", "BOWER_INGEST_TOKEN_FILE", values["ingestTokenFile"]),
            new("cloud-forwarder", "BOWER_ENVIRONMENT", values["environment"])
        ];
        if (Optional(values, "s3Buckets") is { } buckets)
        {
            variables.Add(new("cloud-forwarder", "BOWER_AWS_S3_BUCKETS", buckets));
        }

        if (Optional(values, "agentId") is { } agent)
        {
            variables.Add(new("cloud-forwarder", "BOWER_AGENT_ID", agent));
        }

        variables.Add(ExpectationsVariable());
        string deploy =
            $"aws cloudformation deploy --region {region} \\\n"
            + "  --template-file deploy/aws/bower-aws-security.yaml \\\n"
            + "  --stack-name bower-aws-security \\\n"
            + "  --capabilities CAPABILITY_IAM --no-execute-changeset\n"
            + $"aws cloudformation describe-stacks --region {region} --stack-name bower-aws-security \\\n"
            + "  --query \"Stacks[0].Outputs[?OutputKey=='QueueUrl'].OutputValue\" --output text\n";
        return new SourceSetupBuild(
            [Expectations("aws-security", values["environment"], values["maximumSilenceMinutes"])],
            variables,
            [new SourceSetupSnippet(
                "AWS: deploy the signal stack",
                "Run from a Bower checkout with credentials for the account. This creates a change set without executing it. Review it before deploying; then read the deployed queue URL.",
                "shell",
                deploy)],
            ApplicationVerification("aws-security", values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "authentication_failure",
        ["eventAction"] = "ConsoleLogin",
        ["eventResult"] = "failure",
        ["application"] = new JsonObject { ["name"] = "aws-security", ["environment"] = values["environment"], ["tenantId"] = "123456789012" },
        ["actor"] = new JsonObject { ["username"] = "jordan.example@example.com" },
        ["source"] = new JsonObject { ["ipAddress"] = "192.0.2.44" },
        ["attributes"] = new JsonObject
        {
            ["aws.region"] = QueuePattern().Match(values["queueUrl"]).Groups["region"].Value,
            ["aws.errorMessage"] = "Failed authentication for jordan.example@example.com"
        }
    };

    [GeneratedRegex("^https://sqs\\.(?<region>[a-z]{2}(-[a-z]+)+-[0-9])\\.amazonaws\\.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}(\\.fifo)?$")]
    private static partial Regex QueuePattern();

    [GeneratedRegex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    private static partial Regex BucketPattern();
}

/// <summary>Google Cloud audit logs and findings through Pub/Sub (docs/deployment/gcp.md).</summary>
internal sealed partial class GcpSourceSetup : SourceSetupType
{
    private static readonly SourceFieldOption[] Endpoints =
    [
        new("https://australia-southeast1-pubsub.googleapis.com/", "Sydney (australia-southeast1)"),
        new("https://australia-southeast2-pubsub.googleapis.com/", "Melbourne (australia-southeast2)"),
        new("https://pubsub.googleapis.com/", "Global endpoint")
    ];

    public override string Id => "gcp";

    public override string Title => "Google Cloud";

    public override string Summary =>
        "Cloud Audit Logs and Security Command Center findings arrive in a Pub/Sub subscription; the cloud forwarder reads it and sends events to the collector.";

    public override string Why =>
        "IAM changes, denied requests and threat findings in Google Cloud belong in Sentinel next to the rest of your security signal.";

    public override IReadOnlyList<string> Needs =>
    [
        "The Bower Terraform module in deploy/gcp applied (its subscription output).",
        "Workload Identity Federation or an attached service account for the forwarder (no key files).",
        "The collector ingest token in a file on the forwarder's host.",
        "The gcp-security signed pack on the collector, and producer scopes allowing the forwarder's events."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "subscription", "Pub/Sub subscription", SourceFieldKinds.Text, true,
                "The subscription output of the Terraform module.",
                Placeholder: "projects/acme-security/subscriptions/bower-security", MaximumLength: 300),
            SubscriptionPattern(),
            "Copy the subscription output, for example projects/acme-security/subscriptions/bower-security."),
        new(new SourceFieldDefinition(
            "endpoint", "Pub/Sub endpoint", SourceFieldKinds.Choice, true,
            "A regional endpoint keeps the request in that region.", Endpoints[0].Value, Options: Endpoints, MaximumLength: 64)),
        new(new SourceFieldDefinition(
            "credentialsFile", "Workload Identity Federation file (optional)", SourceFieldKinds.FilePath, false,
            "The external_account file from the module output. It holds no secret. Leave empty with an attached service account.",
            Placeholder: "/etc/bower/gcp-wif.json", MaximumLength: 260)),
        SourceSetupRegistry.Environment(),
        CollectorUrl(string.Empty),
        IngestTokenFile(),
        AgentId("A name for this forwarder on its events. Defaults to the host name."),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for gcp-security in the environment above. It turns green when the collector reports Google Cloud events.";

    public override string Guide => "docs/deployment/gcp.md";

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        List<SourceSetupVariable> variables =
        [
            new("cloud-forwarder", "BOWER_GCP_SUBSCRIPTION", values["subscription"]),
            new("cloud-forwarder", "BOWER_GCP_PUBSUB_ENDPOINT", values["endpoint"]),
            new("cloud-forwarder", "BOWER_COLLECTOR_URL", values["collectorUrl"]),
            new("cloud-forwarder", "BOWER_INGEST_TOKEN_FILE", values["ingestTokenFile"]),
            new("cloud-forwarder", "BOWER_ENVIRONMENT", values["environment"])
        ];
        if (Optional(values, "credentialsFile") is { } credentials)
        {
            variables.Add(new("cloud-forwarder", "GOOGLE_APPLICATION_CREDENTIALS", credentials));
        }

        if (Optional(values, "agentId") is { } agent)
        {
            variables.Add(new("cloud-forwarder", "BOWER_AGENT_ID", agent));
        }

        variables.Add(ExpectationsVariable());
        const string terraform =
            "cd deploy/gcp\n"
            + "cp terraform.tfvars.example terraform.tfvars   # set project, organisation and the agent identity\n"
            + "terraform init\n"
            + "terraform plan -out bower.plan\n"
            + "terraform output subscription\n";
        return new SourceSetupBuild(
            [Expectations("gcp-security", values["environment"], values["maximumSilenceMinutes"])],
            variables,
            [new SourceSetupSnippet(
                "Google Cloud: create the log sink and subscription",
                "Run from a Bower checkout. This creates a plan only; review and apply it separately before reading the subscription output.",
                "shell",
                terraform)],
            ApplicationVerification("gcp-security", values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "authorization_denied",
        ["eventAction"] = "storage.buckets.getIamPolicy",
        ["eventResult"] = "failure",
        ["application"] = new JsonObject
        {
            ["name"] = "gcp-security",
            ["environment"] = values["environment"],
            ["tenantId"] = SubscriptionPattern().Match(values["subscription"]).Groups["project"].Value
        },
        ["actor"] = new JsonObject { ["username"] = "riley.example@example.com" },
        ["source"] = new JsonObject { ["ipAddress"] = "198.51.100.23" },
        ["attributes"] = new JsonObject { ["gcp.status"] = "PERMISSION_DENIED" }
    };

    [GeneratedRegex("^projects/(?<project>[a-z][a-z0-9-]{4,28}[a-z0-9])/subscriptions/[A-Za-z][A-Za-z0-9._~-]{2,254}$")]
    private static partial Regex SubscriptionPattern();
}

/// <summary>AMA companion: the collector writes ready files the Azure Monitor Agent collects (docs/deployment/ama-companion.md).</summary>
internal sealed partial class AmaSourceSetup : SourceSetupType
{
    public override string Id => "ama";

    public override string Title => "Azure Monitor Agent";

    public override string Summary =>
        "Switches this collector's delivery to local files that the Azure Monitor Agent already on the host collects into your workspace.";

    public override string Why =>
        "Some estates allow only the Azure Monitor Agent to send to Log Analytics. Bower still redacts and selects; AMA carries the result.";

    public override IReadOnlyList<string> Needs =>
    [
        "The Azure Monitor Agent installed on the collector host and associated with a data collection rule.",
        "A custom table in the workspace for Bower's records.",
        "A local directory with restrictive permissions and a disk quota for the spool.",
        "Someone who can edit the data collection rule in Azure."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(new SourceFieldDefinition(
            "spoolPath", "Spool directory", SourceFieldKinds.FilePath, true,
            "Where the collector writes ready files for AMA. Keep it on local disk with restrictive permissions.",
            "/var/lib/bower/ama-spool", MaximumLength: 260)),
        new(
            new SourceFieldDefinition(
                "table", "Custom table", SourceFieldKinds.Text, true,
                "The workspace table AMA writes to. Custom table names end in _CL.", "BowerSecurity_CL", MaximumLength: 45),
            TablePattern(),
            "Use letters, digits and underscores, ending in _CL.")
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the ama-spool output. It turns green when the collector reports it healthy. AMA's own collection is checked in Azure Monitor, not here.";

    public override string Guide => "docs/deployment/ama-companion.md";

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        string spool = values["spoolPath"].TrimEnd('/', '\\');
        string separator = spool.Contains('\\', StringComparison.Ordinal) ? "\\" : "/";
        string dataSource = Json(new JsonObject
        {
            ["logFiles"] = new JsonArray(new JsonObject
            {
                ["name"] = "bowerAmaSpool",
                ["streams"] = new JsonArray("Custom-" + values["table"]),
                ["filePatterns"] = new JsonArray($"{spool}{separator}ready{separator}*.jsonl"),
                ["format"] = "json"
            })
        });
        return new SourceSetupBuild(
            [],
            [
                new("collector", "BOWER_OUTPUT", "ama-spool"),
                new("collector", "BOWER_AMA_SPOOL_PATH", values["spoolPath"])
            ],
            [new SourceSetupSnippet(
                "Azure: data collection rule data source",
                "Merge into the dataSources of the rule associated with the collector host. Collect ready files only, never active ones.",
                "json",
                dataSource)],
            new SourceSetupVerification(
                "output",
                "ama-spool",
                "The collector's heartbeat reports the ama-spool output as healthy."));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "privilege_change",
        ["eventAction"] = "group.member.add",
        ["eventResult"] = "success",
        ["application"] = new JsonObject { ["name"] = "finance-portal", ["environment"] = "production" },
        ["actor"] = new JsonObject { ["username"] = "casey.example@example.com" },
        ["target"] = new JsonObject { ["type"] = "group", ["name"] = "Payments approvers" },
        ["attributes"] = new JsonObject { ["ama.table"] = values["table"] }
    };

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_]{0,41}_CL$")]
    private static partial Regex TablePattern();
}

/// <summary>Application events through Bower.Sdk to the collector's HTTP intake (docs/developer-integration/aspnetcore.md).</summary>
internal sealed partial class SdkSourceSetup : SourceSetupType
{
    public override string Id => "http-sdk";

    public override string Title => "Application (HTTP or SDK)";

    public override string Summary =>
        "Your application sends semantic security events (sign-ins, permission changes) to the collector with the Bower SDK or plain HTTP.";

    public override string Why =>
        "The application knows when a sign-in failed or a permission changed. Sending that decision is cleaner and cheaper than parsing logs later.";

    public override IReadOnlyList<string> Needs =>
    [
        "A developer who can add the Bower.Sdk package (or an HTTP call) to the application.",
        "The collector address the application can reach, and the ingest token in a secret store.",
        "The application's host name (the SDK sends it as the instance).",
        "Access to the collector's producer scopes file."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "application", "Application name", SourceFieldKinds.Text, true,
                "The name events carry, for example customer-portal.", Placeholder: "customer-portal", MaximumLength: 128),
            IdentifierPattern(),
            "Use letters, digits, dots, hyphens and underscores only."),
        SourceSetupRegistry.Environment(),
        new(
            new SourceFieldDefinition(
                "instance", "Application host name", SourceFieldKinds.Text, true,
                "The machine the application runs on. The producer scope only allows events from this instance.",
                Placeholder: "portal-01", MaximumLength: 128),
            IdentifierPattern(),
            "Use letters, digits, dots, hyphens and underscores only."),
        new(
            new SourceFieldDefinition(
                "tenantId", "Tenant (optional)", SourceFieldKinds.Text, false,
                "Set only when the application serves several tenants and sends a tenant id.", MaximumLength: 128),
            IdentifierPattern(),
            "Use letters, digits, dots, hyphens and underscores only."),
        new(
            new SourceFieldDefinition(
                "producer", "Producer id", SourceFieldKinds.Text, true,
                "The token id in the collector's BOWER_INGEST_TOKENS_FILE; default for a shared token.", "default", MaximumLength: 64),
            IdentifierPattern(),
            "Use letters, digits, dots, hyphens and underscores only."),
        new(new SourceFieldDefinition(
            "endpoint", "Collector address", SourceFieldKinds.Url, true,
            "Use HTTPS unless the collector runs on the same host (loopback).", "http://127.0.0.1:4319",
            MaximumLength: 512)),
        new(new SourceFieldDefinition(
            "ingestToken", "Ingest token location (optional on loopback)", SourceFieldKinds.SecretReference, false,
            "A file path or Key Vault secret URL where the application reads the ingest token. Never paste the token.",
            Placeholder: "https://acme-vault.vault.azure.net/secrets/bower-ingest-token", MaximumLength: 260, KeyVaultAllowed: true)),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the application and environment above. It turns green when the collector reports events from the application.";

    public override string Guide => "docs/developer-integration/aspnetcore.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        Uri endpoint = new(values["endpoint"]);
        if (!endpoint.IsLoopback && Optional(values, "ingestToken") is null)
        {
            checks.Add(Fail(
                "ingestToken",
                "A collector on another host needs an ingest token.",
                "Enter the file path or Key Vault secret URL where the application reads the token."));
        }

        if (!endpoint.IsLoopback && endpoint.Scheme != Uri.UriSchemeHttps)
        {
            checks.Add(Fail(
                "endpoint",
                "The SDK sends the ingest token only over HTTPS or to this host.",
                "Use an https:// address for a collector on another host."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        JsonObject application = new()
        {
            ["name"] = values["application"],
            ["environment"] = values["environment"],
            ["instance"] = values["instance"]
        };
        if (Optional(values, "tenantId") is { } tenant)
        {
            application["tenantId"] = tenant;
        }

        SourceSetupFile scopes = new(
            "producer-scopes.json",
            "/etc/bower/producer-scopes.json",
            "Lets this producer send events for this application only. If the collector already has a BOWER_PRODUCER_SCOPES_FILE, add this entry to it instead. Events that name a source (such as a client IP) need matching source entries; see docs/security/producer-scopes.md.",
            Json(new JsonArray(new JsonObject
            {
                ["producer"] = values["producer"],
                ["application"] = application
            })));

        StringBuilder code = new();
        code.Append("// Program.cs: send security events to the Bower collector.\n");
        code.Append("builder.Services.AddBower(options =>\n{\n");
        code.Append("    options.Application.Name = \"").Append(values["application"]).Append("\";\n");
        code.Append("    options.Application.Environment = \"").Append(values["environment"]).Append("\";\n");
        code.Append("    options.Application.Instance = \"").Append(values["instance"]).Append("\";\n");
        if (Optional(values, "tenantId") is { } tenantId)
        {
            code.Append("    options.Application.TenantId = \"").Append(tenantId).Append("\";\n");
        }

        code.Append("    options.LocalCollector.Endpoint = \"").Append(values["endpoint"]).Append("\";\n");
        if (Optional(values, "ingestToken") is { } token)
        {
            if (KeyVaultSecretUrl().IsMatch(token))
            {
                code.Append("    // App setting Bower__IngestToken = @Microsoft.KeyVault(SecretUri=").Append(token).Append(")\n");
                code.Append("    options.LocalCollector.IngestToken = builder.Configuration[\"Bower:IngestToken\"];\n");
            }
            else
            {
                code.Append("    options.LocalCollector.IngestToken = File.ReadAllText(").Append(Quoted(token)).Append(").Trim();\n");
            }
        }

        code.Append("});\n");
        return new SourceSetupBuild(
            [scopes, Expectations(values["application"], values["environment"], values["maximumSilenceMinutes"])],
            [new("collector", "BOWER_PRODUCER_SCOPES_FILE", "/etc/bower/producer-scopes.json"), ExpectationsVariable()],
            [new SourceSetupSnippet(
                "Application: ASP.NET Core",
                "Add the Bower.Sdk package, then this registration. Emit events after the decision is known, never request bodies or passwords.",
                "csharp",
                code.ToString())],
            ApplicationVerification(values["application"], values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "authentication_failure",
        ["eventAction"] = "user.sign_in",
        ["eventResult"] = "failure",
        ["application"] = new JsonObject
        {
            ["name"] = values["application"],
            ["environment"] = values["environment"],
            ["instance"] = values["instance"]
        },
        ["actor"] = new JsonObject { ["username"] = "morgan.example@example.com" },
        ["source"] = new JsonObject { ["ipAddress"] = "203.0.113.90" },
        ["attributes"] = new JsonObject
        {
            ["failureReason"] = "invalid-password",
            ["password"] = "not-a-real-password"
        }
    };
}

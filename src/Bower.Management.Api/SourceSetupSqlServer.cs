using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Bower.Management.Api.SourceSetupRegistry;

namespace Bower.Management.Api;

/// <summary>
/// Read-only SQL Server security audit table polling (src/Bower.Source.SqlServer,
/// docs/operations/queue-v5-durability.md). Enforces read-only ApplicationIntent,
/// safe SQL identifiers, bounded batch allocation and a secret reference (never an
/// inline password).
/// </summary>
internal sealed partial class SqlServerSourceSetup : SourceSetupType
{
    private static readonly SourceFieldOption[] CursorKinds =
    [
        new("Incrementing", "Incrementing sequence ID (recommended for identity columns)"),
        new("Timestamp", "Timestamp with bounded overlap sweep (for late-committing rows)"),
        new("Composite", "Composite (EventTime + Sequence)")
    ];

    private static readonly string[] TimestampOnly = ["Timestamp"];

    public override string Id => "sql-server";

    public override string Title => "SQL Server audit table";

    public override string Summary =>
        "Polls a read-only SQL Server audit table with durable keyset cursors and forwards security events to the collector.";

    public override string Why =>
        "Line-of-business databases often record privilege changes, failed sign-ins and sensitive exports in an audit table. Bower reads bounded batches with ApplicationIntent=ReadOnly and never modifies the database.";

    public override IReadOnlyList<string> Needs =>
    [
        "A read-only SQL Server login granted SELECT on the audit table only.",
        "A connection string stored in a protected file or Key Vault secret (with ApplicationIntent=ReadOnly and Encrypt=True).",
        "An approved collector with producer scopes allowing this application's events.",
        "A monotonic sequence column and event timestamp column on the audit table."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "sourceId", "Source identifier", SourceFieldKinds.Text, true,
                "Stable cursor name for this SQL Server table. Keep it unchanged across restarts so the cursor resumes.",
                "sql-audit-primary", MaximumLength: 128),
            IdentifierPattern(),
            "Use letters, digits, dots, hyphens and underscores only."),
        new(
            new SourceFieldDefinition(
                "schema", "SQL schema", SourceFieldKinds.Text, true,
                "Schema owning the audit table (letters, digits and underscores; starts with a letter or underscore).",
                "dbo", MaximumLength: 128),
            SqlIdentifierPattern(),
            "SQL identifiers must start with a letter or underscore and contain only letters, digits or underscores."),
        new(
            new SourceFieldDefinition(
                "table", "Audit table", SourceFieldKinds.Text, true,
                "Read-only audit table name.", Placeholder: "SecurityAuditLog", MaximumLength: 128),
            SqlIdentifierPattern(),
            "SQL identifiers must start with a letter or underscore and contain only letters, digits or underscores."),
        new(new SourceFieldDefinition(
            "cursorKind", "Cursor strategy", SourceFieldKinds.Choice, true,
            "Incrementing is fastest for identity columns; Timestamp adds a bounded overlap sweep for late-committing transactions.",
            "Incrementing", Options: CursorKinds, MaximumLength: 16)),
        new(new SourceFieldDefinition(
            "timestampOverlapSeconds", "Overlap sweep window (seconds)", SourceFieldKinds.Number, true,
            "How far back to sweep for late-committing rows (0 to 86400 seconds).",
            "300", Minimum: 0, Maximum: 86_400, MaximumLength: 5,
            ShownWhenField: "cursorKind", ShownWhenValues: TimestampOnly)),
        new(new SourceFieldDefinition(
            "pollIntervalSeconds", "Poll interval (seconds)", SourceFieldKinds.Number, true,
            "How often to query for new audit rows (5 to 3600 seconds).",
            "30", Minimum: 5, Maximum: 3_600, MaximumLength: 4)),
        new(new SourceFieldDefinition(
            "batchSize", "Batch size", SourceFieldKinds.Number, true,
            "Maximum rows read per poll (1 to 10000; bounded to 64 MiB total with record limit).",
            "500", Minimum: 1, Maximum: 10_000, MaximumLength: 5)),
        new(new SourceFieldDefinition(
            "connectionStringRef", "Connection string secret reference", SourceFieldKinds.SecretReference, true,
            "File path on the collector host or Azure Key Vault secret URL holding the ReadOnly connection string. Never paste passwords here.",
            Placeholder: "/run/secrets/bower-sql-readonly", MaximumLength: 260, KeyVaultAllowed: true)),
        Application("sql-audit", "The application name events carry in Sentinel."),
        SourceSetupRegistry.Environment(),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the application and environment above. It turns green when the collector reports SQL Server audit events.";

    public override string Guide => "docs/operations/queue-v5-durability.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        if (values["cursorKind"] == "Timestamp"
            && Optional(values, "timestampOverlapSeconds") is { } overlapText
            && int.TryParse(overlapText, CultureInfo.InvariantCulture, out int overlap)
            && overlap == 0)
        {
            checks.Add(Warn(
                "timestampOverlapSeconds",
                "Timestamp cursor has zero overlap; rows committed out of timestamp order may be skipped.",
                "Set a bounded overlap window such as 300 seconds when transactions can commit out of order."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        string cursorKind = values["cursorKind"];
        int pollSeconds = int.Parse(values["pollIntervalSeconds"], CultureInfo.InvariantCulture);
        int batchSize = int.Parse(values["batchSize"], CultureInfo.InvariantCulture);
        int overlapSeconds = cursorKind == "Timestamp" && Optional(values, "timestampOverlapSeconds") is { } rawOverlap
            ? int.Parse(rawOverlap, CultureInfo.InvariantCulture)
            : 0;

        JsonObject config = new()
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "SqlServerSource",
            ["sourceId"] = values["sourceId"],
            ["schema"] = values["schema"],
            ["table"] = values["table"],
            ["cursorKind"] = cursorKind,
            ["pollIntervalSeconds"] = pollSeconds,
            ["batchSize"] = batchSize,
            ["timestampOverlapSeconds"] = overlapSeconds,
            ["maximumRecordBytes"] = 65_536,
            ["oversizedRecords"] = "OmitValues",
            ["application"] = values["application"],
            ["environment"] = values["environment"],
            ["connectionStringRef"] = values["connectionStringRef"]
        };

        SourceSetupFile sqlFile = new(
            "sql-server.json",
            "/etc/bower/sql-server.json",
            "Read-only SQL Server audit poller settings. Connection string stays in the referenced secret.",
            Json(config));

        string grantSnippet =
            $"-- Least-privilege read-only access for Bower (run on target SQL Server database):\n" +
            $"CREATE USER [bower_reader] FROM LOGIN [bower_reader];\n" +
            $"GRANT SELECT ON [{values["schema"]}].[{values["table"]}] TO [bower_reader];\n" +
            $"-- Connection string in {values["connectionStringRef"]} must include:\n" +
            $"--   ApplicationIntent=ReadOnly;Encrypt=True;TrustServerCertificate=False\n";

        return new SourceSetupBuild(
            [sqlFile, Expectations(values["application"], values["environment"], values["maximumSilenceMinutes"])],
            [
                new("sql-source", "BOWER_SQLSERVER_CONFIG", "/etc/bower/sql-server.json"),
                new("sql-source", "BOWER_SQLSERVER_CONNECTION_STRING_REF", values["connectionStringRef"]),
                ExpectationsVariable()
            ],
            [new SourceSetupSnippet(
                "SQL Server: least-privilege read-only grant",
                "Grant SELECT on the audit table only. Bower never writes to the source database.",
                "sql",
                grantSnippet)],
            ApplicationVerification(values["application"], values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values) => new()
    {
        ["eventType"] = "role_membership_changed",
        ["eventAction"] = "sql.audit.role_update",
        ["eventResult"] = "success",
        ["application"] = new JsonObject { ["name"] = values["application"], ["environment"] = values["environment"] },
        ["actor"] = new JsonObject { ["username"] = "db.admin@example.org" },
        ["source"] = new JsonObject { ["ipAddress"] = "198.51.100.19" },
        ["attributes"] = new JsonObject
        {
            ["sql.sourceId"] = values["sourceId"],
            ["sql.table"] = $"{values["schema"]}.{values["table"]}",
            ["sql.cursorKind"] = values["cursorKind"],
            ["audit.note"] = "Updated role for user TFN 123 456 782"
        }
    };

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex SqlIdentifierPattern();
}

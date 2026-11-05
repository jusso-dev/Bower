using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Bower.Management.Api.SourceSetupRegistry;

namespace Bower.Management.Api;

/// <summary>A shipped signed pack parser that reads one security record per file line.</summary>
public sealed record FileSourceParser(
    string Pack,
    int ParserIndex,
    string Format,
    string Application,
    string Environment,
    string Label)
{
    /// <summary>The form value: <c>pack:index</c>.</summary>
    public string Value => $"{Pack}:{ParserIndex.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
}

/// <summary>
/// The collector file tail source configuration (<c>BOWER_FILE_CONFIG</c>), in one place. Mirrors
/// <c>FileTailSourceConfigurationLoader</c> in <c>src/Bower.Source.File</c> (and the Rust port),
/// which rejects unknown keys; Management.Api does not reference the source, so the unit tests
/// load every generated file with that loader and its route check (FileSourceSetupTests).
/// Poll interval and batch limits are left at the loader's defaults,
/// and <c>allowSymlink</c> is never generated, so a symbolic link is always refused.
/// </summary>
public static class FileSourceSchema
{
    public const string ApiVersion = "bower.security/v1";
    public const string Kind = "FileTailSource";
    public const string Variable = "BOWER_FILE_CONFIG";
    public const string FileName = "file-source.json";
    public const string LinuxInstallPath = "/etc/bower/" + FileName;

    public const string FormatText = "text";
    public const string FormatJsonLines = "json-lines";
    public const string StartAtEnd = "end";
    public const string StartAtBeginning = "beginning";

    public const int MinimumLineBytes = 256;
    public const int DefaultLineBytes = 16_384;
    // A pack parser reads records of at most 32 KiB, so the loader caps lines below that.
    public const int MaximumLineBytes = 30_720;

    /// <summary>How the collector treats symbolic links. Shown in the form, the plan and the docs.</summary>
    public const string SymlinkPolicy =
        "The collector refuses symbolic links: the file and every directory between the allowed directory and the file must be real. The allowed directory itself may be a link.";

    /// <summary>
    /// The only parsers a file input can route to: shipped signed parsers written for file tail
    /// records (<c>message</c> for text, <c>json</c> for json-lines). Parsers for other sources
    /// read top-level fields and would never select a file line. The collector still refuses a
    /// pack that is not loaded and trusted.
    /// </summary>
    public static IReadOnlyList<FileSourceParser> Parsers { get; } =
    [
        new("linux-authlog-ssh", 0, FormatText, "linux-sshd", "production",
            "linux-authlog-ssh parser 0: SSH sign-in failures from auth.log text lines")
    ];

    /// <summary>The generated document for one input. Written with the JSON writer only.</summary>
    public static JsonObject Document(
        string allowedRoot,
        string id,
        string path,
        FileSourceParser parser,
        string startAt,
        int maxLineBytes) => new()
        {
            ["apiVersion"] = ApiVersion,
            ["kind"] = Kind,
            ["allowedRoots"] = new JsonArray(allowedRoot),
            ["inputs"] = new JsonArray(new JsonObject
            {
                ["id"] = id,
                ["path"] = path,
                ["route"] = new JsonObject { ["pack"] = parser.Pack, ["parser"] = parser.ParserIndex },
                ["format"] = parser.Format,
                ["startAt"] = startAt,
                ["maxLineBytes"] = maxLineBytes
            })
        };
}

/// <summary>
/// Security-selected file tailing: one named file, inside one allowed directory, routed to one
/// shipped signed pack parser. Lines the parser does not select are dropped. No wildcards,
/// directories or catch-all parsers (docs/deployment/file-tail-source.md). Linux paths only:
/// the one offered parser reads Linux auth.log, so a Windows file parser is a follow-up.
/// </summary>
internal sealed partial class FileTailSourceSetup : SourceSetupType
{
    private static readonly SourceFieldOption[] StartOptions =
    [
        new(FileSourceSchema.StartAtEnd, "New lines only (recommended)"),
        new(FileSourceSchema.StartAtBeginning, "Lines already in the file, then new lines")
    ];

    // Kernel and device trees, and Bower's own configuration and secrets, state (queue and
    // enrolment credential), spool and logs (bower.service LogsDirectory=bower). Checked against
    // both the allowed directory and the file, so a parent directory cannot reach into them.
    // /run/credentials is systemd LoadCredential, which holds Bower's privacy HMAC key when the
    // production-readiness 05 setup is used.
    private static readonly string[] RefusedDirectories =
        ["/proc", "/sys", "/dev", "/run/credentials", "/etc/bower", "/var/lib/bower", "/var/spool/bower", "/var/log/bower"];

    // bower.service runs with ProtectHome=true, so these are hidden from the collector.
    private static readonly string[] HiddenDirectories = ["/home", "/root", "/run/user"];

    public const string TypeId = "file";

    public override string Id => TypeId;
    public override string Title => "Security-selected file";
    public override string Summary =>
        "Tail one named file on the collector host. Each line goes to a signed pack parser, and only the security events it selects are kept.";
    public override string Why =>
        "Some systems write security decisions only to a local file. Bower reads the one file you name and drops every line its signed parser does not select. It does not ship whole logs.";
    public override IReadOnlyList<string> Needs =>
    [
        "An approved collector that supports the file source (BOWER_FILE_CONFIG) and loads the signed pack you choose, signed by a key it trusts.",
        "The exact Linux path of one file, and the directory it is allowed to live in. Wildcards, whole directories and catch-all parsers are not offered.",
        "The collector's service account able to read the file. bower.service hides /home and /root.",
        "Symbolic links: " + FileSourceSchema.SymlinkPolicy,
        "An administrator to install the approved files and restart the collector."
    ];
    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(new SourceFieldDefinition("inputId", "Input name", SourceFieldKinds.Text, true,
            "A unique name for this file on the collector. Keep it stable so the read position resumes after a restart.",
            "auth", MaximumLength: 63),
            InputPattern(), "Use lowercase letters, digits and hyphens; start with a letter or digit."),
        new(new SourceFieldDefinition("allowedRoot", "Allowed directory", SourceFieldKinds.FilePath, true,
            "The collector reads only inside this directory. Choose the narrowest directory that holds the file. "
            + FileSourceSchema.SymlinkPolicy,
            "/var/log", MaximumLength: 200)),
        new(new SourceFieldDefinition("path", "File path", SourceFieldKinds.FilePath, true,
            "The exact absolute path of one file inside the allowed directory. Wildcards are not supported.",
            Placeholder: "/var/log/auth.log", MaximumLength: 260)),
        new(new SourceFieldDefinition("parser", "Signed pack parser", SourceFieldKinds.Choice, true,
            "Every line goes to this parser. Lines it does not select are dropped. The collector refuses to start if the pack is not loaded and trusted.",
            FileSourceSchema.Parsers[0].Value,
            Options: [.. FileSourceSchema.Parsers.Select(parser => new SourceFieldOption(parser.Value, parser.Label))],
            MaximumLength: 80)),
        new(new SourceFieldDefinition("startAt", "Where to start", SourceFieldKinds.Choice, true,
            "Where reading starts the first time. A saved read position always resumes.",
            FileSourceSchema.StartAtEnd, Options: StartOptions, MaximumLength: 16)),
        new(new SourceFieldDefinition("maxLineBytes", "Longest line (bytes)", SourceFieldKinds.Number, true,
            $"Longer lines are dropped and counted, never cut and parsed. {FileSourceSchema.MinimumLineBytes} to {FileSourceSchema.MaximumLineBytes} bytes.",
            FileSourceSchema.DefaultLineBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Minimum: FileSourceSchema.MinimumLineBytes, Maximum: FileSourceSchema.MaximumLineBytes, MaximumLength: 5)),
        Silence()
    ];
    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the parser's application and environment. Other files or sources can report the same application, so this check never turns green on its own: "
        + "it reports pack events seen after approval and asks you to confirm this input in the collector's /v1/status. This does not prove Sentinel delivery.";
    public override string Guide => "docs/deployment/file-tail-source.md";

    public static FileSourceParser Parser(IReadOnlyDictionary<string, string> values) =>
        FileSourceSchema.Parsers.Single(parser => parser.Value == values["parser"]);

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        string root = values["allowedRoot"];
        string path = values["path"];
        if (!root.StartsWith('/') || !path.StartsWith('/'))
        {
            checks.Add(Fail(root.StartsWith('/') ? "path" : "allowedRoot", "This source takes Linux paths only for now.",
                "Use a Linux path such as /var/log/auth.log. The only offered parser reads Linux auth.log; a Windows file parser is a follow-up."));
            return;
        }

        string trimmedRoot = root.TrimEnd('/');
        if (!Plain(trimmedRoot) || trimmedRoot.Length == 0)
        {
            checks.Add(Fail("allowedRoot", "Allowed directory must be a specific directory, not the whole disk.",
                "Enter the narrowest directory that holds the file, such as /var/log, without '.' or empty segments."));
            return;
        }

        if (Under(trimmedRoot, RefusedDirectories) is { } refused)
        {
            checks.Add(Fail("allowedRoot", $"Bower does not read files under {refused}.",
                "Choose a directory of security records, not kernel, device or Bower's own files."));
            return;
        }

        if (path.EndsWith('/') || !Plain(path))
        {
            checks.Add(Fail("path", "File path must name one file, without '.' or empty segments.",
                "Enter the full path of the file itself, not its directory."));
            return;
        }

        if (!path.StartsWith(trimmedRoot + '/', StringComparison.Ordinal))
        {
            checks.Add(Fail("path", "File path is outside the allowed directory.",
                "Put the file inside the allowed directory, or choose the directory that holds it."));
            return;
        }

        // A parent allowed directory (such as /var) must not reach a refused one.
        if (Under(path, RefusedDirectories) is { } refusedFile)
        {
            checks.Add(Fail("path", $"Bower does not read files under {refusedFile}.",
                "Choose a file of security records, not kernel, device or Bower's own files."));
            return;
        }

        if ((Under(trimmedRoot, HiddenDirectories) ?? Under(path, HiddenDirectories)) is { } hidden)
        {
            checks.Add(Warn("allowedRoot", $"bower.service hides {hidden} from the collector (ProtectHome).",
                "Write the security records somewhere else, such as /var/log, or change the service hardening deliberately."));
        }
    }

    /// <summary>
    /// Refuses an input name or file that another pending file request on this collector uses.
    /// An approved one can only be replaced, so it warns: the merged file must keep one entry.
    /// Management does not know what is installed, so every approval sharing the name or file
    /// warns; one that a later approval replaced is reported as possibly still installed.
    /// </summary>
    public override void ValidateAgainst(
        IReadOnlyDictionary<string, string> values, IEnumerable<SourceSetupRow> existing, List<SetupCheck> checks)
    {
        SourceSetupRow[] rows = [.. existing];
        foreach (SourceSetupRow row in rows.Where(row => row.Status == SourceSetupRequestStatus.PendingReview))
        {
            if (Clash(values, row) is { } field)
            {
                checks.Add(Fail(field, $"A file request waiting for approval on this collector already {What(field)}.",
                    "Use a different input name and file, or reject the other request first."));
                return;
            }
        }

        foreach ((SourceSetupRow row, bool replaced) in Approvals(rows))
        {
            if (Clash(values, row) is not { } field)
            {
                continue;
            }

            string request = row.Id[..8];
            checks.Add(replaced
                ? Warn(field, $"Approved file request {request} on this collector {What(field)}. A later approval replaced it, but it may still be installed.",
                    "Check the collector's file-source.json; when merging, keep each input name and file once.")
                : Warn(field, $"Approved file request {request} on this collector already {What(field)}.",
                    "This replaces it: when merging, remove the old input so each name and file appears once."));
        }
    }

    public override string? PendingConflict(IReadOnlyDictionary<string, string> values, IReadOnlyList<SourceSetupRow> pending) =>
        pending.Select(row => Clash(values, row)).FirstOrDefault(field => field is not null) is { } clash
            ? $"A file request waiting for approval on this collector already {What(clash)}. Reject one of them first."
            : null;

    private static string? Clash(IReadOnlyDictionary<string, string> values, SourceSetupRow row) =>
        row.Values.GetValueOrDefault("inputId") == values["inputId"] ? "inputId"
        : row.Values.GetValueOrDefault("path") == values["path"] ? "path"
        : null;

    private static string What(string field) => field == "inputId" ? "uses this input name" : "reads this file";

    /// <summary>Approved requests, newest first, each marked when a later approval shares its input name or file.</summary>
    private static IEnumerable<(SourceSetupRow Row, bool Replaced)> Approvals(IEnumerable<SourceSetupRow> rows)
    {
        HashSet<string> claimed = new(StringComparer.Ordinal);
        foreach (SourceSetupRow row in rows
            .Where(row => row.Status == SourceSetupRequestStatus.Approved)
            .OrderByDescending(row => row.ReviewedAt))
        {
            string id = "inputId:" + row.Values.GetValueOrDefault("inputId");
            string path = "path:" + row.Values.GetValueOrDefault("path");
            bool replaced = claimed.Contains(id) || claimed.Contains(path);
            claimed.Add(id);
            claimed.Add(path);
            yield return (row, replaced);
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        FileSourceParser parser = Parser(values);
        string configurationPath = FileSourceSchema.LinuxInstallPath;
        string expectationsPath = ExpectationsVariable().Value;
        SourceSetupFile configuration = new(
            FileSourceSchema.FileName,
            configurationPath,
            "Tails one named file and routes every line to one signed pack parser; unselected lines are dropped. "
            + FileSourceSchema.SymlinkPolicy
            + " If the collector already has a BOWER_FILE_CONFIG file, add this input and allowed directory to its lists instead.",
            Json(FileSourceSchema.Document(
                values["allowedRoot"].TrimEnd('/'),
                values["inputId"],
                values["path"],
                parser,
                values["startAt"],
                int.Parse(values["maxLineBytes"], System.Globalization.CultureInfo.InvariantCulture))));
        return new SourceSetupBuild(
            [configuration, Expectations(parser.Application, parser.Environment, values["maximumSilenceMinutes"])],
            [new("collector", FileSourceSchema.Variable, configurationPath), ExpectationsVariable()],
            [new SourceSetupSnippet("Linux: apply approved settings",
                "After a different approver approves the request, install or merge the files at the paths above. Add these lines to /etc/bower/bower.env (root:bower 0640), then restart the collector.",
                "shell",
                $"{FileSourceSchema.Variable}={configurationPath}\n"
                + $"BOWER_SOURCE_EXPECTATIONS={expectationsPath}\n"
                + "# then: sudo systemctl restart bower\n")],
            PackVerification(parser.Application, parser.Environment, values["inputId"]));
    }

    /// <summary>
    /// Bound to the pack's application, which other files or sources can also report, so the
    /// check never turns green for this input on its own (SourceSetupEndpoints.Check).
    /// </summary>
    private static SourceSetupVerification PackVerification(string application, string environment, string inputId) =>
        new(
            PackSourceVerification,
            $"{application}/{environment}",
            $"The collector's heartbeat reports {application}/{environment}, which any file or source using this pack can produce. "
            + $"Confirm input {inputId} in the collector's /v1/status (fileTail) before relying on it.");

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values)
    {
        FileSourceParser parser = Parser(values);
        return new JsonObject
        {
            ["eventType"] = "authentication_failure",
            ["eventAction"] = "authentication.attempt",
            ["eventResult"] = "failure",
            ["application"] = new JsonObject { ["name"] = parser.Application, ["environment"] = parser.Environment },
            ["actor"] = new JsonObject { ["username"] = "casey.example@example.com" },
            ["source"] = new JsonObject { ["ipAddress"] = "192.0.2.10" }
        };
    }

    /// <summary>Verification kind for a pack application that does not identify one input.</summary>
    public const string PackSourceVerification = "pack-source";

    // No '.', empty (such as '//') or space-padded segments, so a path has one spelling.
    private static bool Plain(string path) =>
        path.Split('/').Skip(1).All(segment => segment.Length > 0 && segment != "." && segment.Trim().Length == segment.Length);

    private static string? Under(string path, IEnumerable<string> directories) =>
        directories.FirstOrDefault(directory => path == directory || path.StartsWith(directory + '/', StringComparison.Ordinal));

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,62}$")]
    private static partial Regex InputPattern();
}

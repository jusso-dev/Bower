using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bower.Core;
using Bower.Integrity;
using Bower.Management.Api;
using Bower.Packs;
using Bower.Pipeline;
using Bower.Source.File;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using static Bower.UnitTests.SourceSetupApiTests;

namespace Bower.UnitTests;

/// <summary>Guided setup for the security-selected file source: paths, parsers, duplicates, golden config, signing and checks.</summary>
[Collection(SerialHostTests.Name)]
public sealed class FileSourceSetupTests
{
    // The shared helpers register collectors at this time, so they are not stale.
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 9, 30, 0, TimeSpan.Zero);

    internal static Dictionary<string, string> Values() => new()
    {
        ["inputId"] = "auth",
        ["allowedRoot"] = "/var/log",
        ["path"] = "/var/log/auth.log",
        ["parser"] = "linux-authlog-ssh:0"
    };

    private const string Golden = """
        {
          "apiVersion": "bower.security/v1",
          "kind": "FileTailSource",
          "allowedRoots": [
            "/var/log"
          ],
          "inputs": [
            {
              "id": "auth",
              "path": "/var/log/auth.log",
              "route": {
                "pack": "linux-authlog-ssh",
                "parser": 0
              },
              "format": "text",
              "startAt": "end",
              "maxLineBytes": 16384
            }
          ]
        }

        """;

    [Fact]
    public async Task Type_OffersOnlyNamedFilesAndShippedSignedParsers()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, cancellationToken);

        SourceTypeDefinition[] types = (await ManagementApiTests.Client(app, BowerRoles.Viewer)
            .GetFromJsonAsync<SourceTypeDefinition[]>("/api/sources/types", ManagementApiTests.ApiJson, cancellationToken))!;

        SourceTypeDefinition file = Assert.Single(types, type => type.Id == "file");
        Assert.Contains("security-selected", file.Title + " " + file.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("log shipping", file.Summary + file.Why, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(file.Needs, need => need.StartsWith("Symbolic links:", StringComparison.Ordinal));
        Assert.Equal("docs/deployment/file-tail-source.md", file.Guide);
        Assert.DoesNotContain(file.Fields, field => field.Kind == SourceFieldKinds.SecretReference);
        SourceFieldDefinition parser = Assert.Single(file.Fields, field => field.Id == "parser");
        Assert.Equal(SourceFieldKinds.Choice, parser.Kind);
        Assert.Equal(FileSourceSchema.Parsers.Select(item => item.Value), parser.Options!.Select(option => option.Value));
        // No collect-all choice: every option names one signed parser or one start position.
        Assert.All(file.Fields.SelectMany(field => field.Options ?? []), option =>
        {
            Assert.DoesNotContain("*", option.Value, StringComparison.Ordinal);
            Assert.DoesNotContain("all", option.Label, StringComparison.OrdinalIgnoreCase);
        });
        Assert.Equal(["inputId", "allowedRoot", "path", "parser", "startAt", "maxLineBytes", "maximumSilenceMinutes"], file.Fields.Select(field => field.Id));
    }

    [Fact]
    public async Task Plan_GeneratesTheGoldenFileSourceConfiguration()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);

        SourceSetupPlanResult result = await PlanAsync(app, "file", "edge-01", Values(), cancellationToken);

        Assert.True(result.Valid, string.Join(" ", result.Checks.Select(check => check.Message)));
        SourceSetupPlan plan = result.Plan!;
        Assert.Equal(Golden.ReplaceLineEndings("\n"), File(plan, FileSourceSchema.FileName));
        Assert.Equal(FileSourceSchema.LinuxInstallPath, plan.Files.Single(item => item.Name == FileSourceSchema.FileName).InstallPath);
        Assert.Equal(
            [("collector", FileSourceSchema.Variable, FileSourceSchema.LinuxInstallPath), ("collector", "BOWER_SOURCE_EXPECTATIONS", "/etc/bower/source-expectations.json")],
            plan.Variables.Select(variable => (variable.Component, variable.Name, variable.Value)));
        string expectations = Path.Combine(directory.Path, "expectations.json");
        await System.IO.File.WriteAllTextAsync(expectations, File(plan, "source-expectations.json"), cancellationToken);
        SourceExpectation expected = Assert.Single(SourceExpectationsLoader.LoadFile(expectations).Sources);
        Assert.Equal(("linux-sshd", "production", 60), (expected.Application, expected.Environment, expected.MaximumSilenceMinutes));
        Assert.Equal(new SourceSetupVerification("source", "linux-sshd/production", plan.Verification.Description), plan.Verification);
        SourceSetupSnippet install = Assert.Single(plan.Snippets);
        Assert.Contains($"{FileSourceSchema.Variable}={FileSourceSchema.LinuxInstallPath}\n", install.Content, StringComparison.Ordinal);
        Assert.Contains(FileSourceSchema.SymlinkPolicy, plan.Files[0].Description, StringComparison.Ordinal);
        Assert.True(result.Preview!.Valid);
        Assert.DoesNotContain("casey.example@example.com", result.Preview.Redacted, StringComparison.Ordinal);
        // No secret material or credential settings in anything the request installs.
        string serialised = JsonSerializer.Serialize(plan, ManagementApiTests.ApiJson);
        foreach (string word in new[] { "token", "password", "secret", "BEGIN" })
        {
            Assert.DoesNotContain(word, serialised, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Equal(plan.ContentHash, (await PlanAsync(app, "file", "edge-01", Values(), cancellationToken)).Plan!.ContentHash);
        Dictionary<string, string> other = Values();
        other["startAt"] = FileSourceSchema.StartAtBeginning;
        Assert.NotEqual(plan.ContentHash, (await PlanAsync(app, "file", "edge-01", other, cancellationToken)).Plan!.ContentHash);
    }

    [Theory]
    [InlineData("posix")]
    [InlineData("windows")]
    [InlineData("beginning")]
    public async Task Plan_ConfigurationPassesTheCollectorLoaderAndRouteCheck(string variant)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        Dictionary<string, string> values = Values();
        if (variant == "windows")
        {
            values["allowedRoot"] = @"C:\Logs\Security\";
            values["path"] = @"C:\Logs\Security\auth.log";
        }
        else if (variant == "beginning")
        {
            values["startAt"] = FileSourceSchema.StartAtBeginning;
            values["maxLineBytes"] = "30720";
        }

        SourceSetupPlanResult result = await PlanAsync(app, "file", "edge-01", values, cancellationToken);

        Assert.True(result.Valid, string.Join(" ", result.Checks.Select(check => check.Message)));
        string json = File(result.Plan!, FileSourceSchema.FileName);
        if (variant == "windows")
        {
            using JsonDocument document = JsonDocument.Parse(json);
            Assert.Equal(@"C:\Logs\Security", document.RootElement.GetProperty("allowedRoots")[0].GetString());
            Assert.All(result.Plan!.Files, file => Assert.StartsWith(@"C:\ProgramData\Bower\", file.InstallPath, StringComparison.Ordinal));
            Assert.Equal("powershell", Assert.Single(result.Plan!.Snippets).Language);
        }
        else
        {
            Assert.Equal("linux-sshd/production", result.Plan!.Verification.ReportId);
        }

        // The loader checks paths for the host it runs on, so Windows paths load only on Windows.
        if (variant != "windows" || OperatingSystem.IsWindows())
        {
            FileTailInputOptions input = Assert.Single(LoadAsCollector(json, SignedPackBundle(directory)).Inputs);
            Assert.Equal(values["path"], input.Path);
            Assert.Equal(new FileTailRoute("linux-authlog-ssh", 0), input.Route);
            Assert.Equal(variant == "beginning" ? "beginning" : "end", input.StartAt);
            Assert.False(input.AllowSymlink);
        }
    }

    [Fact]
    public void Schema_MatchesTheCollectorLoaderLimitsAndRefusesUnloadedRoutes()
    {
        using TemporaryDirectory directory = new();
        Assert.Equal(
            (FileTailFormats.Text, FileTailFormats.JsonLines),
            (FileSourceSchema.FormatText, FileSourceSchema.FormatJsonLines));
        Assert.Equal(
            (FileTailSourceConfigurationLoader.MinimumMaxLineBytes, FileTailSourceConfigurationLoader.DefaultMaxLineBytes, FileTailSourceConfigurationLoader.MaximumMaxLineBytes),
            (FileSourceSchema.MinimumLineBytes, FileSourceSchema.DefaultLineBytes, FileSourceSchema.MaximumLineBytes));
        PolicyBundle bundle = SignedPackBundle(directory);
        FileTailSourceConfiguration golden = LoadAsCollector(Golden, bundle);
        Assert.Equal(
            (1_000, 256, 1_048_576),
            (golden.PollIntervalMilliseconds, golden.MaxLinesPerBatch, golden.MaxBytesPerBatch));

        // The route check is real: a parser the bundle does not load stops start-up.
        Assert.Throws<InvalidOperationException>(() => LoadAsCollector(Golden.Replace("\"parser\": 0", "\"parser\": 1", StringComparison.Ordinal), bundle));
        Assert.Throws<InvalidOperationException>(() => LoadAsCollector(Golden.Replace("linux-authlog-ssh", "linux-ssh-gateway", StringComparison.Ordinal), bundle));
        Assert.Throws<InvalidDataException>(() => LoadAsCollector(Golden.Replace("16384", "30721", StringComparison.Ordinal), bundle));
    }

    [Theory]
    [InlineData("path", "absolute file path", "path=var/log/sshd-json/auth.log")]
    [InlineData("path", "absolute file path", "path=/var/log/../../../etc/shadow")]
    [InlineData("path", "wildcards", "path=/var/log/*.jsonl")]
    [InlineData("path", "wildcards", "path=/var/log/auth-[0-9].jsonl")]
    [InlineData("allowedRoot", "wildcards", "allowedRoot=/var/*")]
    [InlineData("path", "outside the allowed directory", "path=/srv/app/auth.log")]
    [InlineData("path", "outside the allowed directory", "path=/var/log-copy/auth.log")]
    [InlineData("path", "name one file", "path=/var/log/")]
    [InlineData("path", "name one file", "path=/var/log//auth.log")]
    [InlineData("path", "name one file", "path=/var/log/./auth.log")]
    [InlineData("path", "outside the allowed directory", "path=/var/log")]
    [InlineData("allowedRoot", "not the whole disk", "allowedRoot=/", "path=/auth.log")]
    [InlineData("allowedRoot", "not the whole disk", @"allowedRoot=C:\", @"path=C:\auth.log")]
    [InlineData("allowedRoot", "not the whole disk", "allowedRoot=/var//log", "path=/var//log/auth.log")]
    [InlineData("allowedRoot", "does not read files under /proc", "allowedRoot=/proc", "path=/proc/1/environ")]
    [InlineData("allowedRoot", "does not read files under /etc/bower", "allowedRoot=/etc/bower/secrets", "path=/etc/bower/secrets/ingest.token")]
    [InlineData("allowedRoot", "does not read files under /var/lib/bower", "allowedRoot=/var/lib/bower", "path=/var/lib/bower/queue.db")]
    [InlineData("allowedRoot", "does not read its own files", @"allowedRoot=C:\ProgramData\Bower", @"path=C:\ProgramData\Bower\ingest.token")]
    [InlineData("path", "different kinds of path", @"path=C:\Logs\auth.log")]
    [InlineData("parser", "not one of the choices", "parser=windows-security-logon:0")]
    [InlineData("parser", "not one of the choices", "parser=linux-authlog-ssh:7")]
    [InlineData("parser", "not one of the choices", "parser=linux-ssh-gateway:0")]
    [InlineData("parser", "not one of the choices", "parser=unsigned-pack:0")]
    [InlineData("parser", "not one of the choices", "parser=*")]
    [InlineData("startAt", "not one of the choices", "startAt=all")]
    [InlineData("maxLineBytes", "whole number", "maxLineBytes=30721")]
    [InlineData("inputId", "not allowed", "inputId=../auth")]
    [InlineData("values", "does not use", "collectAll=true")]
    public async Task Plan_RejectsUnsafeFileSettingsWithAFix(string id, string expected, params string[] overrides)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        Dictionary<string, string> values = Values();
        foreach (string item in overrides)
        {
            int split = item.IndexOf('=', StringComparison.Ordinal);
            values[item[..split]] = item[(split + 1)..];
        }

        SourceSetupPlanResult result = await PlanAsync(app, "file", "edge-01", values, cancellationToken);

        Assert.False(result.Valid);
        Assert.Null(result.Plan);
        Assert.Null(result.Preview);
        SetupCheck failure = Assert.Single(result.Checks, check => check.State == SetupCheckStates.Fail);
        Assert.Equal(id, failure.Id);
        Assert.Contains(expected, failure.Message + " " + failure.Fix, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(failure.Fix));
    }

    [Fact]
    public async Task Plan_WarnsWhenTheServiceHidesTheDirectory()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        Dictionary<string, string> values = Values();
        values["allowedRoot"] = "/home/app/security";
        values["path"] = "/home/app/security/auth.log";

        SourceSetupPlanResult result = await PlanAsync(app, "file", "edge-01", values, cancellationToken);

        Assert.True(result.Valid);
        Assert.Contains(result.Checks, check => check is { Id: "allowedRoot", State: SetupCheckStates.Warn });
    }

    [Fact]
    public async Task Plan_RefusesPendingDuplicateInputNamesAndFilesOnTheSameCollector()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, new FakeClock(Now), cancellationToken);
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        await ActiveCollectorAsync(app, "edge-02", cancellationToken);
        HttpClient requester = ManagementApiTests.Client(app, BowerRoles.Operator, "alex");
        SourceSetupRequestDetail first = await SubmitAsync(requester, "file", Values(), cancellationToken);
        Dictionary<string, string> sameFile = Values();
        sameFile["inputId"] = "auth-2";
        Dictionary<string, string> different = Values();
        different["inputId"] = "auth-2";
        different["path"] = "/var/log/secure";

        SourceSetupPlanResult sameId = await PlanAsync(app, "file", "edge-01", Values(), cancellationToken);
        SourceSetupPlanResult samePath = await PlanAsync(app, "file", "edge-01", sameFile, cancellationToken);
        SourceSetupPlanResult otherCollector = await PlanAsync(app, "file", "edge-02", Values(), cancellationToken);
        SourceSetupPlanResult distinct = await PlanAsync(app, "file", "edge-01", different, cancellationToken);
        using HttpResponseMessage resubmit = await requester.PostAsJsonAsync(
            "/api/sources/requests", new SourceSetupSubmission("file", "edge-01", Values(), "Again"), cancellationToken);
        HttpClient approver = ManagementApiTests.Client(app, BowerRoles.Approver, "sam");
        await approver.PostAsJsonAsync($"/api/sources/requests/{first.Id}/reject", new ApprovalRequest("Wrong file"), cancellationToken);
        SourceSetupPlanResult afterReject = await PlanAsync(app, "file", "edge-01", Values(), cancellationToken);
        SourceSetupRequestDetail second = await SubmitAsync(requester, "file", Values(), cancellationToken);
        await approver.PostAsJsonAsync($"/api/sources/requests/{second.Id}/approve", new ApprovalRequest("Right file"), cancellationToken);
        SourceSetupPlanResult replacing = await PlanAsync(app, "file", "edge-01", Values(), cancellationToken);

        Assert.Contains(sameId.Checks, check => check is { Id: "inputId", State: SetupCheckStates.Fail });
        Assert.Contains(samePath.Checks, check => check is { Id: "path", State: SetupCheckStates.Fail });
        Assert.True(otherCollector.Valid);
        Assert.True(distinct.Valid);
        Assert.Equal(HttpStatusCode.BadRequest, resubmit.StatusCode);
        Assert.True(afterReject.Valid);
        Assert.DoesNotContain(afterReject.Checks, check => check.Id is "inputId" or "path");
        // An approved input can only be replaced, so a new request for it warns instead of failing.
        Assert.True(replacing.Valid);
        Assert.Contains(replacing.Checks, check => check is { Id: "inputId", State: SetupCheckStates.Warn });
    }

    [Fact]
    public void Parsers_AreActiveParsersOfTheShippedSignedPacks()
    {
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        foreach (FileSourceParser parser in FileSourceSchema.Parsers)
        {
            string source = Path.Combine(AppContext.BaseDirectory, "packs", parser.Pack);
            LoadedPack pack = PackArchive.Load(PackArchive.Build(source, privatePem, directory.Path), [publicPem]);
            Assert.Equal(parser.Pack, pack.Manifest.Id);
            CustomLogParserConfiguration loaded = pack.Parsers[parser.ParserIndex];
            Assert.NotNull(loaded.Runtime);
            Assert.Equal((parser.Application, parser.Environment), (loaded.Runtime.ApplicationName, loaded.Runtime.Environment));
            // File tail records carry the line as message (text) or json (json-lines).
            string line = parser.Format == FileSourceSchema.FormatText ? "message" : "json";
            Assert.Contains(loaded.Fields, field => field.SourceName == line);
        }
    }

    [Fact]
    public async Task Signed_FileSetupVerifiesAndCoversTheGeneratedConfiguration()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string keyFile = Path.Combine(directory.Path, "source-signing.pem");
        await System.IO.File.WriteAllTextAsync(keyFile, privatePem, cancellationToken);
        await using WebApplication app = await ManagementApiTests.StartAsync(
            directory, new FakeClock(Now), cancellationToken, $"--{SourceSetupSigner.KeyFileSetting}={keyFile}");
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        HttpClient requester = ManagementApiTests.Client(app, BowerRoles.Operator, "alex");
        SourceSetupRequestDetail created = await SubmitAsync(requester, "file", Values(), cancellationToken);
        await ManagementApiTests.Client(app, BowerRoles.Approver, "sam").PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Approved"), cancellationToken);

        SignedSourceSetup signed = (await requester.GetFromJsonAsync<SignedSourceSetup>(
            $"/api/sources/requests/{created.Id}/signed", ManagementApiTests.ApiJson, cancellationToken))!;

        Assert.Equal(("file", created.ContentHash), (signed.SourceType, signed.ContentHash));
        Assert.Equal(Golden.ReplaceLineEndings("\n"), signed.Files.Single(file => file.Name == FileSourceSchema.FileName).Content);
        Assert.True(DetachedSigner.Verify(Bytes(signed, signed.Files), signed.Signature, [publicPem]));
        SourceSetupFile[] widened =
        [
            .. signed.Files.Select(file => file.Name == FileSourceSchema.FileName
                ? file with { Content = file.Content.Replace("/var/log\"", "/var\"", StringComparison.Ordinal) }
                : file)
        ];
        Assert.False(DetachedSigner.Verify(Bytes(signed, widened), signed.Signature, [publicPem]));
    }

    [Fact]
    public async Task Status_ReportsHeartbeatMetadataOnly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        FakeClock clock = new(Now);
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, clock, cancellationToken);
        ManagementStore store = app.Services.GetRequiredService<ManagementStore>();
        await ActiveCollectorAsync(app, "edge-01", cancellationToken);
        SourceSetupRequestDetail created = await SubmitAsync(ManagementApiTests.Client(app, BowerRoles.Operator, "alex"), "file", Values(), cancellationToken);
        await ManagementApiTests.Client(app, BowerRoles.Approver, "sam").PostAsJsonAsync(
            $"/api/sources/requests/{created.Id}/approve", new ApprovalRequest("Approved"), cancellationToken);
        clock.Advance(TimeSpan.FromSeconds(5));
        await store.ExchangeHeartbeatAsync(
            "edge-01",
            Heartbeat(new SourceReport("linux-sshd/production", "application", "healthy", 0, Now.AddSeconds(5))),
            "principal-edge-01",
            Now.AddSeconds(5),
            cancellationToken);

        using HttpResponseMessage list = await ManagementApiTests.Client(app, BowerRoles.Viewer).GetAsync("/api/sources/requests", cancellationToken);
        string body = await list.Content.ReadAsStringAsync(cancellationToken);
        SourceSetupRequestSummary summary = Assert.Single(JsonSerializer.Deserialize<SourceSetupRequestSummary[]>(body, ManagementApiTests.ApiJson)!);

        Assert.Equal(("complete", "Receiving events"), (summary.Check.State, summary.Check.Label));
        Assert.Equal("Security-selected file", summary.TypeTitle);
        Assert.DoesNotContain("/var/log/auth.log", body, StringComparison.Ordinal);
    }

    private static byte[] Bytes(SignedSourceSetup signed, IReadOnlyList<SourceSetupFile> files) =>
        SourceSetupSigner.SignedBytes(
            signed.RequestId, signed.CollectorId, signed.SourceType, signed.ContentHash, files, signed.Variables,
            signed.Snippets, signed.Verification, signed.ApprovedAt);

    /// <summary>What a collector start does with <c>BOWER_FILE_CONFIG</c>: load it, then check every route.</summary>
    private static FileTailSourceConfiguration LoadAsCollector(string json, PolicyBundle bundle)
    {
        FileTailSourceConfiguration configuration = FileTailSourceConfigurationLoader.Parse(json);
        Bower.Collector.FileTailRoutes.Validate(configuration, bundle);
        return configuration;
    }

    /// <summary>A collector bundle with every offered pack built, signed and loaded under a trusted key.</summary>
    private static PolicyBundle SignedPackBundle(TemporaryDirectory directory)
    {
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string trusted = Path.Combine(directory.Path, "trusted.pem");
        string hmacKey = Path.Combine(directory.Path, "hmac.key");
        System.IO.File.WriteAllText(trusted, publicPem);
        System.IO.File.WriteAllText(hmacKey, Convert.ToBase64String(new byte[32]));
        string[] packs =
        [
            .. FileSourceSchema.Parsers.Select(parser => parser.Pack).Distinct(StringComparer.Ordinal)
                .Select(pack => PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", pack), privatePem, directory.Path))
        ];
        return PolicyBundle.Load(new PolicyBundleSources
        {
            PolicyDirectory = Directory.CreateDirectory(Path.Combine(directory.Path, "policies")).FullName,
            Packs = packs,
            PackTrustedKeyFiles = [trusted],
            PrivacyHmacKeyFile = hmacKey
        });
    }
}

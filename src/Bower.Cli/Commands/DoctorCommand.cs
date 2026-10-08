using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Dcr;
using Bower.Evidence;
using Bower.Packs;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;

namespace Bower.Cli.Commands;

/// <summary>
/// bower doctor: checks a Bower deployment for problems Azure would otherwise handle
/// silently (truncation, dropped rows, schema drift, out-of-region data) and for local
/// misconfiguration. Exit code 1 when any check fails.
/// </summary>
internal static class DoctorCommand
{
    private sealed record Check(string Status, string Area, string Detail);

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static readonly string[] AustralianRegions = ["australiaeast", "australiasoutheast", "australiacentral", "australiacentral2"];

    public static async Task<int> RunAsync(string[] args)
    {
        List<Check> checks = [];
        void Pass(string area, string detail) => checks.Add(new("PASS", area, detail));
        void Warn(string area, string detail) => checks.Add(new("WARN", area, detail));
        void Fail(string area, string detail) => checks.Add(new("FAIL", area, detail));

        // Policies.
        string policyDirectory = CliOptions.Get(args, "--policy-directory") ?? Path.Combine("policies", "default");
        List<LoadedPolicy> policies = [];
        try
        {
            if (Directory.Exists(policyDirectory))
            {
                policies.AddRange(PolicyLoader.LoadDirectory(policyDirectory));
                Pass("policies", $"{policies.Count} policies load strictly from {policyDirectory}.");
            }
            else
            {
                Warn("policies", $"Policy directory {policyDirectory} not found (fine if packs supply policies).");
            }
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException)
        {
            Fail("policies", exception.Message);
        }

        // Packs.
        string[] trusted = CliOptions.All(args, "--trusted-key").Select(File.ReadAllText).ToArray();
        string? packProfile = null;
        foreach (string pack in CliOptions.All(args, "--pack"))
        {
            try
            {
                LoadedPack loaded = PackArchive.Load(pack, trusted);
                policies.AddRange(loaded.Policies);
                packProfile ??= loaded.PrivacyProfileYaml;
                Pass("pack", $"{loaded.Manifest.Id}@{loaded.Manifest.Version} signature and hashes verified (key {loaded.SignedByKeyId}).");
            }
            catch (Exception exception) when (exception is PackVerificationException or InvalidDataException or IOException)
            {
                Fail("pack", $"{Path.GetFileName(pack)}: {exception.Message}");
            }
        }

        string[] duplicates = policies.GroupBy(policy => policy.Policy.Metadata.Id).Where(group => group.Count() > 1).Select(group => group.Key).ToArray();
        if (duplicates.Length > 0)
        {
            Fail("policies", $"Duplicate policy ids across directory and packs: {string.Join(", ", duplicates)}.");
        }

        // Privacy profile.
        PrivacyPolicy privacy = PrivacyPolicy.CreateDefault();
        string? profileYaml = CliOptions.Get(args, "--privacy-profile") is { } profilePath ? File.ReadAllText(profilePath) : packProfile;
        if (profileYaml is not null)
        {
            try
            {
                byte[]? key = CliOptions.Get(args, "--hmac-key-file") is { } keyFile ? PrivacyProfileLoader.ReadKeyFile(keyFile) : null;
                privacy = PrivacyProfileLoader.Load(profileYaml, key).Policy;
                Pass("privacy", $"Privacy profile loads; {privacy.FieldRules.Count} field rule(s), max field length {privacy.MaximumFieldLength}.");
            }
            catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or IOException)
            {
                Fail("privacy", exception.Message);
            }
        }
        else
        {
            Pass("privacy", "Default Australian privacy policy (TFN masked, secrets removed).");
        }

        // Schema and preflight against the Logs Ingestion API limits.
        SentinelSchema schema = SentinelSchema.Default;
        IReadOnlyList<DcrFinding> lint = DcrDrift.LintSchema(schema);
        if (lint.Count == 0)
        {
            Pass("schema", $"{schema.TableName}: {schema.TableColumns.Count} columns, names valid, TimeGenerated present.");
        }

        lint.ToList().ForEach(finding => Fail("schema", finding.Detail));
        PrivacyScanResult sample = new PrivacyEngine(privacy).RedactJson(SampleEnvelope());
        if (sample.Succeeded && JsonNode.Parse(sample.RedactedJson!) is JsonObject record)
        {
            IReadOnlyList<PreflightIssue> issues = IngestionPreflight.Check(record, schema);
            if (issues.Count == 0)
            {
                Pass("preflight", "Representative event passes Logs Ingestion API size, type and field checks after redaction.");
            }

            issues.ToList().ForEach(issue => Fail("preflight", $"{issue.Field}: {issue.Detail}"));
        }

        if (privacy.MaximumFieldLength * 2 > IngestionPreflight.MaximumFieldBytes)
        {
            Warn("preflight", $"maximumFieldLength {privacy.MaximumFieldLength} could exceed Azure's 64 KB field limit for non-ASCII text.");
        }

        // Region placement (sovereignty).
        foreach (string endpoint in CliOptions.All(args, "--ingestion-endpoint"))
        {
            string host = new Uri(endpoint).Host.ToLowerInvariant();
            string? region = AustralianRegions.FirstOrDefault(name => host.Contains(name, StringComparison.Ordinal));
            if (region is not null)
            {
                Pass("region", $"Ingestion endpoint is in {region}.");
            }
            else
            {
                Warn("region", $"Ingestion endpoint {host} is not recognisably in an Australian region.");
            }
        }

        // Live collector.
        if (CliOptions.Get(args, "--collector-url") is { } collectorUrl)
        {
            await CheckCollectorAsync(collectorUrl, policies, Pass, Warn, Fail);
        }

        // Local queue ledger.
        if (CliOptions.Get(args, "--database") is { } database)
        {
            SqliteEventStore store = new(database, 10L * 1024 * 1024 * 1024);
            await store.InitializeAsync();
            LedgerVerification ledger = await store.VerifyLedgerAsync();
            if (ledger.Intact)
            {
                Pass("ledger", $"Queue ledger intact ({ledger.Entries} entries, head {ledger.HeadSequence}).");
            }
            else
            {
                Fail("ledger", $"Queue ledger has {ledger.Issues.Count} issue(s); run 'bower queue verify'.");
            }

            QueueSnapshot snapshot = await store.GetSnapshotAsync();
            if (snapshot.DeadLettered > 0)
            {
                Warn("queue", $"{snapshot.DeadLettered} dead-lettered event(s); inspect with 'bower queue dead-letters'.");
            }
        }

        // Live Azure resources (read-only).
        string? ruleId = CliOptions.Get(args, "--dcr-resource-id");
        string? workspaceId = CliOptions.Get(args, "--workspace-resource-id");
        if (ruleId is not null || workspaceId is not null)
        {
            ArmReader arm = new(new HttpClient(), VerifierCredential.Create(CliOptions.Get(args, "--credential")));
            if (ruleId is not null)
            {
                JsonObject? rule = await arm.GetAsync(ruleId, DcrTemplateGenerator.ApiVersion, CancellationToken.None);
                if (rule is null)
                {
                    Fail("dcr", "DCR not found or not readable with this credential.");
                }
                else
                {
                    Report("dcr", DcrDrift.CompareRule(rule.ToJsonString(), schema), Pass, Warn, Fail);
                    CheckRegion("dcr", rule["location"]?.GetValue<string>(), Pass, Warn);
                }
            }

            if (workspaceId is not null)
            {
                JsonObject? workspace = await arm.GetAsync(workspaceId, DcrTemplateGenerator.ApiVersion, CancellationToken.None);
                CheckRegion("workspace", workspace?["location"]?.GetValue<string>(), Pass, Warn);
                JsonObject? table = await arm.GetAsync($"{workspaceId}/tables/{schema.TableName}", DcrTemplateGenerator.ApiVersion, CancellationToken.None);
                if (table is null)
                {
                    Fail("table", $"{schema.TableName} not found; deploy with 'bower dcr generate'.");
                }
                else
                {
                    Report("table", DcrDrift.CompareTable(table.ToJsonString(), schema), Pass, Warn, Fail);
                }
            }
        }

        if (CliOptions.Has(args, "--json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(checks, Indented));
        }
        else
        {
            foreach (Check check in checks)
            {
                Console.WriteLine($"{check.Status,-5} {check.Area,-10} {check.Detail}");
            }

            int failed = checks.Count(check => check.Status == "FAIL");
            int warned = checks.Count(check => check.Status == "WARN");
            Console.WriteLine($"{checks.Count} checks: {failed} failed, {warned} warnings.");
        }

        return checks.Any(check => check.Status == "FAIL") ? 1 : 0;
    }

    private static async Task CheckCollectorAsync(
        string collectorUrl,
        List<LoadedPolicy> policies,
        Action<string, string> pass,
        Action<string, string> warn,
        Action<string, string> fail)
    {
        using HttpClient http = new() { BaseAddress = new Uri(collectorUrl.EndsWith('/') ? collectorUrl : collectorUrl + "/"), Timeout = TimeSpan.FromSeconds(10) };
        try
        {
            using HttpResponseMessage health = await http.GetAsync("health");
            if (!health.IsSuccessStatusCode)
            {
                fail("collector", $"/health returned HTTP {(int)health.StatusCode}.");
                return;
            }

            pass("collector", $"{http.BaseAddress!.Host} is reachable.");
            using HttpRequestMessage request = new(HttpMethod.Get, "v1/status");
            if (Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN") is { Length: > 0 } token)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            using HttpResponseMessage response = await http.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                warn("collector", $"/v1/status returned HTTP {(int)response.StatusCode} (set BOWER_INGEST_TOKEN for details).");
                return;
            }

            JsonObject? status = JsonNode.Parse(await response.Content.ReadAsStringAsync()) as JsonObject;
            long dead = status?["queue"]?["deadLettered"]?.GetValue<long>() ?? 0;
            if (dead > 0)
            {
                warn("collector", $"{dead} dead-lettered event(s) on the collector.");
            }

            string? policyHash = status?["policy"]?["hash"]?.GetValue<string>();
            pass("collector", $"Running policy bundle {policyHash ?? "unknown"}.");
        }
        catch (HttpRequestException exception)
        {
            fail("collector", $"Unreachable: {exception.Message}");
        }
    }

    private static void Report(
        string area,
        IReadOnlyList<DcrFinding> findings,
        Action<string, string> pass,
        Action<string, string> warn,
        Action<string, string> fail)
    {
        if (findings.Count == 0)
        {
            pass(area, "Matches Bower's schema.");
        }

        foreach (DcrFinding finding in findings)
        {
            (finding.Level switch
            {
                FindingLevel.Error => fail,
                FindingLevel.Warning => warn,
                _ => pass
            })(area, $"{finding.Code}: {finding.Detail}");
        }
    }

    private static void CheckRegion(string area, string? location, Action<string, string> pass, Action<string, string> warn)
    {
        string normalised = (location ?? string.Empty).Replace(" ", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
        if (AustralianRegions.Contains(normalised))
        {
            pass(area, $"Located in {normalised}.");
        }
        else
        {
            warn(area, $"Located in '{location ?? "unknown"}', outside Australia.");
        }

        if (area == "workspace" && normalised is not "australiaeast" and not "")
        {
            warn(area, "The Sentinel data lake is only available in Australia East.");
        }
    }

    private static string SampleEnvelope() =>
        JsonSerializer.Serialize(new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = "doctor-sample",
            TimeGenerated = DateTimeOffset.UtcNow,
            EventCategory = SecurityEventCategories.Authentication,
            EventType = SecurityEventTypes.AuthenticationFailure,
            EventAction = "authentication.attempt",
            EventResult = EventResult.Failure,
            EventOutcomeReason = new string('x', 2_000),
            Application = new ApplicationContext { Name = "doctor", Environment = "test" },
            Actor = new ActorContext { Username = "doctor" },
            Source = new SourceContext { IpAddress = "192.0.2.1" },
            Request = new RequestContext { CorrelationId = "doctor" }
        }, BowerJson.Options);
}

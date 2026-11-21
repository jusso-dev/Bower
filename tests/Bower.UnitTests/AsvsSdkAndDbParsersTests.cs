using System.Net;
using System.Text.Json;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Integrity;
using Bower.Packs;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;
using Bower.Sdk;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Bower.UnitTests;

public sealed class AsvsSdkAndDbParsersTests
{
    private const string PackId = "owasp-asvs-app-logging";
    private static readonly DateTimeOffset EvaluationTime = new(2026, 11, 22, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SignedDbAuditParsers_MapAllowedEvents_DropSqlStatements_AndPassAsvsPolicy()
    {
        LoadedPack pack = BuildAsvsPack();
        Assert.Equal(4, pack.Parsers.Count);

        PrivacyEngine privacy = new(PrivacyProfileLoader.Load(pack.PrivacyProfileYaml!, new byte[32], "k1").Policy);
        DeterministicPolicyEvaluator evaluator = new(pack.Policies);

        (string AppName, string Raw, string ExpectedEngine, string ExpectedAction, string ExpectedCategory)[] cases =
        [
            (
                "postgresql-pgaudit",
                """{"timestamp":"2026-11-22T00:00:00Z","session_id":"673f1a.12","session_line_num":4,"user":"db_admin","dbname":"billing","remote_host":"192.0.2.21","error_severity":"LOG","message":"AUDIT: SESSION,1,1,ROLE,GRANT,,,GRANT super_role TO alice; SELECT 'secret-token-xyz'"}""",
                "postgresql",
                "db.dcl",
                "administrative-activity"
            ),
            (
                "mysql-audit",
                """{"timestamp":"2026-11-22T00:00:00Z","id":"991","class":"connection","event":"connect","user":"app_svc","ip":"192.0.2.22","db":"orders","status":1045,"statement":"SELECT secret_col FROM customers"}""",
                "mysql",
                "db.logon_failure",
                "authentication"
            ),
            (
                "mongodb-audit",
                """{"atype":"grantRolesToUser","ts":{"$date":"2026-11-22T00:00:00Z"},"uuid":"m-100","remote":{"ip":"192.0.2.23"},"users":[{"user":"ops_admin","db":"admin"}],"param":{"db":"ledger","user":"bob"},"result":0}""",
                "mongodb",
                "db.dcl",
                "administrative-activity"
            ),
            (
                "sqlserver-audit",
                """{"id":"win-33205-1","timeCreated":"2026-11-22T00:00:00Z","provider":"MSSQLSERVER$AUDIT","channel":"Security","eventId":33205,"data.action_id":"AL  ","data.succeeded":"true","data.server_principal_name":"CONTOSO\\sa_ops","data.database_name":"finance","data.object_name":"dbo.accounts","data.client_ip":"192.0.2.24","data.statement":"ALTER TABLE dbo.accounts ADD secret_note nvarchar(50)"}""",
                "sqlserver",
                "db.ddl",
                "administrative-activity"
            )
        ];

        foreach ((string appName, string raw, string expectedEngine, string expectedAction, string expectedCategory) in cases)
        {
            var parser = Assert.Single(pack.Parsers, p => p.Runtime?.ApplicationName == appName);
            SecurityEventEnvelope? parsed = PackRuntime.Parse(parser, raw, EvaluationTime);
            Assert.NotNull(parsed);
            Assert.Equal("database_audit", parsed.EventType);
            Assert.Equal(expectedAction, parsed.EventAction);
            Assert.Equal(expectedCategory, parsed.EventCategory);
            Assert.Equal(expectedEngine, parsed.Labels!["dbEngine"]);

            string json = JsonSerializer.Serialize(parsed, BowerJson.Envelope);
            Assert.DoesNotContain("secret-token-xyz", json, StringComparison.Ordinal);
            Assert.DoesNotContain("secret_col", json, StringComparison.Ordinal);
            Assert.DoesNotContain("secret_note", json, StringComparison.Ordinal);

            PrivacyScanResult redacted = privacy.RedactJson(json);
            Assert.True(redacted.Succeeded);
            Assert.DoesNotContain("db_admin", redacted.RedactedJson!, StringComparison.Ordinal);
            Assert.DoesNotContain("app_svc", redacted.RedactedJson!, StringComparison.Ordinal);
            Assert.DoesNotContain("ops_admin", redacted.RedactedJson!, StringComparison.Ordinal);
            Assert.DoesNotContain("sa_ops", redacted.RedactedJson!, StringComparison.Ordinal);

            SecurityEventEnvelope envelope = JsonSerializer.Deserialize(redacted.RedactedJson!, BowerJson.Envelope)!;
            PolicyDecision decision = evaluator.Evaluate(envelope);
            Assert.Equal(DecisionAction.Accept, decision.Action);
            Assert.Equal("BWR-PACK-ASVS-DB-AUDIT", decision.PolicyId);
        }

        // Unapproved / non-audit records return null (default deny).
        Assert.Null(PackRuntime.Parse(
            Assert.Single(pack.Parsers, p => p.Runtime?.ApplicationName == "postgresql-pgaudit"),
            """{"timestamp":"2026-11-22T00:00:00Z","session_id":"s1","session_line_num":1,"user":"app","message":"checkpoint complete"}""",
            EvaluationTime));
        Assert.Null(PackRuntime.Parse(
            Assert.Single(pack.Parsers, p => p.Runtime?.ApplicationName == "sqlserver-audit"),
            """{"id":"win-4625-1","timeCreated":"2026-11-22T00:00:00Z","provider":"Microsoft-Windows-Security-Auditing","channel":"Security","eventId":4625,"data.action_id":"AL","data.server_principal_name":"u"}""",
            EvaluationTime));
    }

    [Fact]
    public async Task AsvsSdk_EmitsAllElevenEventFamilies_PassingAsvsPackPoliciesAndPrivacy()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        LoadedPack pack = BuildAsvsPack();
        PrivacyEngine privacy = new(PrivacyProfileLoader.Load(pack.PrivacyProfileYaml!, new byte[32], "k1").Policy);
        DeterministicPolicyEvaluator evaluator = new(pack.Policies);

        List<string> received = [];
        WebApplicationBuilder sinkBuilder = WebApplication.CreateSlimBuilder();
        sinkBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using WebApplication sink = sinkBuilder.Build();
        sink.MapPost("/v1/events", async (HttpContext ctx) =>
        {
            using StreamReader reader = new(ctx.Request.Body);
            string body = await reader.ReadToEndAsync(ct);
            lock (received) { received.Add(body); }
            return Results.Accepted();
        });
        await sink.StartAsync(ct);
        string endpoint = sink.Urls.Single();

        ServiceCollection services = new();
        services.AddBower(options =>
        {
            options.Application.Name = "asvs-sdk-app";
            options.Application.Environment = "production";
            options.Application.TenantId = "tenant-1";
            options.LocalCollector.Endpoint = endpoint;
            options.ShutdownFlushTimeout = TimeSpan.FromSeconds(5);
        });

        await using ServiceProvider provider = services.BuildServiceProvider();
        IAsvsTelemetry asvs = provider.GetRequiredService<IAsvsTelemetry>();

        IPAddress ip = IPAddress.Parse("192.0.2.55");
        await asvs.AuthenticationSucceededAsync(new AuthenticationSucceededEvent
        {
            UserId = "u-1",
            Username = "alice@example.com",
            AuthMethod = "passkey",
            SourceIpAddress = ip,
            CorrelationId = "c-1"
        }, ct);
        await asvs.MfaEventAsync(new MfaSecurityEvent
        {
            UserId = "u-1",
            Outcome = MfaOutcome.Failure,
            Factor = "totp",
            Reason = "invalid_code",
            SourceIpAddress = ip,
            CorrelationId = "c-2"
        }, ct);
        await asvs.AuthenticationFactorLifecycleAsync(new AuthenticationFactorLifecycleEvent
        {
            ActorUserId = "u-admin",
            TargetUserId = "u-1",
            Action = FactorLifecycleAction.MfaRemoved,
            Factor = "totp",
            InitiatedBy = "admin",
            CorrelationId = "c-3"
        }, ct);
        await asvs.AccountStatusChangedAsync(new AccountStatusChangedEvent
        {
            ActorUserId = "u-admin",
            TargetUserId = "u-2",
            Action = AccountStatusAction.Disable,
            Reason = "offboarding",
            CorrelationId = "c-4"
        }, ct);
        await asvs.SessionLifecycleAsync(new SessionLifecycleEvent
        {
            ActorUserId = "u-1",
            Action = SessionLifecycleAction.RevokeAll,
            SessionId = "sess-raw-secret-token",
            SessionsTerminated = 3,
            CorrelationId = "c-5"
        }, ct);
        await asvs.AuthorisationFailedAsync(new AuthorisationFailedEvent
        {
            ActorUserId = "u-1",
            Kind = AuthorisationFailureKind.ObjectLevel,
            TargetType = "invoice",
            TargetId = "inv-9",
            Route = "/api/invoices/inv-9",
            HttpMethod = "GET",
            SourceIpAddress = ip,
            CorrelationId = "c-6"
        }, ct);
        await asvs.SensitiveDataAccessedAsync(new SensitiveDataAccessEvent
        {
            ActorUserId = "u-1",
            Operation = SensitiveDataOperation.Read,
            TargetType = "record",
            TargetId = "rec-7",
            DataClassification = "OFFICIAL:Sensitive",
            RecordCount = 1,
            CorrelationId = "c-7"
        }, ct);
        await asvs.AdministrativeActionAsync(new AdministrativeSecurityEvent
        {
            ActorUserId = "u-admin",
            Kind = AdministrativeEventKind.ConfigurationChanged,
            Action = "config.update",
            TargetType = "setting",
            TargetId = "mfa-policy",
            ChangedField = "requireMfa",
            CorrelationId = "c-8"
        }, ct);
        await asvs.ControlBypassAttemptedAsync(new ControlBypassEvent
        {
            Kind = ControlBypassKind.AntiAutomationTriggered,
            Action = "rate_limit.exceeded",
            SourceIpAddress = ip,
            Route = "/login",
            Reason = "threshold_exceeded",
            CorrelationId = "c-9"
        }, ct);
        await asvs.SecurityErrorAsync(new SecurityErrorEvent
        {
            Kind = SecurityErrorKind.SecurityControlFailure,
            Action = "tls.verify",
            Reason = "certificate_expired",
            ErrorType = "TlsValidationError",
            CorrelationId = "c-10"
        }, ct);
        await asvs.DatabaseAuditAsync(new DatabaseAuditEvent
        {
            DbEngine = "postgresql",
            Action = DatabaseAuditAction.Dcl,
            ActorUsername = "db_ops",
            TargetName = "billing",
            StatementClass = "ROLE",
            SourceIpAddress = ip
        }, ct);

        await provider.DisposeAsync();
        await sink.StopAsync(ct);

        Assert.Equal(11, received.Count);
        HashSet<string> matchedPolicies = new(StringComparer.Ordinal);
        foreach (string rawJson in received)
        {
            PrivacyScanResult redacted = privacy.RedactJson(rawJson);
            Assert.True(redacted.Succeeded);
            Assert.DoesNotContain("alice@example.com", redacted.RedactedJson!, StringComparison.Ordinal);
            Assert.DoesNotContain("sess-raw-secret-token", redacted.RedactedJson!, StringComparison.Ordinal);

            SecurityEventEnvelope envelope = JsonSerializer.Deserialize(redacted.RedactedJson!, BowerJson.Envelope)!;
            PolicyDecision decision = evaluator.Evaluate(envelope);
            Assert.Equal(DecisionAction.Accept, decision.Action);
            matchedPolicies.Add(decision.PolicyId);
        }

        Assert.Equal(11, matchedPolicies.Count);
    }

    private static LoadedPack BuildAsvsPack()
    {
        using TemporaryDirectory output = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        string archive = PackArchive.Build(Path.Combine(AppContext.BaseDirectory, "packs", PackId), privatePem, output.Path);
        return PackArchive.Load(archive, [publicPem]);
    }
}

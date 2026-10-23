using System.Text.Json;
using Bower.Abstractions;
using Bower.Collector;
using Bower.Contracts;
using Bower.PolicyEngine;
using Bower.Sdk;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class DefaultSignalCoverageTests
{
    [Fact]
    public async Task Every_public_sdk_event_reaches_durable_queue_with_shipped_defaults()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = CollectorApplication.Build(new CollectorSettings
        {
            ListenUrl = "http://127.0.0.1:0",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies/default"),
            CollectorId = "sdk-coverage",
            SingleTrustDomain = true
        }, builder => builder.Logging.ClearProviders());
        await CollectorApplication.InitializeAsync(app, ct);
        await app.StartAsync(ct);
        ServiceCollection services = new();
        services.AddBower(options =>
        {
            options.Application.Name = "coverage-app";
            options.Application.Environment = "test";
            options.LocalCollector.Endpoint = app.Urls.Single();
        });
        await using (ServiceProvider provider = services.BuildServiceProvider())
        {
            IBowerTelemetry sdk = provider.GetRequiredService<IBowerTelemetry>();
            Assert.True((await sdk.AuthenticationFailedAsync(new()
            { Username = "operator", FailureReason = "bad-password", CorrelationId = "auth-1" }, ct)).AcceptedForDelivery);
            Assert.True((await sdk.RoleMembershipChangedAsync(new()
            { ActorUserId = "operator", TargetUserId = "member", Role = "auditor", Change = MembershipChange.Added, CorrelationId = "role-1" }, ct)).AcceptedForDelivery);
            Assert.True((await sdk.SensitiveDataExportedAsync(new()
            { ActorUserId = "operator", ExportId = "export-1", ExportFormat = "csv", DataClassification = "sensitive", RecordCount = 7, CorrelationId = "export-1" }, ct)).AcceptedForDelivery);
        }
        IDurableEventStore store = app.Services.GetRequiredService<IDurableEventStore>();
        IReadOnlyList<QueuedEvent> rows = await store.LeaseAsync(10, TimeSpan.FromMinutes(1), ct);
        foreach (string type in new[] { "authentication_failure", "role_membership_changed", "sensitive_data_exported" })
            Assert.Contains(rows, row => row.Payload.Contains($"\"eventType\":\"{type}\"", StringComparison.Ordinal));
        SecurityEventEnvelope[] accepted = rows.Select(row => JsonSerializer.Deserialize(row.Payload, BowerJson.Envelope)!).ToArray();
        SecurityEventEnvelope role = Assert.Single(accepted, item => item.EventType == "role_membership_changed");
        Assert.Equal("member", role.Target?.Id);
        Assert.Equal("auditor", role.Change?.NewValue);
        Assert.Equal("operator", role.Actor?.UserId);
        SecurityEventEnvelope export = Assert.Single(accepted, item => item.EventType == "sensitive_data_exported");
        Assert.Equal("export-1", export.Target?.Id);
        Assert.Equal(7, export.Attributes!["recordCount"].GetInt64());
        Assert.Equal("sensitive", export.Labels!["dataClassification"]);
        DeterministicPolicyEvaluator evaluator = new(PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "policies/default")));
        Assert.Equal(DecisionAction.Reject, evaluator.Evaluate(TestEvents.AuthenticationFailure(DateTimeOffset.UtcNow) with { EventType = "unapproved_type" }).Action);
    }

    [Theory]
    [InlineData("aws-security", "aws_cloudtrail", "ListBuckets", EventResult.Success, false)]
    [InlineData("aws-security", "aws_cloudtrail", "AppLogs", EventResult.Success, false)]
    [InlineData("aws-security", "aws_cloudtrail", "AttachUserPolicy", EventResult.Success, true)]
    [InlineData("aws-security", "aws_cloudtrail", "StopLogging", EventResult.Success, true)]
    [InlineData("aws-security", "aws_cloudtrail", "DetachUserPolicy", EventResult.Success, true)]
    [InlineData("aws-security", "aws_cloudtrail", "DetachRolePolicy", EventResult.Success, true)]
    [InlineData("aws-security", "aws_cloudtrail", "DetachGroupPolicy", EventResult.Success, true)]
    [InlineData("aws-security", "aws_cloudtrail", "RemoveUserFromGroup", EventResult.Success, true)]
    [InlineData("gcp-security", "gcp_cloud_audit", "ListProjects", EventResult.Success, false)]
    [InlineData("gcp-security", "gcp_cloud_audit", "SetIamPolicy", EventResult.Success, true)]
    [InlineData("gcp-security", "gcp_cloud_audit", "ListProjects", EventResult.Denied, true)]
    public void Broadened_cloud_feed_still_obeys_local_security_population(string pack, string type, string action, EventResult result, bool accepted)
    {
        DeterministicPolicyEvaluator evaluator = new(PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "packs", pack, "policies")));
        SecurityEventEnvelope candidate = TestEvents.AuthenticationFailure(TestEvents.Now) with
        {
            EventCategory = "administrative-activity",
            EventType = type,
            EventAction = action,
            EventResult = result,
            Target = new TargetContext { Type = "resource", Name = "fixture-resource" }
        };
        Assert.Equal(accepted ? DecisionAction.Accept : DecisionAction.Reject, evaluator.Evaluate(candidate).Action);
    }

    [Theory]
    [InlineData("eventActions: []")]
    [InlineData("eventActions: null")]
    [InlineData("eventResults: [typo]")]
    [InlineData("eventSeverities: [urgent]")]
    public void Invalid_selection_predicates_fail_closed(string predicate)
    {
        string yaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "policies/default/authentication-failure.yaml"));
        Assert.Throws<InvalidDataException>(() => PolicyLoader.LoadYaml(yaml.Replace("match:", "match:\n  " + predicate, StringComparison.Ordinal), "fixture.yaml"));
    }
}

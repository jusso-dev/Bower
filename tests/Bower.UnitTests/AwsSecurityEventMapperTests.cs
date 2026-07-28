using System.Text.Json;
using Bower.Contracts;
using Bower.Source.Aws;

namespace Bower.UnitTests;

public sealed class AwsSecurityEventMapperTests
{
    [Fact]
    public void Options_RejectInvalidAccountId()
    {
        AwsSourceOptions options = ValidOptions() with { AccountId = "abc" };

        Assert.Throws<ArgumentException>(options.Validate);
    }

    [Fact]
    public void Map_CloudTrailRecords_ToSecurityEvents()
    {
        const string json =
            """
            {
              "Records": [
                {
                  "eventVersion": "1.08",
                  "eventID": "11111111-1111-1111-1111-111111111111",
                  "eventTime": "2026-07-01T10:00:00Z",
                  "eventName": "ConsoleLogin",
                  "eventSource": "signin.amazonaws.com",
                  "awsRegion": "ap-southeast-2",
                  "sourceIPAddress": "203.0.113.10",
                  "recipientAccountId": "123456789012",
                  "userIdentity": {
                    "type": "IAMUser",
                    "userName": "alice",
                    "accountId": "123456789012"
                  }
                }
              ]
            }
            """;

        AwsSecurityEventMapper mapper = new(ValidOptions() with
        {
            Kind = AwsTelemetrySourceKind.CloudTrail
        });

        IReadOnlyList<SecurityEventEnvelope> events = mapper.MapJsonDocument(json);

        Assert.Single(events);
        SecurityEventEnvelope envelope = events[0];
        Assert.Equal("11111111-1111-1111-1111-111111111111", envelope.EventOriginalId);
        Assert.Equal("aws_cloudtrail", envelope.EventType);
        Assert.Equal("ConsoleLogin", envelope.EventAction);
        Assert.Equal(EventResult.Success, envelope.EventResult);
        Assert.Equal("alice", envelope.Actor?.Username);
        Assert.Equal("203.0.113.10", envelope.Source?.IpAddress);
        Assert.Equal("123456789012", envelope.Labels?["aws.accountId"]);
        Assert.Equal("ap-southeast-2", envelope.Labels?["aws.region"]);
        Assert.Equal("aws.cloudtrail", envelope.Collector?.SourceAdapter);
    }

    [Fact]
    public void Map_GuardDutyFinding_SetsSeverity()
    {
        const string json =
            """
            {
              "id": "gd-1",
              "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
              "title": "Credential exfiltration",
              "severity": 8.0,
              "createdAt": "2026-07-01T11:00:00Z",
              "region": "us-east-1",
              "accountId": "123456789012"
            }
            """;

        AwsSecurityEventMapper mapper = new(ValidOptions() with
        {
            Kind = AwsTelemetrySourceKind.GuardDuty
        });

        SecurityEventEnvelope envelope = Assert.Single(mapper.MapJsonDocument(json));

        Assert.Equal("aws_guardduty", envelope.EventType);
        Assert.Equal(EventSeverity.High, envelope.EventSeverity);
        Assert.Equal(EventResult.Failure, envelope.EventResult);
        Assert.Equal("Credential exfiltration", envelope.EventOutcomeReason);
    }

    [Fact]
    public void Map_SecurityHubFinding_MapsCompliance()
    {
        const string json =
            """
            {
              "Id": "arn:aws:securityhub:finding/1",
              "Title": "S3.1 S3 Block Public Access",
              "ProductArn": "arn:aws:securityhub:ap-southeast-2::product/aws/securityhub",
              "AwsAccountId": "123456789012",
              "Region": "ap-southeast-2",
              "UpdatedAt": "2026-07-01T12:00:00Z",
              "Severity": { "Label": "HIGH" },
              "Compliance": { "Status": "FAILED" }
            }
            """;

        AwsSecurityEventMapper mapper = new(ValidOptions() with
        {
            Kind = AwsTelemetrySourceKind.SecurityHub
        });

        SecurityEventEnvelope envelope = Assert.Single(mapper.MapJsonDocument(json));

        Assert.Equal("aws_security_hub", envelope.EventType);
        Assert.Equal(EventSeverity.High, envelope.EventSeverity);
        Assert.Equal(EventResult.Failure, envelope.EventResult);
        Assert.Equal("FAILED", envelope.Labels?["aws.compliance"]);
    }

    [Fact]
    public void Map_CloudWatchLogEvents_ExpandArray()
    {
        const string json =
            """
            {
              "logEvents": [
                { "id": "1", "timestamp": 1710000000000, "message": "deny policy" },
                { "id": "2", "timestamp": 1710000001000, "message": "allow policy" }
              ]
            }
            """;

        AwsSecurityEventMapper mapper = new(ValidOptions() with
        {
            Kind = AwsTelemetrySourceKind.CloudWatchLogs
        });

        IReadOnlyList<SecurityEventEnvelope> events = mapper.MapJsonDocument(json);

        Assert.Equal(2, events.Count);
        Assert.All(events, item => Assert.Equal("aws_cloudwatch_logs", item.EventType));
        Assert.Contains("deny policy", events[0].Labels?["aws.messagePreview"]);
    }

    [Fact]
    public void Map_RejectsOversizedRecord()
    {
        AwsSecurityEventMapper mapper = new(ValidOptions() with
        {
            Kind = AwsTelemetrySourceKind.GuardDuty,
            MaximumRecordBytes = 1_024
        });
        string huge = JsonSerializer.Serialize(new
        {
            id = "big",
            type = "x",
            title = new string('a', 2_000)
        });

        Assert.Throws<AwsTelemetryPayloadTooLargeException>(() => mapper.MapJsonDocument(huge));
    }

    private static AwsSourceOptions ValidOptions()
    {
        return new AwsSourceOptions
        {
            SourceId = "aws-security-primary",
            Kind = AwsTelemetrySourceKind.CloudTrail,
            AccountId = "123456789012",
            Region = "ap-southeast-2",
            Environment = "test",
            ApplicationName = "bower-aws"
        };
    }
}

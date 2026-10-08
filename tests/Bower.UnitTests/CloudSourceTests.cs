using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Bower.Contracts;
using Bower.Source.Aws;
using Bower.Source.Gcp;

namespace Bower.UnitTests;

public sealed class CloudSourceTests
{
    internal const string GuardDutyEvent = """
        {"version":"0","id":"c8c4daa7-a20c-2f03-0070-b7393dd542ad","detail-type":"GuardDuty Finding","source":"aws.guardduty",
         "account":"123456789012","time":"2026-07-26T02:10:00Z","region":"ap-southeast-2","resources":[],
         "detail":{"schemaVersion":"2.0","accountId":"123456789012","region":"ap-southeast-2","id":"a1b2c3","type":"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
           "title":"Credentials for instance role used from external IP","severity":8.0,"createdAt":"2026-07-26T02:00:00Z","updatedAt":"2026-07-26T02:05:00Z",
           "resource":{"resourceType":"AccessKey","accessKeyDetails":{"secretAccessKey":"never-forward-this"}}}}
        """;

    internal const string RootConsoleLoginFailure = """
        {"version":"0","id":"1","detail-type":"AWS Console Sign In via CloudTrail","source":"aws.signin","account":"123456789012",
         "time":"2026-07-26T02:10:00Z","region":"us-east-1","resources":[],
         "detail":{"eventVersion":"1.09","userIdentity":{"type":"Root","principalId":"123456789012","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012"},
           "eventTime":"2026-07-26T02:09:59Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1",
           "sourceIPAddress":"203.0.113.10","userAgent":"Mozilla/5.0","requestParameters":null,
           "responseElements":{"ConsoleLogin":"Failure"},"additionalEventData":{"MFAUsed":"No"},"errorMessage":"Failed authentication",
           "eventID":"4e1d2b9a-0000-4000-8000-000000000001","readOnly":false,"eventType":"AwsConsoleSignIn","recipientAccountId":"123456789012"}}
        """;

    internal const string StopLogging = """
        {"version":"0","id":"2","detail-type":"AWS API Call via CloudTrail","source":"aws.cloudtrail","account":"123456789012",
         "time":"2026-07-26T02:10:00Z","region":"ap-southeast-2","resources":[],
         "detail":{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:alice","arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice",
             "sessionContext":{"sessionIssuer":{"type":"Role","userName":"Admin","arn":"arn:aws:iam::123456789012:role/Admin"}}},
           "eventTime":"2026-07-26T02:09:00Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","awsRegion":"ap-southeast-2",
           "sourceIPAddress":"198.51.100.7","requestParameters":{"name":"org-trail"},"responseElements":null,
           "eventID":"4e1d2b9a-0000-4000-8000-000000000002","readOnly":false,"recipientAccountId":"123456789012"}}
        """;

    internal const string SecurityHubEvent = """
        {"version":"0","id":"3","detail-type":"Security Hub Findings - Imported","source":"aws.securityhub","account":"123456789012",
         "time":"2026-07-26T02:10:00Z","region":"ap-southeast-2","resources":[],
         "detail":{"findings":[
           {"Id":"arn:aws:securityhub:ap-southeast-2:123456789012:finding/1","ProductArn":"arn:aws:securityhub:ap-southeast-2::product/aws/securityhub",
            "Title":"S3 general purpose buckets should block public access","AwsAccountId":"123456789012","Region":"ap-southeast-2",
            "UpdatedAt":"2026-07-26T02:00:00Z","Severity":{"Label":"HIGH"},"Compliance":{"Status":"FAILED"}},
           {"Id":"arn:aws:securityhub:ap-southeast-2:123456789012:finding/2","ProductArn":"arn:aws:securityhub:ap-southeast-2::product/aws/securityhub",
            "Title":"CRITICAL finding","AwsAccountId":"123456789012","Region":"ap-southeast-2",
            "UpdatedAt":"2026-07-26T02:00:00Z","Severity":{"Label":"CRITICAL"},"Compliance":{"Status":"FAILED"}}]}}
        """;

    internal const string S3Notification = """
        {"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","awsRegion":"ap-southeast-2","eventName":"ObjectCreated:Put",
          "s3":{"bucket":{"name":"bower-app-logs"},"object":{"key":"logs/2026/07/26/app+logs%3A1.gz","size":1024}}}]}
        """;

    internal const string AuditLogEntry = """
        {"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","status":{},
           "authenticationInfo":{"principalEmail":"alice@example.com"},
           "requestMetadata":{"callerIp":"203.0.113.20","callerSuppliedUserAgent":"gcloud"},
           "serviceName":"iam.googleapis.com","methodName":"google.iam.admin.v1.CreateServiceAccountKey",
           "resourceName":"projects/-/serviceAccounts/123","request":{"privateKeyType":"TYPE_GOOGLE_CREDENTIALS_FILE"}},
         "insertId":"abc123","resource":{"type":"service_account","labels":{"project_id":"bower-prod"}},
         "timestamp":"2026-07-26T02:09:00Z","severity":"NOTICE","logName":"projects/bower-prod/logs/cloudaudit.googleapis.com%2Factivity",
         "receiveTimestamp":"2026-07-26T02:09:01Z"}
        """;

    internal const string SccNotification = """
        {"notificationConfigName":"organizations/1/notificationConfigs/bower",
         "finding":{"name":"organizations/1/sources/2/findings/f1","parent":"organizations/1/sources/2",
           "resourceName":"//compute.googleapis.com/projects/bower-prod/zones/australia-southeast1-a/instances/vm1",
           "state":"ACTIVE","category":"OPEN_FIREWALL","severity":"HIGH","findingClass":"MISCONFIGURATION","mute":"UNMUTED",
           "eventTime":"2026-07-26T02:00:00Z","createTime":"2026-07-26T01:59:00Z","sourceProperties":{"secret":"do-not-forward"}},
         "resource":{"name":"//compute.googleapis.com/projects/bower-prod/zones/australia-southeast1-a/instances/vm1",
           "projectDisplayName":"bower-prod","type":"google.compute.Instance"}}
        """;

    private static readonly string[] SubscriptionFilters = ["bower"];

    private static readonly AwsQueueOptions QueueOptions = new()
    {
        SourceId = "aws:123456789012:ap-southeast-2",
        AccountId = "123456789012",
        Region = "ap-southeast-2"
    };

    [Fact]
    public void Aws_GuardDutyEventBridgeEvent_MapsWithoutRawRecord()
    {
        AwsQueueMessage message = new AwsQueueMessageParser(QueueOptions).Parse(GuardDutyEvent, TestEvents.Now);

        SecurityEventEnvelope envelope = Assert.Single(message.Events);
        Assert.Equal(AwsQueueMessageKind.Events, message.Kind);
        Assert.Equal("aws_guardduty", envelope.EventType);
        Assert.Equal(EventSeverity.High, envelope.EventSeverity);
        Assert.StartsWith("aws-", envelope.EventId, StringComparison.Ordinal);
        Assert.Null(envelope.Attributes);
        Assert.DoesNotContain("never-forward-this", JsonSerializer.Serialize(envelope, BowerJson.Options), StringComparison.Ordinal);
    }

    [Fact]
    public void Aws_RootConsoleLoginFailure_IsAuthenticationFailureByRoot()
    {
        SecurityEventEnvelope envelope = Assert.Single(
            new AwsQueueMessageParser(QueueOptions).Parse(RootConsoleLoginFailure, TestEvents.Now).Events);

        Assert.Equal(SecurityEventCategories.Authentication, envelope.EventCategory);
        Assert.Equal("ConsoleLogin", envelope.EventAction);
        Assert.Equal(EventResult.Failure, envelope.EventResult);
        Assert.Equal("root", envelope.Actor!.Username);
        Assert.Equal(ActorType.Human, envelope.Actor.Type);
        Assert.Equal("Root", envelope.Labels!["aws.identityType"]);
        Assert.Equal("No", envelope.Labels["aws.mfaUsed"]);
        Assert.Equal("203.0.113.10", envelope.Source!.IpAddress);
    }

    [Fact]
    public void Aws_AssumedRoleUsesSessionIssuerAndArn()
    {
        SecurityEventEnvelope envelope = Assert.Single(
            new AwsQueueMessageParser(QueueOptions).Parse(StopLogging, TestEvents.Now).Events);

        Assert.Equal("StopLogging", envelope.EventAction);
        Assert.Equal("Admin", envelope.Actor!.Username);
        Assert.Equal("arn:aws:sts::123456789012:assumed-role/Admin/alice", envelope.Actor.UserId);
        Assert.Equal(EventResult.Success, envelope.EventResult);
    }

    [Fact]
    public void Aws_SnsWrappedSecurityHubBatch_ExpandsFindings()
    {
        string sns = JsonSerializer.Serialize(new { Type = "Notification", MessageId = "m1", Message = SecurityHubEvent });

        AwsQueueMessage message = new AwsQueueMessageParser(QueueOptions).Parse(sns, TestEvents.Now);

        Assert.Equal(2, message.Events.Count);
        Assert.All(message.Events, item => Assert.Equal("aws_security_hub", item.EventType));
        Assert.Equal(EventSeverity.Critical, message.Events[1].EventSeverity);
    }

    [Fact]
    public void Aws_LongTitlesAreClippedToSchemaLimits()
    {
        string json = SecurityHubEvent.Replace(
            "\"Title\":\"CRITICAL finding\"",
            $"\"Title\":\"{new string('x', 400)}\"",
            StringComparison.Ordinal);

        AwsQueueMessage message = new AwsQueueMessageParser(QueueOptions).Parse(json, TestEvents.Now);

        Assert.Equal(128, message.Events[1].EventAction.Length);
    }

    [Fact]
    public void Aws_RedeliveryProducesSameEventIds()
    {
        AwsQueueMessageParser parser = new(QueueOptions);

        string first = parser.Parse(StopLogging, TestEvents.Now).Events[0].EventId;
        string second = parser.Parse(StopLogging, TestEvents.Now.AddHours(1)).Events[0].EventId;

        Assert.Equal(first, second);
    }

    [Fact]
    public void Aws_S3Notification_ReturnsDecodedObjectReference()
    {
        AwsQueueMessage message = new AwsQueueMessageParser(QueueOptions).Parse(S3Notification, TestEvents.Now);

        AwsS3ObjectReference reference = Assert.Single(message.Objects);
        Assert.Equal("bower-app-logs", reference.Bucket);
        Assert.Equal("logs/2026/07/26/app logs:1.gz", reference.Key);
    }

    [Theory]
    [InlineData("""{"Event":"s3:TestEvent","Bucket":"b"}""")]
    [InlineData("""{"detail-type":"EC2 Instance State-change Notification","detail":{}}""")]
    [InlineData("""{"hello":"world"}""")]
    public void Aws_UnknownShapesAreUnsupported(string body)
    {
        AwsQueueMessage message = new AwsQueueMessageParser(QueueOptions).Parse(body, TestEvents.Now);

        Assert.Equal(AwsQueueMessageKind.Unsupported, message.Kind);
        Assert.Empty(message.Events);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1,2]")]
    [InlineData("""{"detail-type":"GuardDuty Finding","detail":"oops"}""")]
    [InlineData("""{"detail-type":"Security Hub Findings - Imported","detail":{"findings":"oops"}}""")]
    [InlineData("""{"Type":"Notification","Message":"not json"}""")]
    public void Aws_MalformedMessagesThrowTypedErrors(string body)
    {
        Assert.Throws<AwsTelemetryMalformedRecordException>(
            () => new AwsQueueMessageParser(QueueOptions).Parse(body, TestEvents.Now));
    }

    [Fact]
    public void Aws_OversizedMessageIsRejected()
    {
        AwsQueueMessageParser parser = new(QueueOptions with { MaximumMessageBytes = 1024 });

        Assert.Throws<AwsTelemetryPayloadTooLargeException>(
            () => parser.Parse(GuardDutyEvent + new string(' ', 2048), TestEvents.Now));
    }

    [Fact]
    public void Aws_ConfigurationHashComesFromOptionsNotRecord()
    {
        AwsQueueMessageParser parser = new(QueueOptions);

        string first = parser.Parse(StopLogging, TestEvents.Now).Events[0].Collector!.ConfigurationHash!;
        string second = parser.Parse(RootConsoleLoginFailure, TestEvents.Now).Events[0].Collector!.ConfigurationHash!;
        string guardDuty = parser.Parse(GuardDutyEvent, TestEvents.Now).Events[0].Collector!.ConfigurationHash!;

        Assert.Equal(first, second);
        Assert.NotEqual(first, guardDuty);
        Assert.Equal(16, first.Length);
    }

    [Fact]
    public void Firehose_GzipConcatenatedPayloads_YieldOnlyEnvelopes()
    {
        string envelope = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(TestEvents.Now, "app-1"), BowerJson.Options);
        string lambdaJson = JsonSerializer.Serialize(new { timestamp = "t", level = "INFO", message = JsonDocument.Parse(envelope).RootElement });
        string first = Subscription("DATA_MESSAGE", envelope, "plain log line", $"2026-07-26T02:00:00Z\treq-1\tINFO\t{envelope}");
        string control = Subscription("CONTROL_MESSAGE", "CWL CONTROL MESSAGE: Checking health of destination Firehose.");
        string second = Subscription("DATA_MESSAGE", lambdaJson);
        byte[] content = [.. Gzip(first), .. Gzip(control), .. Gzip(second)];

        FirehoseLogObject result = FirehoseLogObjectReader.Read(
            new MemoryStream(content),
            new FirehoseLogObjectOptions { SourceId = "test" });

        Assert.Equal(3, result.Envelopes.Count);
        Assert.Equal(1, result.Skipped);
        Assert.All(result.Envelopes, item => Assert.Contains("\"eventId\":\"app-1\"", item, StringComparison.Ordinal));
    }

    [Fact]
    public void Firehose_DecompressedLines_AreRead()
    {
        string envelope = JsonSerializer.Serialize(TestEvents.AuthenticationFailure(TestEvents.Now, "line-1"), BowerJson.Options);
        byte[] content = Encoding.UTF8.GetBytes($"START RequestId: 1\n{envelope}\nEND RequestId: 1\n");

        FirehoseLogObject result = FirehoseLogObjectReader.Read(
            new MemoryStream(content),
            new FirehoseLogObjectOptions { SourceId = "test" });

        Assert.Single(result.Envelopes);
        Assert.Equal(2, result.Skipped);
    }

    [Fact]
    public void Firehose_DecompressionIsBounded()
    {
        byte[] bomb = Gzip(new string('a', 4 * 1024 * 1024));

        Assert.Throws<AwsTelemetryPayloadTooLargeException>(() => FirehoseLogObjectReader.Read(
            new MemoryStream(bomb),
            new FirehoseLogObjectOptions { SourceId = "test", MaximumDecompressedBytes = 1024 * 1024 }));
    }

    [Fact]
    public void Gcp_AuditLog_MapsAdminActivity()
    {
        GcpMappedMessage mapped = Gcp().Map(Encoding.UTF8.GetBytes(AuditLogEntry), TestEvents.Now);

        SecurityEventEnvelope envelope = mapped.Event!;
        Assert.Equal(GcpEventTypes.CloudAudit, envelope.EventType);
        Assert.Equal("google.iam.admin.v1.CreateServiceAccountKey", envelope.EventAction);
        Assert.Equal(EventResult.Success, envelope.EventResult);
        Assert.Equal("alice@example.com", envelope.Actor!.Username);
        Assert.Equal(ActorType.Human, envelope.Actor.Type);
        Assert.Equal("203.0.113.20", envelope.Source!.IpAddress);
        Assert.Equal("bower-prod", envelope.Application.TenantId);
        Assert.Equal("activity", envelope.Labels!["gcp.auditLog"]);
        Assert.StartsWith("gcp-", envelope.EventId, StringComparison.Ordinal);
        Assert.Null(envelope.Attributes);
    }

    [Theory]
    [InlineData(7, EventResult.Denied)]
    [InlineData(16, EventResult.Denied)]
    [InlineData(3, EventResult.Failure)]
    public void Gcp_AuditStatusMapsResult(int code, EventResult expected)
    {
        string json = AuditLogEntry.Replace("\"status\":{}", $"\"status\":{{\"code\":{code},\"message\":\"nope\"}}", StringComparison.Ordinal);

        SecurityEventEnvelope envelope = Gcp().Map(Encoding.UTF8.GetBytes(json), TestEvents.Now).Event!;

        Assert.Equal(expected, envelope.EventResult);
        Assert.Equal("nope", envelope.EventOutcomeReason);
    }

    [Fact]
    public void Gcp_InternalCallerIpIsLabelNotAddress()
    {
        string json = AuditLogEntry
            .Replace("203.0.113.20", "private", StringComparison.Ordinal)
            .Replace("alice@example.com", "deployer@bower-prod.iam.gserviceaccount.com", StringComparison.Ordinal);

        SecurityEventEnvelope envelope = Gcp().Map(Encoding.UTF8.GetBytes(json), TestEvents.Now).Event!;

        Assert.Null(envelope.Source);
        Assert.Equal("private", envelope.Labels!["gcp.callerIp"]);
        Assert.Equal(ActorType.Service, envelope.Actor!.Type);
    }

    [Fact]
    public void Gcp_SccFinding_MapsSeverityAndState()
    {
        SecurityEventEnvelope envelope = Gcp().Map(Encoding.UTF8.GetBytes(SccNotification), TestEvents.Now).Event!;

        Assert.Equal(GcpEventTypes.SccFinding, envelope.EventType);
        Assert.Equal("OPEN_FIREWALL", envelope.EventAction);
        Assert.Equal(EventSeverity.High, envelope.EventSeverity);
        Assert.Equal(EventResult.Failure, envelope.EventResult);
        Assert.Equal("bower-prod", envelope.Application.TenantId);
        Assert.DoesNotContain("do-not-forward", JsonSerializer.Serialize(envelope, BowerJson.Options), StringComparison.Ordinal);
    }

    [Fact]
    public void Gcp_FindingStateChangeIsANewEvent()
    {
        GcpSecurityEventMapper mapper = Gcp();
        string inactive = SccNotification.Replace("\"ACTIVE\"", "\"INACTIVE\"", StringComparison.Ordinal);

        string active = mapper.Map(Encoding.UTF8.GetBytes(SccNotification), TestEvents.Now).Event!.EventId;
        string again = mapper.Map(Encoding.UTF8.GetBytes(SccNotification), TestEvents.Now.AddMinutes(5)).Event!.EventId;
        string resolved = mapper.Map(Encoding.UTF8.GetBytes(inactive), TestEvents.Now).Event!.EventId;

        Assert.Equal(active, again);
        Assert.NotEqual(active, resolved);
    }

    [Theory]
    [InlineData("""{"textPayload":"hello","insertId":"x"}""")]
    [InlineData("""{"protoPayload":{"@type":"type.googleapis.com/google.cloud.bigquery.logging.v1.AuditData"}}""")]
    public void Gcp_UnknownPayloadsAreUnsupported(string json)
    {
        GcpMappedMessage mapped = Gcp().Map(Encoding.UTF8.GetBytes(json), TestEvents.Now);

        Assert.Null(mapped.Event);
        Assert.NotNull(mapped.UnsupportedReason);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("""{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog"}}""")]
    [InlineData("""{"finding":{"category":"X"}}""")]
    public void Gcp_MalformedMessagesThrowTypedErrors(string json)
    {
        Assert.Throws<GcpTelemetryMalformedException>(() => Gcp().Map(Encoding.UTF8.GetBytes(json), TestEvents.Now));
    }

    [Fact]
    public void Gcp_OversizedMessageIsRejected()
    {
        GcpSecurityEventMapper mapper = new(new GcpSourceOptions { SourceId = "gcp:test", MaximumMessageBytes = 1024 });

        Assert.Throws<GcpTelemetryPayloadTooLargeException>(
            () => mapper.Map(Encoding.UTF8.GetBytes(AuditLogEntry + new string(' ', 2048)), TestEvents.Now));
    }

    private static GcpSecurityEventMapper Gcp() => new(new GcpSourceOptions { SourceId = "gcp:bower-prod" });

    private static string Subscription(string type, params string[] messages) =>
        JsonSerializer.Serialize(new
        {
            messageType = type,
            owner = "123456789012",
            logGroup = "/aws/lambda/app",
            logStream = "stream",
            subscriptionFilters = SubscriptionFilters,
            logEvents = messages.Select((message, index) => new { id = index.ToString(System.Globalization.CultureInfo.InvariantCulture), timestamp = 1, message })
        });

    private static byte[] Gzip(string text)
    {
        using MemoryStream output = new();
        using (GZipStream gzip = new(output, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(text));
        }

        return output.ToArray();
    }
}

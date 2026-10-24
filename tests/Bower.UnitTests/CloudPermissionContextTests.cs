using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Ingestion;
using Bower.Abstractions;
using Bower.Contracts;
using Bower.Core;
using Bower.Dcr;
using Bower.Output.AzureLogsIngestion;
using Bower.Persistence;
using Bower.PolicyEngine;
using Bower.Redaction.Privacy;
using Bower.Source.Aws;
using Bower.Source.Gcp;

namespace Bower.UnitTests;

public sealed class CloudPermissionContextTests
{
    private const string Canary = "unapproved-canary";
    private const string KeyCanary = "AKIAIOSFODNN7EXAMPLE";
    private const string LongPolicy = "arn:aws:iam::123456789012:policy/";

    [Theory]
    [InlineData("AttachUserPolicy", "userName", "user", "grant")]
    [InlineData("DetachUserPolicy", "userName", "user", "revoke")]
    [InlineData("AttachRolePolicy", "roleName", "role", "grant")]
    [InlineData("DetachRolePolicy", "roleName", "role", "revoke")]
    [InlineData("AttachGroupPolicy", "groupName", "group", "grant")]
    [InlineData("DetachGroupPolicy", "groupName", "group", "revoke")]
    public void AwsPolicyAttachmentPreservesSubjectAndLongPolicy(string action, string nameKey, string kind, string direction)
    {
        string policy = LongPolicy + new string('p', 500) + "/" + new string('n', 128);
        SecurityEventEnvelope mapped = Aws(action, new JsonObject { [nameKey] = "security-operators", ["policyArn"] = policy, ["password"] = Canary });
        SecurityEventEnvelope safe = Redact(mapped);
        Assert.Equal("security-operators", safe.Target!.Name);
        Assert.Equal($"aws-iam-{kind}", safe.Target.Type);
        Assert.Equal(direction, safe.Change!.NewValue);
        JsonElement entry = Assert.Single(Context(safe).GetProperty("entries").EnumerateArray());
        Assert.Equal("security-operators", entry.GetProperty("member").GetString());
        Assert.Equal(policy, entry.GetProperty("permission").GetString());
        Assert.Equal(direction, entry.GetProperty("direction").GetString());
        Assert.Equal("operator", safe.Actor!.Username);
        Assert.DoesNotContain(Canary, JsonSerializer.Serialize(safe, BowerJson.Envelope), StringComparison.Ordinal);
        Assert.False(safe.Attributes!.ContainsKey("aws.raw"));
    }

    [Theory]
    [InlineData("AddUserToGroup", "grant")]
    [InlineData("RemoveUserFromGroup", "revoke")]
    public void AwsGroupMembershipSeparatesActorMemberAndGroup(string action, string direction)
    {
        SecurityEventEnvelope safe = Redact(Aws(action, new JsonObject { ["userName"] = "affected-user", ["groupName"] = "Administrators" }));
        Assert.Equal("operator", safe.Actor!.Username);
        Assert.Equal("Administrators", safe.Target!.Name);
        JsonElement entry = Context(safe).GetProperty("entries")[0];
        Assert.Equal("affected-user", entry.GetProperty("member").GetString());
        Assert.Equal("Administrators", entry.GetProperty("permission").GetString());
        Assert.Equal(direction, safe.Change!.NewValue);
    }

    [Theory]
    [InlineData("object")]
    [InlineData("json")]
    [InlineData("encoded")]
    public void AwsTrustReplacementExtractsMultiplePrincipalsWithoutConditionsOrInventedRevocations(string shape)
    {
        JsonObject policy = TrustPolicy();
        JsonNode document = shape switch
        {
            "json" => JsonValue.Create(policy.ToJsonString())!,
            "encoded" => JsonValue.Create(Uri.EscapeDataString(policy.ToJsonString()))!,
            _ => policy
        };
        SecurityEventEnvelope safe = Redact(Aws("UpdateAssumeRolePolicy", new JsonObject { ["roleName"] = "ProductionDeploy", ["policyDocument"] = document }));
        Assert.Equal("ProductionDeploy", safe.Target!.Name);
        Assert.Equal("replace", safe.Change!.NewValue);
        JsonElement context = Context(safe);
        Assert.Equal("replacement", context.GetProperty("mode").GetString());
        JsonElement[] entries = context.GetProperty("entries").EnumerateArray().ToArray();
        Assert.Equal(3, entries.Length);
        Assert.Equal("arn:aws:iam::123456789012:role/" + new string('a', 450) + "/Deploy", entries[0].GetProperty("member").GetString());
        Assert.Equal("ec2.amazonaws.com", entries[1].GetProperty("member").GetString());
        Assert.Equal("Deny", entries[2].GetProperty("effect").GetString());
        Assert.All(entries, entry => Assert.Equal("present", entry.GetProperty("direction").GetString()));
        Assert.True(entries[0].GetProperty("conditionPresent").GetBoolean());
        Assert.DoesNotContain(Canary, context.GetRawText(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("serviceData")]
    [InlineData("metadata")]
    public void GcpDeltasPreserveLongPrincipalsTargetsRolesAndMixedDirections(string location)
    {
        string member = LongGcpMember();
        string role = "organizations/123456789012/roles/" + new string('r', 64);
        string target = "projects/bower-prod/topics/" + new string('p', 255);
        JsonArray deltas = [Delta("ADD", member, role), Delta("REMOVE", "allAuthenticatedUsers", "roles/owner")];
        SecurityEventEnvelope safe = Redact(Gcp(deltas, location, target));
        JsonElement context = Context(safe);
        Assert.Equal("mixed", safe.Change!.NewValue);
        Assert.Equal(target, context.GetProperty("target").GetString());
        Assert.True(context.GetProperty("targetNameTruncated").GetBoolean());
        Assert.Equal(256, safe.Target!.Name!.Length);
        JsonElement entries = context.GetProperty("entries");
        Assert.Equal(2, entries.GetArrayLength());
        Assert.Equal(member, entries[0].GetProperty("member").GetString());
        Assert.Equal(role, entries[0].GetProperty("permission").GetString());
        Assert.Equal("grant", entries[0].GetProperty("direction").GetString());
        Assert.Equal("revoke", entries[1].GetProperty("direction").GetString());
        Assert.DoesNotContain(Canary, context.GetRawText(), StringComparison.Ordinal);
        Assert.False(safe.Attributes!.ContainsKey("gcp.raw"));
    }

    [Fact]
    public void GcpReplacementIsASnapshotNotAGrantAndMissingDeltaIsExplicit()
    {
        JsonObject payload = GcpPayload();
        payload["request"] = JsonNode.Parse("""{"policy":{"bindings":[{"role":"roles/viewer","members":["allUsers","allAuthenticatedUsers"],"condition":{"expression":"unapproved-canary"}},{"role":"roles/editor","members":["allAuthenticatedUsers"]}],"etag":"unapproved-canary"}}""");
        SecurityEventEnvelope safe = Redact(MapGcp(payload));
        Assert.Equal("replace", safe.Change!.NewValue);
        Assert.Equal("replacement", Context(safe).GetProperty("mode").GetString());
        Assert.Equal(3, Context(safe).GetProperty("entries").GetArrayLength());
        Assert.Equal("present", Context(safe).GetProperty("entries")[0].GetProperty("direction").GetString());
        Assert.Equal("roles/editor", Context(safe).GetProperty("entries")[2].GetProperty("permission").GetString());
        Assert.DoesNotContain(Canary, Context(safe).GetRawText(), StringComparison.Ordinal);
        safe = Redact(MapGcp(GcpPayload()));
        Assert.Equal("unknown", safe.Change!.NewValue);
        Assert.Equal("unavailable", Context(safe).GetProperty("mode").GetString());
    }

    [Theory]
    [InlineData("ADD", "grant")]
    [InlineData("REMOVE", "revoke")]
    public void GcpEmailPrivacyRemainsConfiguredAndFailedRequestsStayFailed(string action, string direction)
    {
        JsonObject payload = GcpPayload();
        payload["status"] = new JsonObject { ["code"] = 7 };
        payload["serviceData"] = new JsonObject { ["policyDelta"] = new JsonObject { ["bindingDeltas"] = new JsonArray(Delta(action, "user:changed@example.test", "roles/viewer")) } };
        SecurityEventEnvelope mapped = MapGcp(payload);
        SecurityEventEnvelope safe = Redact(mapped);
        Assert.Equal(EventResult.Denied, safe.EventResult);
        Assert.Equal(direction, safe.Change!.NewValue);
        Assert.DoesNotContain("changed@example.test", Context(safe).GetRawText(), StringComparison.Ordinal);
        // Tenants can retain identities explicitly; secret detectors remain active.
        PrivacyPolicy defaults = PrivacyPolicy.CreateDefault();
        PrivacyEngine retainEmail = new(new PrivacyPolicy
        {
            DetectorActions = new Dictionary<string, PrivacyAction>(defaults.DetectorActions) { [DetectorIds.Email] = PrivacyAction.Allow }
        });
        safe = Redact(mapped, retainEmail);
        Assert.Equal("user:changed@example.test", Context(safe).GetProperty("entries")[0].GetProperty("member").GetString());
    }

    [Fact]
    public void KnownSecretsInsideApprovedIdentifiersStillGetRedacted()
    {
        SecurityEventEnvelope aws = Redact(Aws("AttachUserPolicy", new JsonObject { ["userName"] = "operator", ["policyArn"] = LongPolicy + KeyCanary }));
        SecurityEventEnvelope gcp = Redact(Gcp([Delta("ADD", "principal://example/" + KeyCanary, "roles/viewer")]));
        Assert.DoesNotContain(KeyCanary, JsonSerializer.Serialize(aws, BowerJson.Envelope), StringComparison.Ordinal);
        Assert.DoesNotContain(KeyCanary, JsonSerializer.Serialize(gcp, BowerJson.Envelope), StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownActionsAndServicesDoNotProjectPermissionParameters()
    {
        SecurityEventEnvelope envelope = Aws("ListUsers", new JsonObject { ["userName"] = Canary });
        Assert.Null(envelope.Change);
        Assert.Null(envelope.Attributes);
        envelope = Aws("AttachUserPolicy", new JsonObject { ["userName"] = Canary }, "other.amazonaws.com");
        Assert.Null(envelope.Change);
        Assert.Null(envelope.Attributes);
        JsonObject payload = GcpPayload();
        payload["methodName"] = "GetIamPolicy";
        payload["serviceData"] = new JsonObject { ["policyDelta"] = new JsonObject { ["bindingDeltas"] = new JsonArray(Delta("ADD", Canary, "roles/viewer")) } };
        Assert.Null(MapGcp(payload).Attributes);
    }

    [Theory]
    [InlineData("google.iam.v1.IAMPolicy.SetIamPolicy")]
    [InlineData("google.pubsub.v1.Publisher.SetIamPolicy")]
    [InlineData("google.cloud.resourcemanager.v3.Projects.setIamPolicy")]
    public void GcpDeltaWinsOverReplacementWithoutCopyingUnknownFields(string method)
    {
        JsonObject payload = GcpPayload();
        payload["methodName"] = method;
        payload["serviceData"] = new JsonObject { ["policyDelta"] = new JsonObject { ["bindingDeltas"] = new JsonArray(Delta("REMOVE", "allUsers", "roles/owner")) } };
        payload["request"] = new JsonObject { ["policy"] = new JsonObject { ["bindings"] = Canary } };
        SecurityEventEnvelope safe = Redact(MapGcp(payload));
        Assert.Equal("revoke", safe.Change!.NewValue);
        Assert.Equal("delta", Context(safe).GetProperty("mode").GetString());
        Assert.DoesNotContain(Canary, JsonSerializer.Serialize(safe, BowerJson.Envelope), StringComparison.Ordinal);
    }

    [Fact]
    public void AwsTrustCrossProductIsBoundedAndMissingContextIsExplicit()
    {
        JsonObject policy = TrustPolicy();
        policy["Statement"]![0]!["Action"] = new JsonArray("sts:AssumeRole", "sts:TagSession");
        SecurityEventEnvelope mapped = Aws("UpdateAssumeRolePolicy", new JsonObject { ["roleName"] = "Deploy", ["policyDocument"] = policy });
        Assert.Equal(5, Context(mapped).GetProperty("entries").GetArrayLength());
        Assert.Equal("sts:TagSession", Context(mapped).GetProperty("entries")[1].GetProperty("permission").GetString());
        policy = TrustPolicy();
        policy["Statement"]![0]!["Action"] = new JsonArray(Enumerable.Range(0, 33).Select(_ => (JsonNode)JsonValue.Create("sts:AssumeRole")!).ToArray());
        Assert.Throws<AwsTelemetryPermissionContextException>(() => Aws("UpdateAssumeRolePolicy", new JsonObject { ["roleName"] = "Deploy", ["policyDocument"] = policy }));
        mapped = Redact(Aws("UpdateAssumeRolePolicy", new JsonObject { ["roleName"] = "Deploy" }));
        Assert.Equal("Deploy", mapped.Target!.Name);
        Assert.Equal("unknown", mapped.Change!.NewValue);
        Assert.Equal("unavailable", Context(mapped).GetProperty("mode").GetString());
    }

    [Fact]
    public void LimitsRejectWholeContextWithoutTruncatingEntriesOrIdentifiers()
    {
        Assert.Throws<AwsTelemetryPermissionContextException>(() => Aws("AttachUserPolicy", new JsonObject { ["userName"] = "alice", ["policyArn"] = new string('a', 2049) }));
        Assert.Throws<GcpTelemetryMalformedException>(() => Gcp([Delta("ADD", new string('a', 2049), "roles/viewer")]));
        Assert.Throws<GcpTelemetryMalformedException>(() => Gcp(new JsonArray(Enumerable.Range(0, 65).Select(_ => (JsonNode)Delta("ADD", "allUsers", "roles/viewer")).ToArray())));
        Assert.Throws<GcpTelemetryMalformedException>(() => Gcp(new JsonArray(Enumerable.Range(0, 64).Select(_ => (JsonNode)Delta("ADD", new string('a', 1024), "roles/viewer")).ToArray())));
        JsonObject policy = TrustPolicy();
        policy["Statement"]![0]!["Principal"]!["AWS"] = new JsonArray(Enumerable.Range(0, 65).Select(_ => (JsonNode)JsonValue.Create("arn:aws:iam::123456789012:root")!).ToArray());
        Assert.Throws<AwsTelemetryPermissionContextException>(() => Aws("UpdateAssumeRolePolicy", new JsonObject { ["roleName"] = "role", ["policyDocument"] = policy }));
        SecurityEventEnvelope boundary = Gcp(new JsonArray(Enumerable.Range(0, 64).Select(_ => (JsonNode)Delta("ADD", "allUsers", "roles/viewer")).ToArray()));
        Assert.Equal(64, Context(boundary).GetProperty("entries").GetArrayLength());
        boundary = Gcp([Delta("ADD", new string('a', 2048), "roles/viewer")]);
        Assert.Equal(2048, Context(boundary).GetProperty("entries")[0].GetProperty("member").GetString()!.Length);
    }

    [Theory]
    [InlineData("{\"action\":\"BOGUS\",\"member\":\"allUsers\",\"role\":\"roles/viewer\"}")]
    [InlineData("{\"action\":\"ADD\",\"member\":{},\"role\":\"roles/viewer\"}")]
    [InlineData("{\"action\":\"ADD\",\"member\":\"allUsers\"}")]
    [InlineData("null")]
    public void MalformedBindingFailsWithNoPayloadInError(string delta)
    {
        GcpTelemetryMalformedException error = Assert.Throws<GcpTelemetryMalformedException>(() => Gcp(new JsonArray(JsonNode.Parse(delta))));
        Assert.DoesNotContain("allUsers", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PermissionContextSurvivesSqliteReopenAndCapturedAzureProjection()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string database = Path.Combine(directory.Path, "queue.db");
        FakeClock clock = new(TestEvents.Now);
        SqliteEventStore store = new(database, 10 * 1024 * 1024, clock);
        await store.InitializeAsync(cancellationToken);
        LoadedPolicy basePolicy = TestEvents.AuthenticationPolicy();
        LoadedPolicy policy = basePolicy with
        {
            Policy = basePolicy.Policy with
            {
                // Revokes need a test-only policy until the parent updates selection assets.
                Match = new PolicyMatch { EventTypes = ["aws_cloudtrail"], EventActions = ["DetachUserPolicy"] },
                Requirements = new PolicyRequirements { RequiredFields = ["target.name", "change.newValue"] },
                Decision = new PolicyAction { Action = "accept", MinimumValueScore = 0 }
            }
        };
        SecurityEventProcessor processor = new(new PrivacyEngine(), new DeterministicPolicyEvaluator(
        [
            .. PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "packs", "aws-security", "policies")),
            .. PolicyLoader.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "packs", "gcp-security", "policies")),
            policy
        ]), store, clock);
        SecurityEventEnvelope[] candidates =
        [
            Aws("AttachUserPolicy", new JsonObject { ["userName"] = "affected-user", ["policyArn"] = LongPolicy + new string('p', 500) + "/ReadSecurity", ["password"] = Canary }),
            Aws("AddUserToGroup", new JsonObject { ["userName"] = "affected-user", ["groupName"] = "Administrators" }),
            Aws("UpdateAssumeRolePolicy", new JsonObject { ["roleName"] = "ProductionDeploy", ["policyDocument"] = TrustPolicy() }),
            Gcp([Delta("ADD", LongGcpMember(), "roles/viewer"), Delta("REMOVE", "allUsers", "roles/owner")],
                target: "projects/bower-prod/topics/" + new string('p', 255)),
            Aws("DetachUserPolicy", new JsonObject { ["userName"] = "affected-user", ["policyArn"] = LongPolicy + KeyCanary })
        ];
        Dictionary<string, string> expected = candidates.ToDictionary(item => item.EventId, item => Context(Redact(item)).GetRawText());
        foreach (SecurityEventEnvelope candidate in candidates)
        {
            ProcessingResult result = await processor.ProcessAsync(JsonSerializer.Serialize(candidate, BowerJson.Envelope),
                new CollectorIdentity("collector", "test", "test", "sha256:test"), cancellationToken);
            Assert.True(result.Queued, string.Join("; ", result.Reasons));
        }

        SqliteEventStore reopened = new(database, 10 * 1024 * 1024, clock);
        await reopened.InitializeAsync(cancellationToken);
        IReadOnlyList<QueuedEvent> batch = await reopened.LeaseAsync(10, TimeSpan.FromMinutes(1), cancellationToken);
        Assert.Equal(candidates.Length, batch.Count);
        foreach (QueuedEvent item in batch)
        {
            SecurityEventEnvelope saved = JsonSerializer.Deserialize(item.Payload, BowerJson.Envelope)!;
            Assert.Equal(expected[item.EventId], Context(saved).GetRawText());
            Assert.NotNull(saved.Change!.NewValue);
            Assert.DoesNotContain(Canary, item.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain(KeyCanary, item.Payload, StringComparison.Ordinal);
            Assert.Empty(IngestionPreflight.Check(Encoding.UTF8.GetBytes(item.Payload), SentinelSchema.Default));
        }

        foreach (string file in Directory.GetFiles(directory.Path, "queue.db*"))
        {
            string bytes = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(file, cancellationToken));
            Assert.DoesNotContain(Canary, bytes, StringComparison.Ordinal);
            Assert.DoesNotContain(KeyCanary, bytes, StringComparison.Ordinal);
        }

        CaptureHandler capture = new();
        AzureLogsIngestionOutput output = new(new AzureLogsIngestionOptions
        {
            Id = "test",
            Endpoint = new Uri("https://simulated.ingest.monitor.azure.com"),
            DcrImmutableId = "dcr-test",
            StreamName = "Custom-BowerSecurity"
        }, new FakeCredential(), new LogsIngestionClientOptions
        {
            Transport = new HttpClientTransport(new HttpClient(capture)),
            Retry = { MaxRetries = 0 }
        });
        DeliveryResult delivered = await output.DeliverAsync(batch, cancellationToken);
        Assert.Equal(candidates.Length, delivered.AcknowledgedEventIds.Count);
        Assert.NotEmpty(capture.Bodies);
        foreach (string body in capture.Bodies)
        {
            Assert.DoesNotContain(Canary, body, StringComparison.Ordinal);
            Assert.DoesNotContain(KeyCanary, body, StringComparison.Ordinal);
            using JsonDocument document = JsonDocument.Parse(body);
            foreach (JsonElement row in document.RootElement.EnumerateArray())
            {
                Assert.Equal(expected[row.GetProperty("eventId").GetString()!], row.GetProperty("attributes").GetProperty("cloud.permissionChanges").GetRawText());
                Assert.True(row.TryGetProperty("target", out _));
                Assert.True(row.TryGetProperty("change", out _));
            }
        }

        Assert.Contains(SentinelSchema.Default.TableColumns, column => column.Name == "Attributes" && column.Expression == "attributes");
    }

    private static JsonElement Context(SecurityEventEnvelope envelope) => envelope.Attributes!["cloud.permissionChanges"];

    private static SecurityEventEnvelope Redact(SecurityEventEnvelope envelope, PrivacyEngine? engine = null)
    {
        PrivacyScanResult scan = (engine ?? new PrivacyEngine()).RedactJson(JsonSerializer.Serialize(envelope, BowerJson.Envelope));
        Assert.True(scan.Succeeded);
        return JsonSerializer.Deserialize(scan.RedactedJson!, BowerJson.Envelope)!;
    }

    private static SecurityEventEnvelope Aws(string action, JsonObject request, string service = "iam.amazonaws.com")
    {
        JsonObject record = new()
        {
            ["eventID"] = action,
            ["eventTime"] = TestEvents.Now.ToString("O"),
            ["eventName"] = action,
            ["eventSource"] = service,
            ["recipientAccountId"] = "123456789012",
            ["userIdentity"] = new JsonObject { ["type"] = "IAMUser", ["userName"] = "operator" },
            ["requestParameters"] = request
        };
        return Assert.Single(new AwsSecurityEventMapper(new AwsSourceOptions { SourceId = "aws:test", Kind = AwsTelemetrySourceKind.CloudTrail }).MapJsonDocument(record.ToJsonString(), TestEvents.Now));
    }

    private static JsonObject TrustPolicy() => JsonNode.Parse("""
        {"Version":"2012-10-17","Statement":[
          {"Effect":"Allow","Principal":{"AWS":"LONG_MEMBER","Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole",
           "Condition":{"StringEquals":{"sts:ExternalId":"unapproved-canary"}},"Sid":"unapproved-canary"},
          {"Effect":"Deny","Principal":"*","Action":["sts:AssumeRole"]}]}
        """.Replace("LONG_MEMBER", "arn:aws:iam::123456789012:role/" + new string('a', 450) + "/Deploy", StringComparison.Ordinal))!.AsObject();

    private static JsonObject Delta(string action, string member, string role) => new()
    {
        ["action"] = action,
        ["member"] = member,
        ["role"] = role,
        ["condition"] = new JsonObject { ["expression"] = Canary },
        ["unknown"] = Canary
    };

    private static SecurityEventEnvelope Gcp(JsonArray deltas, string location = "serviceData", string target = "projects/bower-prod")
    {
        JsonObject payload = GcpPayload();
        payload["resourceName"] = target;
        if (target.Contains("/topics/", StringComparison.Ordinal))
        {
            payload["serviceName"] = "pubsub.googleapis.com";
        }
        payload[location] = new JsonObject { ["policyDelta"] = new JsonObject { ["bindingDeltas"] = deltas } };
        return MapGcp(payload);
    }

    private static string LongGcpMember() =>
        "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/"
        + new string('p', 32) + "/subject/" + new string('a', 127);

    private static JsonObject GcpPayload() => new()
    {
        ["@type"] = "type.googleapis.com/google.cloud.audit.AuditLog",
        ["methodName"] = "SetIamPolicy",
        ["serviceName"] = "cloudresourcemanager.googleapis.com",
        ["resourceName"] = "projects/bower-prod",
        ["authenticationInfo"] = new JsonObject { ["principalSubject"] = "operator" }
    };

    private static SecurityEventEnvelope MapGcp(JsonObject payload)
    {
        JsonObject record = new()
        {
            ["protoPayload"] = payload,
            ["insertId"] = "iam-change",
            ["timestamp"] = TestEvents.Now.ToString("O"),
            ["logName"] = "projects/bower-prod/logs/cloudaudit.googleapis.com%2Factivity"
        };
        return new GcpSecurityEventMapper(new GcpSourceOptions { SourceId = "gcp:test" }).Map(Encoding.UTF8.GetBytes(record.ToJsonString()), TestEvents.Now).Event!;
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            if (request.Content.Headers.ContentEncoding.Contains("gzip"))
            {
                using GZipStream gzip = new(new MemoryStream(bytes), CompressionMode.Decompress);
                using MemoryStream plain = new();
                await gzip.CopyToAsync(plain, cancellationToken);
                bytes = plain.ToArray();
            }

            Bodies.Add(Encoding.UTF8.GetString(bytes));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    private sealed class FakeCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => new("synthetic-test-token", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}

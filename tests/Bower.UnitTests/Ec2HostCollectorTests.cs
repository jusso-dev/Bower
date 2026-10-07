using System.Net;
using Bower.Agent.Aws;
using Bower.Contracts;

namespace Bower.UnitTests;

public sealed class Ec2HostCollectorTests
{
    [Fact]
    public void Options_RejectPathTraversal()
    {
        Ec2AgentOptions options = new()
        {
            AgentId = "agent-1",
            Sources = [new HostLogSource("x", HostLogKind.Custom, "../etc/passwd")]
        };

        Assert.Throws<ArgumentException>(options.Validate);
    }

    [Fact]
    public async Task MetadataClient_MapsInjectedImdsValues()
    {
        Ec2MetadataClient client = new(path => path switch
        {
            "instance-id" => Task.FromResult<string?>("i-abc"),
            "identity-account-id" => Task.FromResult<string?>("123456789012"),
            "region" => Task.FromResult<string?>("ap-southeast-2"),
            "availability-zone" => Task.FromResult<string?>("ap-southeast-2a"),
            "vpc-id" => Task.FromResult<string?>("vpc-1"),
            "subnet-id" => Task.FromResult<string?>("subnet-1"),
            "ami-id" => Task.FromResult<string?>("ami-1"),
            "security-groups" => Task.FromResult<string?>("sg-1,sg-2"),
            "tags" => Task.FromResult<string?>("""{"Name":"web","Env":"prod"}"""),
            "auto-scaling-group" => Task.FromResult<string?>("asg-web"),
            "ecs-cluster" => Task.FromResult<string?>("ecs-1"),
            "eks-cluster" => Task.FromResult<string?>("eks-1"),
            _ => Task.FromResult<string?>(null)
        });

        Ec2InstanceMetadata? metadata = await client.GetAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(metadata);
        Assert.Equal("i-abc", metadata.InstanceId);
        Assert.Equal("123456789012", metadata.AccountId);
        Assert.Equal(["sg-1", "sg-2"], metadata.SecurityGroups);
        Assert.Equal("web", metadata.Tags["Name"]);
        Assert.Equal("asg-web", metadata.AutoScalingGroup);
    }

    [Fact]
    public void CollectLines_EnrichesWithMetadataAndMapsAuthFailure()
    {
        Ec2InstanceMetadata metadata = new(
            "i-abc",
            "123456789012",
            "ap-southeast-2",
            "ap-southeast-2a",
            "vpc-1",
            "subnet-1",
            "ami-1",
            ["sg-1"],
            new Dictionary<string, string> { ["Name"] = "web" },
            "asg-web",
            null,
            null);

        Ec2HostCollector collector = new(
            new Ec2AgentOptions
            {
                AgentId = "agent-1",
                Sources = [new HostLogSource("auth", HostLogKind.Auth, "/var/log/auth.log")]
            },
            metadata);

        SecurityEventEnvelope envelope = Assert.Single(
            collector.CollectLines("auth", ["Failed password for root from 203.0.113.10"]));

        Assert.Equal("host_auth", envelope.EventType);
        Assert.Equal(EventResult.Failure, envelope.EventResult);
        Assert.Equal("aws.ec2-agent", envelope.Collector?.SourceAdapter);
        Assert.Equal("i-abc", envelope.Labels?["aws.instanceId"]);
        Assert.Equal("123456789012", envelope.Labels?["aws.accountId"]);
        Assert.Equal("web", envelope.Labels?["aws.tag.Name"]);
        Assert.Equal(SecurityEventCategories.Authentication, envelope.EventCategory);
    }

    [Fact]
    public void DefaultSources_CoverWindowsAndLinux()
    {
        Assert.Contains(Ec2HostCollector.DefaultSourcesForPlatform(windows: true), item => item.Kind == HostLogKind.Sysmon);
        Assert.Contains(Ec2HostCollector.DefaultSourcesForPlatform(windows: false), item => item.Kind == HostLogKind.Auditd);
    }

    [Fact]
    public void CollectLines_KeepsRawLineOutOfLabelsByDefault()
    {
        Ec2HostCollector collector = new(AuthOptions());

        SecurityEventEnvelope envelope = Assert.Single(
            collector.CollectLines("auth", ["Failed password for alice@example.test from 203.0.113.10"]));

        Assert.False(envelope.Labels!.ContainsKey("host.linePreview"));
        Assert.DoesNotContain(envelope.Labels.Values, value => value.Contains("alice", StringComparison.Ordinal));
        Assert.Equal(64, envelope.Labels["host.lineSha256"].Length);
    }

    [Fact]
    public void CollectLines_RedactsOptInPreview()
    {
        Ec2HostCollector collector = new(AuthOptions() with { IncludeRedactedLinePreview = true });

        SecurityEventEnvelope envelope = Assert.Single(
            collector.CollectLines("auth", ["Failed password for alice@example.test"]));

        Assert.Contains("a***@example.test", envelope.Labels!["host.linePreview"], StringComparison.Ordinal);
    }

    [Fact]
    public void CollectLines_ProducesStableIdsWhenSameLinesAreReRead()
    {
        Ec2HostCollector collector = new(AuthOptions());
        string[] lines = ["Accepted publickey for deploy", "Failed password for root"];

        IReadOnlyList<SecurityEventEnvelope> first = collector.CollectLines(
            "auth", lines, TestEvents.Now, firstLineNumber: 40);
        IReadOnlyList<SecurityEventEnvelope> again = collector.CollectLines(
            "auth", lines, TestEvents.Now.AddMinutes(5), firstLineNumber: 40);
        IReadOnlyList<SecurityEventEnvelope> shifted = collector.CollectLines(
            "auth", lines, TestEvents.Now, firstLineNumber: 41);

        Assert.Equal(first.Select(item => item.EventId), again.Select(item => item.EventId));
        Assert.NotEqual(first[0].EventId, shifted[0].EventId);
        Assert.Equal("40", first[0].Labels!["host.lineNumber"]);
    }

    [Fact]
    public void CollectLines_FlagsOversizedLineWithoutFailingBatch()
    {
        Ec2HostCollector collector = new(AuthOptions() with { MaximumLineBytes = 256 });
        string oversized = "Failed password " + new string('x', 1_000);

        IReadOnlyList<SecurityEventEnvelope> events = collector.CollectLines(
            "auth", ["Accepted publickey for deploy", oversized]);

        Assert.Equal(2, events.Count);
        Assert.Equal("true", events[1].Labels!["host.lineTruncated"]);
        Assert.Equal(EventResult.Unknown, events[1].EventResult);
    }

    [Fact]
    public void CollectLines_UsesStableConfigurationHash()
    {
        Ec2HostCollector first = new(AuthOptions());
        Ec2HostCollector second = new(AuthOptions());
        Ec2HostCollector changed = new(AuthOptions() with { Environment = "staging" });

        string hash = first.CollectLines("auth", ["a"])[0].Collector!.ConfigurationHash!;

        Assert.StartsWith("sha256:", hash, StringComparison.Ordinal);
        Assert.Equal(hash, second.CollectLines("auth", ["b"])[0].Collector!.ConfigurationHash);
        Assert.NotEqual(hash, changed.CollectLines("auth", ["a"])[0].Collector!.ConfigurationHash);
    }

    [Fact]
    public async Task ImdsV2Client_UsesSessionTokenAndReadsIdentity()
    {
        FakeImdsHandler handler = new();
        using ImdsV2Client imds = new(new HttpClient(handler) { BaseAddress = ImdsV2Client.DefaultEndpoint });

        Ec2InstanceMetadata? metadata = await Ec2MetadataClient.CreateImdsV2(imds)
            .GetAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(metadata);
        Assert.Equal("i-0abc", metadata.InstanceId);
        Assert.Equal("123456789012", metadata.AccountId);
        Assert.Equal("vpc-9", metadata.VpcId);
        Assert.Equal("prod", metadata.Tags["Env"]);
        Assert.Equal(1, handler.TokenRequests);
        Assert.True(handler.AllReadsHadToken);
    }

    [Fact]
    public async Task ImdsV2Client_ReturnsNullOffEc2()
    {
        using ImdsV2Client imds = new(new HttpClient(new UnreachableHandler())
        {
            BaseAddress = ImdsV2Client.DefaultEndpoint
        });

        Ec2InstanceMetadata? metadata = await Ec2MetadataClient.CreateImdsV2(imds)
            .GetAsync(TestContext.Current.CancellationToken);

        Assert.Null(metadata);
    }

    private static Ec2AgentOptions AuthOptions() =>
        new()
        {
            AgentId = "agent-1",
            Sources = [new HostLogSource("auth", HostLogKind.Auth, "/var/log/auth.log")]
        };

    private sealed class FakeImdsHandler : HttpMessageHandler
    {
        private static readonly Dictionary<string, string> Values = new(StringComparer.Ordinal)
        {
            ["/latest/meta-data/instance-id"] = "i-0abc",
            ["/latest/meta-data/placement/region"] = "ap-southeast-2",
            ["/latest/meta-data/placement/availability-zone"] = "ap-southeast-2a",
            ["/latest/meta-data/ami-id"] = "ami-1",
            ["/latest/meta-data/security-groups"] = "web\nssh",
            ["/latest/dynamic/instance-identity/document"] = """{"accountId":"123456789012"}""",
            ["/latest/meta-data/mac"] = "0a:00:00:00:00:01",
            ["/latest/meta-data/network/interfaces/macs/0a:00:00:00:00:01/vpc-id"] = "vpc-9",
            ["/latest/meta-data/network/interfaces/macs/0a:00:00:00:00:01/subnet-id"] = "subnet-9",
            ["/latest/meta-data/tags/instance"] = "Env\nName",
            ["/latest/meta-data/tags/instance/Env"] = "prod",
            ["/latest/meta-data/tags/instance/Name"] = "web"
        };

        public int TokenRequests { get; private set; }

        public bool AllReadsHadToken { get; private set; } = true;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Put && request.RequestUri!.AbsolutePath == "/latest/api/token")
            {
                TokenRequests++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("session-token")
                });
            }

            AllReadsHadToken &= request.Headers.TryGetValues("X-aws-ec2-metadata-token", out IEnumerable<string>? values)
                && values.Single() == "session-token";
            return Task.FromResult(
                Values.TryGetValue(request.RequestUri!.AbsolutePath, out string? value)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(value) }
                    : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class UnreachableHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new HttpRequestException("No route to host");
    }
}

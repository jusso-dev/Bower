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
}

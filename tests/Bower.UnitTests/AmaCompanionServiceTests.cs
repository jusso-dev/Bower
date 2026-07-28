using Bower.Contracts;
using Bower.Source.Ama;

namespace Bower.UnitTests;

public sealed class AmaCompanionServiceTests
{
    [Fact]
    public void Discover_ReadsInventoryWhenPresent()
    {
        Dictionary<string, string> files = new(StringComparer.Ordinal)
        {
            ["/tmp/ama/agentversion"] = "1.31.0",
            ["/tmp/ama/config/bower-ama-inventory.json"] =
                """{"status":"healthy","dcrs":["dcr-1"],"workspaces":["law-1"]}"""
        };

        AmaCompanionService service = new(
            new AmaCompanionOptions
            {
                SourceId = "ama-1",
                InstallMarkerPath = "/tmp/ama/agentversion",
                ConfigDirectory = "/tmp/ama/config"
            },
            pathExists: files.ContainsKey,
            readAllText: path => files[path]);

        AmaDiscoveryResult result = service.Discover();

        Assert.True(result.Installed);
        Assert.Equal("1.31.0", result.AgentVersion);
        Assert.Equal("healthy", result.Status);
        Assert.Equal(["dcr-1"], result.DataCollectionRuleIds);
        Assert.Equal(["law-1"], result.WorkspaceIds);
    }

    [Fact]
    public void MapCustomLogLines_CreatesEnvelopes()
    {
        AmaCompanionService service = new(
            new AmaCompanionOptions
            {
                SourceId = "ama-1",
                CustomLogs =
                [
                    new AmaCustomLogTarget("app", "/var/log/app/security.json", "json", true)
                ]
            },
            pathExists: _ => false,
            readAllText: _ => string.Empty);

        IReadOnlyList<SecurityEventEnvelope> events = service.MapCustomLogLines(
            "app",
            ["{\"action\":\"login-failed\"}", ""]);

        SecurityEventEnvelope envelope = Assert.Single(events);
        Assert.Equal("ama_custom_log", envelope.EventType);
        Assert.Equal("ama.companion", envelope.Collector?.SourceAdapter);
        Assert.Equal("app", envelope.Labels?["ama.targetId"]);
    }

    [Fact]
    public void Options_RejectPathTraversal()
    {
        AmaCompanionOptions options = new()
        {
            SourceId = "ama-1",
            CustomLogs = [new AmaCustomLogTarget("x", "../etc/passwd", "text", true)]
        };

        Assert.Throws<ArgumentException>(options.Validate);
    }
}

using Bower.PolicyEngine;

namespace Bower.UnitTests;

public sealed class PolicyLoaderTests
{
    [Fact]
    public void LoadFile_ParsesAndHashesVersionedYamlDeterministically()
    {
        using TemporaryDirectory directory = new();
        string path = Path.Combine(directory.Path, "policy.yaml");
        File.WriteAllText(
            path,
            """
            apiVersion: bower.security/v1
            kind: TelemetryPolicy
            metadata:
              id: BWR-POL-TEST
              name: Test policy
              version: 1.0.0
              owner: Test
            match:
              eventTypes:
                - authentication_failure
            requirements:
              requiredFields:
                - eventType
            decision:
              action: accept
              minimumValueScore: 1
              neverSample: true
            """);

        LoadedPolicy first = PolicyLoader.LoadFile(path);
        LoadedPolicy second = PolicyLoader.LoadFile(path);

        Assert.Equal("BWR-POL-TEST", first.Policy.Metadata.Id);
        Assert.Equal(first.Hash, second.Hash);
        Assert.StartsWith("sha256:", first.Hash, StringComparison.Ordinal);
    }
}

using System.Globalization;
using Bower.Contracts;
using Bower.Ocsf;

namespace Bower.UnitTests;

public sealed class OcsfNormalisationEngineTests
{
    private readonly OcsfNormalisationEngine engine = new();

    [Fact]
    public void SupportedSources_IncludeInitialCatalogue()
    {
        Assert.Contains(OcsfSourceKind.CloudTrail, engine.SupportedSources);
        Assert.Contains(OcsfSourceKind.WindowsEvent, engine.SupportedSources);
        Assert.Contains(OcsfSourceKind.CrowdStrike, engine.SupportedSources);
        Assert.Contains(OcsfSourceKind.MicrosoftSentinel, engine.SupportedSources);
    }

    [Fact]
    public void NormaliseEnvelope_MapsAuthenticationFailure()
    {
        SecurityEventEnvelope envelope = new()
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = Guid.CreateVersion7().ToString(),
            TimeGenerated = DateTimeOffset.Parse(
                "2026-07-01T00:00:00Z",
                CultureInfo.InvariantCulture),
            EventCategory = SecurityEventCategories.Authentication,
            EventType = SecurityEventTypes.AuthenticationFailure,
            EventAction = "authentication.attempt",
            EventResult = EventResult.Failure,
            EventSeverity = EventSeverity.High,
            EventOutcomeReason = "InvalidPassword",
            Application = new ApplicationContext
            {
                Name = "app",
                Environment = "test"
            },
            Actor = new ActorContext { Username = "alice", Type = ActorType.Human },
            Source = new SourceContext { IpAddress = "203.0.113.5" },
            Target = new TargetContext { Type = "account", Name = "alice" }
        };

        OcsfNormalisationResult result = engine.NormaliseEnvelope(envelope);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Event);
        Assert.Equal(3002, result.Event.ClassUid);
        Assert.Equal("Authentication", result.Event.ClassName);
        Assert.Equal("alice", result.Event.ActorUserName);
        Assert.Equal("203.0.113.5", result.Event.SrcEndpointIp);
        Assert.Equal(4, result.Event.SeverityId);
    }

    [Fact]
    public void Normalise_CloudTrailRecord()
    {
        const string json =
            """
            {
              "eventName": "AssumeRole",
              "eventSource": "sts.amazonaws.com",
              "eventTime": "2026-07-01T01:00:00Z",
              "eventID": "ct-1",
              "sourceIPAddress": "198.51.100.2",
              "userIdentity": { "userName": "deploy" }
            }
            """;

        OcsfNormalisationResult result = engine.Normalise(json, OcsfSourceKind.CloudTrail);

        Assert.True(result.Succeeded);
        Assert.Equal("AssumeRole", result.Event?.ActivityName);
        Assert.Equal("deploy", result.Event?.ActorUserName);
        Assert.Equal("AWS", result.Event?.MetadataProductVendor);
    }

    [Fact]
    public void Normalise_WindowsFailedLogon()
    {
        const string json =
            """
            {
              "EventID": "4625",
              "TimeCreated": "2026-07-01T02:00:00Z",
              "TargetUserName": "bob",
              "IpAddress": "192.0.2.10",
              "Computer": "DC01",
              "Message": "An account failed to log on."
            }
            """;

        OcsfNormalisationResult result = engine.Normalise(json, OcsfSourceKind.WindowsEvent);

        Assert.True(result.Succeeded);
        Assert.Equal("Authentication", result.Event?.ClassName);
        Assert.Equal("Failure", result.Event?.Status);
        Assert.Equal("bob", result.Event?.ActorUserName);
    }

    [Fact]
    public void Normalise_RejectsInvalidJson()
    {
        OcsfNormalisationResult result = engine.Normalise("{", OcsfSourceKind.Sysmon);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid-json", result.FailureCode);
    }
}

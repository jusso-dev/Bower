using System.Net;
using System.Net.Http.Json;
using Bower.Management.Api;
using Bower.Redaction.Privacy;
using Microsoft.AspNetCore.Builder;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class PrivacyProfileFormTests
{
    private const string Profile = """
        apiVersion: bower.security/v1
        kind: PrivacyProfile
        metadata:
          id: guided-profile
          version: 1.0.0
          description: Example
        detectors:
          id.email: hmac
        secretFieldNames: [employeeSecret]
        maximumFieldLength: 4096
        fields:
          - path: attributes.message
            action: truncate
            maxLength: 24
        """;

    [Theory]
    [InlineData("")]
    [InlineData(BowerRoles.Viewer)]
    [InlineData(BowerRoles.Collector)]
    public async Task Forms_RequireOperator(string roles)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        using HttpResponseMessage response = await ManagementApiTests.Client(app, roles).PostAsJsonAsync(
            "/api/privacy-profiles/form", new PrivacyFormRequest(Profile, null), ct);
        Assert.True(response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Forms_PreserveAdvancedSettingsAndRoundTripThroughCollectorLoader()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        using HttpClient client = ManagementApiTests.Client(app, BowerRoles.Operator);
        PrivacyFormResult original = await FormAsync(client, new(Profile, null), ct);
        Assert.Equal(Profile, original.Content);
        Assert.Equal(new PrivacyFormField("attributes.message", "truncate", 24), Assert.Single(original.Form.Fields));
        PrivacyForm changed = original.Form with
        {
            Version = "1.0.1",
            Description = "A quoted description: \"safe\"\nfields: []",
            Fields = [new("actor.username", "replace", null)]
        };
        PrivacyFormResult result = await FormAsync(client, new(Profile, changed), ct);
        LoadedPrivacyProfile loaded = PrivacyProfileLoader.Load(result.Content, new byte[32], "test");
        Assert.True(result.Validation.Valid);
        Assert.Equal("1.0.1", loaded.Version);
        Assert.Equal(PrivacyAction.Hmac, loaded.Policy.DetectorActions["id.email"]);
        Assert.Contains("employeesecret", loaded.Policy.SecretFieldNames);
        Assert.Equal(4096, loaded.Policy.MaximumFieldLength);
        Assert.Equal(PrivacyAction.Replace, Assert.Single(loaded.Policy.FieldRules).Action);
        PrivacyFormResult reopened = await FormAsync(client, new(result.Content, null), ct);
        Assert.Equal(changed.Description, reopened.Form.Description);
        Assert.Equal(changed.Fields, reopened.Form.Fields);
        Assert.DoesNotContain("alex.example@example.com", result.Preview.Redacted!, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-password", result.Preview.Redacted!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Forms_PreviewHasServerOwnedMinimumProtectionAndCannotSubmitOldVersion()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        using HttpClient client = ManagementApiTests.Client(app, BowerRoles.Operator);
        using HttpResponseMessage submitted = await client.PostAsJsonAsync("/api/privacy-profiles",
            new PrivacyProfileSubmission(Profile, "Initial version"), ct);
        submitted.EnsureSuccessStatusCode();
        PrivacyFormResult result = await FormAsync(client, new(Profile,
            new("guided-profile", "1.0.0", "Example", [new("actor.username", "allow", null), new("attributes.password", "allow", null)])), ct);
        Assert.False(result.Validation.Valid);
        Assert.Contains(result.Validation.Errors, error => error.Contains("greater than 1.0.0", StringComparison.Ordinal));
        Assert.DoesNotContain("alex.example@example.com", result.Preview.Redacted!, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-password", result.Preview.Redacted!, StringComparison.Ordinal);
        Assert.True(result.Preview.Valid);
    }

    [Theory]
    [InlineData("truncate", 0)]
    [InlineData("truncate", 65537)]
    [InlineData("execute", null)]
    public async Task Forms_RejectUnsupportedActionsAndInvalidLengths(string action, int? length)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        await using WebApplication app = await ManagementApiTests.StartAsync(directory, ct);
        using HttpResponseMessage response = await ManagementApiTests.Client(app, BowerRoles.Operator).PostAsJsonAsync(
            "/api/privacy-profiles/form", new PrivacyFormRequest(Profile,
                new("guided-profile", "1.0.1", "Example", [new("actor.username", action, length)])), ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static async Task<PrivacyFormResult> FormAsync(HttpClient client, PrivacyFormRequest request, CancellationToken ct)
    {
        using HttpResponseMessage response = await client.PostAsJsonAsync("/api/privacy-profiles/form", request, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PrivacyFormResult>(ManagementApiTests.ApiJson, ct))!;
    }
}

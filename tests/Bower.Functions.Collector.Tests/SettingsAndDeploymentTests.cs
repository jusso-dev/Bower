using System.Text.Json;
using Azure.Identity;
using Bower.Packs;

namespace Bower.Functions.Collector.Tests;

public sealed class SettingsAndDeploymentTests
{
    private static Dictionary<string, string?> Environment() => new(StringComparer.Ordinal)
    {
        ["BOWER_ENTRA_TENANT_ID"] = TestEntra.Tenant,
        ["BOWER_ENTRA_AUDIENCE"] = TestEntra.Audience,
        ["BOWER_DCE_ENDPOINT"] = "https://example.ingest.monitor.azure.com",
        ["BOWER_DCR_ID"] = "dcr-00000000000000000000000000000000",
        ["WEBSITE_SITE_NAME"] = "bower-fn-test"
    };

    private static FunctionSettings Read(Dictionary<string, string?> values) =>
        FunctionSettings.FromEnvironment(name => values.GetValueOrDefault(name));

    [Fact]
    public void Defaults_are_production_managed_identity_and_packaged_policies()
    {
        FunctionSettings settings = Read(Environment());

        Assert.False(settings.IsDevelopment);
        Assert.False(settings.DevelopmentAuthentication);
        Assert.Equal("oid", settings.ProducerClaim);
        Assert.Equal(FunctionCredentialMode.ManagedIdentity, settings.AzureCredential);
        Assert.Null(settings.AzureClientId);
        Assert.Equal("azure-function:bower-fn-test", settings.CollectorId);
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, "policies", "default"), settings.PolicySources.PolicyDirectory);
        Assert.Equal(TimeSpan.FromSeconds(30), settings.DeliveryTimeout);
        Assert.StartsWith("sha256:", settings.ConfigurationHash(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("BOWER_ENTRA_TENANT_ID", null)]
    [InlineData("BOWER_ENTRA_TENANT_ID", "common")]
    [InlineData("BOWER_ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000000")]
    [InlineData("BOWER_ENTRA_AUDIENCE", null)]
    [InlineData("BOWER_ENTRA_AUDIENCE", "*")]
    [InlineData("BOWER_DCE_ENDPOINT", null)]
    [InlineData("BOWER_DCE_ENDPOINT", "http://example.ingest.monitor.azure.com")]
    [InlineData("BOWER_DCR_ID", null)]
    [InlineData("BOWER_DCR_ID", "not-a-dcr")]
    [InlineData("BOWER_STREAM_NAME", "Microsoft-Syslog")]
    [InlineData("BOWER_PRODUCER_CLAIM", "sub")]
    [InlineData("BOWER_DEVELOPMENT_AUTH", "true")]
    [InlineData("BOWER_AZURE_CREDENTIAL", "azure-cli")]
    [InlineData("BOWER_AZURE_CREDENTIAL", "environment")]
    [InlineData("BOWER_AZURE_CREDENTIAL", "client-secret")]
    [InlineData("BOWER_AZURE_CLIENT_ID", "not-a-guid")]
    [InlineData("BOWER_DELIVERY_TIMEOUT_SECONDS", "1")]
    [InlineData("BOWER_DELIVERY_TIMEOUT_SECONDS", "600")]
    [InlineData("BOWER_PACKS", "pack.bowerpack")]
    public void Missing_or_unsafe_settings_fail_start_up(string name, string? value)
    {
        Dictionary<string, string?> values = Environment();
        values[name] = value;

        Assert.Throws<InvalidOperationException>(() => Read(values));
    }

    [Fact]
    public void Scopes_file_and_inline_scopes_are_mutually_exclusive()
    {
        Dictionary<string, string?> values = Environment();
        values["BOWER_PRODUCER_SCOPES_FILE"] = "scopes.json";
        values["BOWER_PRODUCER_SCOPES_JSON"] = "[]";

        Assert.Throws<InvalidOperationException>(() => Read(values));
    }

    [Fact]
    public void Invalid_inline_scopes_fail_without_echoing_values()
    {
        FunctionSettings settings = Harness.Settings(scopesJson: """[{"producer":"x","application":{"name":"secret-app"},"extra":1}]""");

        FormatException error = Assert.Throws<FormatException>(() => new Harness(settings));

        Assert.DoesNotContain("secret-app", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Development_bypass_and_cli_credential_only_in_development()
    {
        Dictionary<string, string?> values = Environment();
        values["AZURE_FUNCTIONS_ENVIRONMENT"] = "Development";
        values["BOWER_DEVELOPMENT_AUTH"] = "true";
        values["BOWER_AZURE_CREDENTIAL"] = "azure-cli";
        values.Remove("BOWER_ENTRA_TENANT_ID");
        values.Remove("BOWER_ENTRA_AUDIENCE");

        FunctionSettings settings = Read(values);

        Assert.True(settings.DevelopmentAuthentication);
        Assert.Equal(new CredentialSelection(FunctionCredentialMode.AzureCli, null), FunctionCredentialFactory.Select(settings));
        Assert.IsType<AzureCliCredential>(FunctionCredentialFactory.Create(settings));
        Assert.Throws<InvalidOperationException>(() =>
            FunctionCredentialFactory.Select(settings with { Environment = "Production" }));
    }

    [Fact]
    public void Credential_defaults_to_system_assigned_managed_identity()
    {
        FunctionSettings settings = Read(Environment());

        CredentialSelection selection = FunctionCredentialFactory.Select(settings);

        Assert.Equal(FunctionCredentialMode.ManagedIdentity, selection.Mode);
        Assert.Null(selection.UserAssignedClientId);
        Assert.Equal("managed-identity:system-assigned", selection.Description);
        Assert.IsType<ManagedIdentityCredential>(FunctionCredentialFactory.Create(settings));
    }

    [Fact]
    public void Credential_uses_user_assigned_identity_only_when_its_client_id_is_set()
    {
        Dictionary<string, string?> values = Environment();
        values["BOWER_AZURE_CLIENT_ID"] = TestEntra.ProducerClientId;
        FunctionSettings settings = Read(values);

        CredentialSelection selection = FunctionCredentialFactory.Select(settings);

        Assert.Equal(FunctionCredentialMode.ManagedIdentity, selection.Mode);
        Assert.Equal(TestEntra.ProducerClientId, selection.UserAssignedClientId);
        Assert.Equal("managed-identity:user-assigned", selection.Description);
        Assert.IsType<ManagedIdentityCredential>(FunctionCredentialFactory.Create(settings));
    }

    [Fact]
    public void Packaged_default_policies_load_through_the_shared_policy_bundle()
    {
        PolicyBundle bundle = PolicyBundle.Load(new PolicyBundleSources
        {
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default")
        });

        Assert.Contains(bundle.Policies, policy => policy.Policy.Metadata.Id == "BWR-POL-AUTH-FAILURE");
        Assert.Null(bundle.PrivacyProfile);
    }

    [Fact]
    public void Bicep_is_identity_only_least_privilege_and_never_enables_the_development_bypass()
    {
        string bicep = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "azure-function", "main.bicep"));
        string role = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "deploy", "azure-function", "dcr-role.bicep"));

        Assert.DoesNotContain("BOWER_DEVELOPMENT_AUTH", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("azure-cli", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("listKeys", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("AccountKey", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("AzureWebJobsStorage'", bicep, StringComparison.Ordinal);
        Assert.Contains("{ name: 'AZURE_FUNCTIONS_ENVIRONMENT', value: 'Production' }", bicep, StringComparison.Ordinal);
        Assert.Contains("{ name: 'AzureWebJobsStorage__accountName', value: storage.name }", bicep, StringComparison.Ordinal);
        Assert.Contains("{ name: 'BOWER_AZURE_CREDENTIAL', value: 'managed-identity' }", bicep, StringComparison.Ordinal);
        Assert.Contains("allowSharedKeyAccess: false", bicep, StringComparison.Ordinal);
        Assert.Contains("httpsOnly: true", bicep, StringComparison.Ordinal);
        Assert.Contains("minTlsVersion: '1.2'", bicep, StringComparison.Ordinal);
        Assert.Contains("minimumTlsVersion: 'TLS1_2'", bicep, StringComparison.Ordinal);
        Assert.Equal(2, CountOf(bicep, "allow: false"));
        Assert.Contains("tier: 'FlexConsumption'", bicep, StringComparison.Ordinal);
        Assert.Contains("name: 'dotnet-isolated'", bicep, StringComparison.Ordinal);
        Assert.Contains("param location string = 'australiaeast'", bicep, StringComparison.Ordinal);
        Assert.Contains("type: 'SystemAssigned'", bicep, StringComparison.Ordinal);
        // Monitoring Metrics Publisher is granted on the DCR only (and, optionally, the
        // Application Insights component) — never on a resource group or subscription.
        Assert.Contains("scope: dcr", role, StringComparison.Ordinal);
        Assert.Contains("3913510d-42f4-4e42-8a64-420c390055eb", role, StringComparison.Ordinal);
        Assert.DoesNotContain("scope: resourceGroup()", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("scope: subscription()", bicep, StringComparison.Ordinal);
        Assert.DoesNotContain("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", bicep + role, StringComparison.Ordinal); // Owner
        Assert.DoesNotContain("b24988ac-6180-42a0-ab88-20f7382dd24c", bicep + role, StringComparison.Ordinal); // Contributor
    }

    [Fact]
    public void Ingest_app_manifest_exposes_only_the_application_only_producer_role()
    {
        using JsonDocument ingest = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "deploy", "entra", "ingest-api-app-manifest.json")));
        using JsonDocument management = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "deploy", "entra", "api-app-manifest.json")));
        JsonElement root = ingest.RootElement;

        Assert.Equal("AzureADMyOrg", root.GetProperty("signInAudience").GetString());
        Assert.Equal(2, root.GetProperty("api").GetProperty("requestedAccessTokenVersion").GetInt32());
        Assert.Empty(root.GetProperty("api").GetProperty("oauth2PermissionScopes").EnumerateArray());
        JsonElement role = Assert.Single(root.GetProperty("appRoles").EnumerateArray());
        Assert.Equal(EntraProducerAuthenticator.ProducerRole, role.GetProperty("value").GetString());
        // Stable contract identifier: never regenerate once deployed.
        Assert.Equal("12859e27-8403-42a7-b3e4-66cc808de79f", role.GetProperty("id").GetString());
        Assert.Equal(["Application"], role.GetProperty("allowedMemberTypes").EnumerateArray().Select(item => item.GetString()));
        Assert.DoesNotContain(
            management.RootElement.GetProperty("appRoles").EnumerateArray(),
            item => item.GetProperty("value").GetString() == EntraProducerAuthenticator.ProducerRole
                || item.GetProperty("id").GetString() == role.GetProperty("id").GetString());
        Assert.DoesNotContain("secret", ingest.RootElement.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    private static int CountOf(string text, string value)
    {
        int count = 0;
        for (int index = text.IndexOf(value, StringComparison.Ordinal); index >= 0;
             index = text.IndexOf(value, index + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}

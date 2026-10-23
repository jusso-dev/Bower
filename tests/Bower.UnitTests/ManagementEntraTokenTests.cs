using System.Security.Claims;
using System.Security.Cryptography;
using Bower.Management.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Bower.UnitTests;

[Collection(SerialHostTests.Name)]
public sealed class ManagementEntraTokenTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("resource-uri", false)]
    [InlineData("wrong-audience", false)]
    [InlineData("wrong-issuer", false)]
    [InlineData("expired", false)]
    [InlineData("wrong-signature", false)]
    public async Task V2_tokens_validate_exact_guid_audience_and_trust_boundaries(string scenario, bool expected)
    {
        const string audience = "11111111-2222-3333-4444-555555555555";
        const string tenant = "22222222-3333-4444-5555-666666666666";
        const string issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0";
        using TemporaryDirectory directory = new();
        await using WebApplication app = ManagementApplication.Build(
            ["--BOWER_AUTH_MODE=entra", $"--Bower:Entra:TenantId={tenant}",
                $"--Bower:Entra:Audience={audience}", $"--BOWER_MANAGEMENT_DB_PATH={directory.Path}/management.db"]);
        JwtBearerOptions options = app.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);
        using RSA trusted = RSA.Create(2048);
        using RSA other = RSA.Create(2048);
        RsaSecurityKey key = new(trusted) { KeyId = "offline-fixture" };
        TokenValidationParameters validation = options.TokenValidationParameters.Clone();
        validation.ValidIssuer = options.Authority;
        validation.IssuerSigningKey = key;
        validation.ClockSkew = TimeSpan.Zero;
        DateTime now = DateTime.UtcNow;
        JsonWebTokenHandler handler = new();
        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Audience = scenario switch
            {
                "resource-uri" => "api://" + audience,
                "wrong-audience" => "33333333-4444-5555-6666-777777777777",
                _ => audience
            },
            Issuer = scenario == "wrong-issuer" ? "https://login.microsoftonline.com/another/v2.0" : issuer,
            Subject = new ClaimsIdentity([new Claim("roles", BowerRoles.Viewer), new Claim("ver", "2.0")]),
            NotBefore = now.AddHours(-2),
            IssuedAt = now.AddHours(-2),
            Expires = scenario == "expired" ? now.AddHours(-1) : now.AddHours(1),
            SigningCredentials = new SigningCredentials(
                scenario == "wrong-signature" ? new RsaSecurityKey(other) { KeyId = key.KeyId } : key,
                SecurityAlgorithms.RsaSha256)
        });

        TokenValidationResult result = await handler.ValidateTokenAsync(token, validation);
        Assert.Equal(expected, result.IsValid);
    }
}

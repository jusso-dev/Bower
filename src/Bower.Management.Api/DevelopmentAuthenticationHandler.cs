using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Bower.Management.Api;

public sealed class DevelopmentAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string AuthenticationScheme = "BowerDevelopment";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        Claim[] claims =
        [
            new("oid", "development-user"),
            new("name", "Local development administrator"),
            new("roles", BowerRoles.Viewer),
            new("roles", BowerRoles.Operator),
            new("roles", BowerRoles.Approver),
            new("roles", BowerRoles.Administrator),
            new("roles", BowerRoles.Collector),
            new(ClaimTypes.NameIdentifier, "development-user")
        ];
        ClaimsIdentity identity = new(claims, AuthenticationScheme, "name", "roles");
        return Task.FromResult(
            AuthenticateResult.Success(
                new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    AuthenticationScheme)));
    }
}

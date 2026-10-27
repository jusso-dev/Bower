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

    /// <summary>
    /// Development only: a comma-separated subset of roles for this request, so local and
    /// end-to-end tests can act as a viewer. It can only remove roles, never add one.
    /// </summary>
    public const string RolesHeader = "X-Bower-Development-Roles";

    private static readonly string[] AllRoles =
        [BowerRoles.Viewer, BowerRoles.Operator, BowerRoles.Approver, BowerRoles.Administrator, BowerRoles.Collector];

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string[] roles = AllRoles;
        if (Request.Headers.TryGetValue(RolesHeader, out Microsoft.Extensions.Primitives.StringValues requested))
        {
            HashSet<string> subset = requested.ToString()
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.Ordinal);
            roles = AllRoles.Where(subset.Contains).ToArray();
        }

        List<Claim> claims =
        [
            new("oid", "development-user"),
            new("name", roles.Contains(BowerRoles.Administrator)
                ? "Local development administrator"
                : "Local development user"),
            .. roles.Select(role => new Claim("roles", role)),
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

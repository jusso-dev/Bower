using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Bower.Management.Api;

/// <summary>
/// Authenticates enrolled collectors by a short-lived assertion signed with the key bound to
/// their credential (<c>Authorization: Bearer bwc1.…</c>). Grants only <c>Bower.Collector</c>,
/// bound to one collector id. Every request re-reads the credential, so revocation takes
/// effect on the next heartbeat. Refusals are logged as codes, never the assertion.
/// </summary>
public sealed partial class CollectorCredentialAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ManagementStore store,
    TimeProvider clock)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "BowerCollectorCredential";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!CollectorEnrolment.HasAssertion(Request))
        {
            return AuthenticateResult.NoResult();
        }

        DateTimeOffset now = clock.GetUtcNow();
        string value = Request.Headers.Authorization.ToString()["Bearer ".Length..];
        string? refusal = CollectorEnrolment.TryReadAssertion(value, now, out CollectorAssertion? assertion)
            ?? await store.AuthenticateCredentialAsync(assertion!, now, Context.RequestAborted);
        if (refusal is not null)
        {
            LogRefused(Logger, refusal);
            return AuthenticateResult.Fail("Collector credential refused.");
        }

        Claim[] claims =
        [
            new("oid", CollectorEnrolment.PrincipalFor(assertion!.CollectorId)),
            new("name", $"Enrolled collector {assertion.CollectorId}"),
            new("roles", BowerRoles.Collector),
            new(CollectorEnrolment.CollectorIdClaim, assertion.CollectorId),
            new(CollectorEnrolment.CredentialIdClaim, assertion.CredentialId)
        ];
        ClaimsIdentity identity = new(claims, SchemeName, "name", "roles");
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    [LoggerMessage(
        EventId = 2101,
        Level = LogLevel.Warning,
        Message = "Collector credential refused: {Code}.")]
    private static partial void LogRefused(ILogger logger, string code);
}

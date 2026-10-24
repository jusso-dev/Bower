using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Bower.Functions.Collector;

public enum AuthenticationFailure
{
    None,

    /// <summary>No bearer token was presented (401).</summary>
    Missing,

    /// <summary>Signature, issuer, tenant, audience, lifetime or token version failed (401).</summary>
    Invalid,

    /// <summary>A valid token without the producer app role or a producer identity claim (403).</summary>
    Forbidden,

    /// <summary>Signing keys could not be retrieved; the caller should retry (503).</summary>
    Unavailable
}

/// <summary>An authenticated producer. Never carries the token.</summary>
public sealed record ProducerCaller(string Producer);

public sealed record AuthenticationOutcome(ProducerCaller? Caller, AuthenticationFailure Failure)
{
    public static AuthenticationOutcome Fail(AuthenticationFailure failure) => new(null, failure);
}

public interface IProducerAuthenticator
{
    Task<AuthenticationOutcome> AuthenticateAsync(string? authorizationHeader, CancellationToken cancellationToken);
}

/// <summary>
/// Validates Microsoft Entra v2 access tokens in code: RS256 signature against the tenant's
/// OIDC signing keys, exact v2 issuer and <c>tid</c>, exact audience, lifetime, then the
/// application-only <c>Bower.Producer</c> app role. The producer id used for producer scopes
/// is the caller's <c>oid</c> (service principal object ID) or <c>azp</c> (client ID).
/// Tokens and validation exception text are never logged or returned.
/// </summary>
public sealed class EntraProducerAuthenticator : IProducerAuthenticator
{
    public const string ProducerRole = "Bower.Producer";
    public const int MaximumTokenLength = 16 * 1024;

    private readonly IConfigurationManager<OpenIdConnectConfiguration> metadata;
    private readonly JsonWebTokenHandler handler = new() { MapInboundClaims = false };
    private readonly string tenantId;
    private readonly string audience;
    private readonly string issuer;
    private readonly string producerClaim;

    public EntraProducerAuthenticator(
        string tenantId,
        string audience,
        string producerClaim,
        IConfigurationManager<OpenIdConnectConfiguration>? metadata = null)
    {
        if (!Guid.TryParse(tenantId, out Guid tenant) || tenant == Guid.Empty)
        {
            throw new ArgumentException("Tenant ID must be a GUID.", nameof(tenantId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        this.tenantId = tenant.ToString("D");
        this.audience = audience;
        this.producerClaim = producerClaim is "oid" or "azp"
            ? producerClaim
            : throw new ArgumentException("Producer claim must be oid or azp.", nameof(producerClaim));
        issuer = $"https://login.microsoftonline.com/{this.tenantId}/v2.0";
        this.metadata = metadata ?? new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{issuer}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = true });
    }

    public string Issuer => issuer;

    public async Task<AuthenticationOutcome> AuthenticateAsync(
        string? authorizationHeader,
        CancellationToken cancellationToken)
    {
        const string prefix = "Bearer ";
        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Missing);
        }

        if (!authorizationHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Invalid);
        }

        string token = authorizationHeader[prefix.Length..].Trim();
        if (token.Length == 0 || token.Length > MaximumTokenLength)
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Invalid);
        }

        TokenValidationResult result;
        try
        {
            result = await ValidateAsync(token, cancellationToken);
            if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
            {
                // Key rollover: refresh the signing keys once, then decide.
                metadata.RequestRefresh();
                result = await ValidateAsync(token, cancellationToken);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Metadata retrieval failed (network or service). Retryable, never a credential verdict.
            return AuthenticationOutcome.Fail(AuthenticationFailure.Unavailable);
        }

        if (!result.IsValid)
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Invalid);
        }

        ClaimsIdentity identity = result.ClaimsIdentity;
        if (!string.Equals(Claim(identity, "tid"), tenantId, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(Claim(identity, "ver"), "2.0", StringComparison.Ordinal))
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Invalid);
        }

        // Application-only role (allowedMemberTypes: Application); a delegated user token
        // cannot carry it, and an explicit idtyp other than app is refused.
        string? tokenType = Claim(identity, "idtyp");
        if (!identity.FindAll("roles").Any(claim => string.Equals(claim.Value, ProducerRole, StringComparison.Ordinal))
            || (tokenType is not null && !string.Equals(tokenType, "app", StringComparison.Ordinal))
            || identity.FindFirst("scp") is not null)
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Forbidden);
        }

        string? producer = Claim(identity, producerClaim);
        if (!Guid.TryParse(producer, out Guid producerId) || producerId == Guid.Empty)
        {
            return AuthenticationOutcome.Fail(AuthenticationFailure.Forbidden);
        }

        return new AuthenticationOutcome(new ProducerCaller(producerId.ToString("D")), AuthenticationFailure.None);
    }

    private async Task<TokenValidationResult> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        OpenIdConnectConfiguration configuration = await metadata.GetConfigurationAsync(cancellationToken);
        TokenValidationParameters parameters = new()
        {
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKeys = configuration.SigningKeys,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            RequireAudience = true,
            ClockSkew = TimeSpan.FromMinutes(2),
            NameClaimType = "oid",
            RoleClaimType = "roles"
        };
        return await handler.ValidateTokenAsync(token, parameters);
    }

    private static string? Claim(ClaimsIdentity identity, string type) => identity.FindFirst(type)?.Value;
}

/// <summary>
/// Development-only bypass: every request is producer <c>development</c>. Constructed only
/// when <see cref="FunctionSettings.Validate"/> accepted Development mode.
/// </summary>
public sealed class DevelopmentProducerAuthenticator : IProducerAuthenticator
{
    public const string Producer = "development";

    public Task<AuthenticationOutcome> AuthenticateAsync(string? authorizationHeader, CancellationToken cancellationToken) =>
        Task.FromResult(new AuthenticationOutcome(new ProducerCaller(Producer), AuthenticationFailure.None));
}

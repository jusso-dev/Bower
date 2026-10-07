using System.Security.Cryptography;
using System.Text;

namespace Bower.Collector;

/// <summary>
/// Shared-secret bearer authentication for event producers. Compares SHA-256 digests with
/// <see cref="CryptographicOperations.FixedTimeEquals"/> so neither content nor length leaks
/// through timing. The token itself is never logged.
/// </summary>
public sealed class IngestAuthentication
{
    private readonly byte[]? expectedDigest;

    public IngestAuthentication(string? token)
    {
        expectedDigest = string.IsNullOrEmpty(token)
            ? null
            : SHA256.HashData(Encoding.UTF8.GetBytes(token));
    }

    public bool Required => expectedDigest is not null;

    public bool IsAuthorized(HttpRequest request)
    {
        if (expectedDigest is null)
        {
            return true;
        }

        string? header = request.Headers.Authorization;
        const string prefix = "Bearer ";
        if (header is null || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        byte[] presented = SHA256.HashData(Encoding.UTF8.GetBytes(header[prefix.Length..].Trim()));
        return CryptographicOperations.FixedTimeEquals(presented, expectedDigest);
    }
}

internal sealed class IngestAuthenticationFilter(IngestAuthentication authentication) : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        if (authentication.IsAuthorized(context.HttpContext.Request))
        {
            return next(context);
        }

        context.HttpContext.Response.Headers.WWWAuthenticate = "Bearer";
        return ValueTask.FromResult<object?>(Results.Json(
            new { error = "A valid collector ingest token is required." },
            statusCode: StatusCodes.Status401Unauthorized));
    }
}

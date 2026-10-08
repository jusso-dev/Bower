using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Bower.Collector;

/// <summary>
/// Bearer authentication for event producers. Supports one shared token
/// (<c>BOWER_INGEST_TOKEN</c>, producer id "default") and/or a tokens file with one
/// revocable credential per producer. The file holds SHA-256 hashes, never tokens:
/// <code>sidecar-01 sha256:&lt;hex&gt;</code>
/// Removing a line revokes that producer within seconds, without a restart.
/// Comparisons are constant-time over every entry, and tokens are never logged.
/// </summary>
public sealed class IngestAuthentication
{
    private static readonly TimeSpan ReloadInterval = TimeSpan.FromSeconds(2);
    private readonly (string Producer, byte[] Digest)? sharedToken;
    private readonly string? tokensFile;
    private readonly TimeProvider clock;
    private readonly Lock gate = new();
    private IReadOnlyList<(string Producer, byte[] Digest)> fileTokens = [];
    private DateTimeOffset nextReload = DateTimeOffset.MinValue;
    private DateTime fileStamp = DateTime.MinValue;

    public IngestAuthentication(string? token, string? tokensFile = null, TimeProvider? clock = null)
    {
        sharedToken = string.IsNullOrEmpty(token) ? null : ("default", Digest(token));
        this.tokensFile = string.IsNullOrWhiteSpace(tokensFile) ? null : tokensFile;
        this.clock = clock ?? TimeProvider.System;
        if (this.tokensFile is not null)
        {
            // Fail fast on a malformed file at start-up.
            fileTokens = Parse(File.ReadAllLines(this.tokensFile));
            fileStamp = File.GetLastWriteTimeUtc(this.tokensFile);
        }
    }

    public bool Required => sharedToken is not null || tokensFile is not null;

    public bool IsAuthorized(HttpRequest request) => Authenticate(request) is not null;

    /// <summary>The authenticated producer id, or null. "anonymous" when auth is off.</summary>
    public string? Authenticate(HttpRequest request)
    {
        if (!Required)
        {
            return "anonymous";
        }

        string? header = request.Headers.Authorization;
        const string prefix = "Bearer ";
        if (header is null || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        byte[] presented = Digest(header[prefix.Length..].Trim());
        string? match = null;
        foreach ((string producer, byte[] digest) in Candidates())
        {
            // Check every entry so timing does not reveal which producer matched.
            if (CryptographicOperations.FixedTimeEquals(presented, digest))
            {
                match ??= producer;
            }
        }

        return match;
    }

    /// <summary>Formats a tokens-file line for a producer and a freshly generated token.</summary>
    public static string TokensFileLine(string producer, string token) =>
        $"{producer} sha256:{Convert.ToHexStringLower(Digest(token))}";

    private IEnumerable<(string Producer, byte[] Digest)> Candidates()
    {
        if (sharedToken is { } shared)
        {
            yield return shared;
        }

        foreach ((string Producer, byte[] Digest) entry in FileTokens())
        {
            yield return entry;
        }
    }

    private IReadOnlyList<(string Producer, byte[] Digest)> FileTokens()
    {
        if (tokensFile is null)
        {
            return [];
        }

        lock (gate)
        {
            DateTimeOffset now = clock.GetUtcNow();
            if (now < nextReload)
            {
                return fileTokens;
            }

            nextReload = now + ReloadInterval;
            try
            {
                DateTime stamp = File.GetLastWriteTimeUtc(tokensFile);
                if (stamp != fileStamp)
                {
                    fileTokens = Parse(File.ReadAllLines(tokensFile));
                    fileStamp = stamp;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException)
            {
                // A missing or unreadable file revokes every file-based credential.
                fileTokens = [];
                fileStamp = DateTime.MinValue;
            }

            return fileTokens;
        }
    }

    internal static IReadOnlyList<(string Producer, byte[] Digest)> Parse(IEnumerable<string> lines)
    {
        List<(string, byte[])> tokens = [];
        int number = 0;
        foreach (string raw in lines)
        {
            number++;
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2
                || parts[0].Length is < 1 or > 64
                || !parts[1].StartsWith("sha256:", StringComparison.Ordinal)
                || parts[1].Length != 7 + 64)
            {
                throw new FormatException(
                    string.Create(CultureInfo.InvariantCulture, $"Ingest tokens file line {number} must be '<producer-id> sha256:<64 hex>'."));
            }

            tokens.Add((parts[0], Convert.FromHexString(parts[1][7..])));
        }

        return tokens;
    }

    private static byte[] Digest(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
}

internal sealed class IngestAuthenticationFilter(IngestAuthentication authentication) : IEndpointFilter
{
    public const string ProducerItem = "bower.producer";

    public ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        string? producer = authentication.Authenticate(context.HttpContext.Request);
        if (producer is not null)
        {
            context.HttpContext.Items[ProducerItem] = producer;
            return next(context);
        }

        context.HttpContext.Response.Headers.WWWAuthenticate = "Bearer";
        return ValueTask.FromResult<object?>(Results.Json(
            new { error = "A valid collector ingest token is required." },
            statusCode: StatusCodes.Status401Unauthorized));
    }
}

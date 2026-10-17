using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Bower.Agent.Cloud.Gcp.Auth;

internal sealed record AwsCredentials(string AccessKeyId, string SecretAccessKey, string? SessionToken)
{
    // Keep secrets out of logs and exception messages that format the record.
    public override string ToString() => $"AwsCredentials {{ AccessKeyId = {AccessKeyId} }}";
}

internal sealed record AwsSignedRequest(
    IReadOnlyList<KeyValuePair<string, string>> Headers,
    string CanonicalRequest,
    string StringToSign,
    string Signature,
    string Authorization);

/// <summary>
/// AWS Signature Version 4 (header-based, AWS4-HMAC-SHA256) for the GetCallerIdentity
/// subject token. Only what Workload Identity Federation needs: a request whose path is
/// made of unreserved characters (STS uses <c>/</c>), any query string and signed headers.
/// Checked against AWS's published SigV4 test suite.
/// </summary>
internal static class AwsSignatureV4
{
    private const string Algorithm = "AWS4-HMAC-SHA256";

    /// <param name="headers">Extra headers to sign (names are case-insensitive). <c>host</c>,
    /// <c>x-amz-date</c> and, with a session token, <c>x-amz-security-token</c> are added.</param>
    public static AwsSignedRequest Sign(
        string method,
        Uri url,
        IEnumerable<KeyValuePair<string, string>> headers,
        ReadOnlySpan<byte> payload,
        AwsCredentials credentials,
        string region,
        string service,
        DateTimeOffset now)
    {
        string amzDate = now.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        string date = amzDate[..8];

        SortedDictionary<string, string> signed = new(StringComparer.Ordinal)
        {
            ["host"] = url.IsDefaultPort ? url.Host : $"{url.Host}:{url.Port}",
            ["x-amz-date"] = amzDate
        };
        if (!string.IsNullOrEmpty(credentials.SessionToken))
        {
            signed["x-amz-security-token"] = credentials.SessionToken;
        }

        foreach ((string name, string value) in headers)
        {
            signed[name.ToLowerInvariant()] = TrimValue(value);
        }

        string signedHeaders = string.Join(';', signed.Keys);
        StringBuilder canonical = new();
        canonical.Append(method.ToUpperInvariant()).Append('\n')
            .Append(CanonicalPath(url)).Append('\n')
            .Append(CanonicalQuery(url.Query)).Append('\n');
        foreach ((string name, string value) in signed)
        {
            canonical.Append(name).Append(':').Append(value).Append('\n');
        }

        canonical.Append('\n').Append(signedHeaders).Append('\n').Append(Hex(SHA256.HashData(payload)));
        string canonicalRequest = canonical.ToString();

        string scope = $"{date}/{region}/{service}/aws4_request";
        string stringToSign = string.Join(
            '\n',
            Algorithm,
            amzDate,
            scope,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));

        byte[] key = Hmac(Encoding.UTF8.GetBytes("AWS4" + credentials.SecretAccessKey), date);
        key = Hmac(key, region);
        key = Hmac(key, service);
        key = Hmac(key, "aws4_request");
        string signature = Hex(Hmac(key, stringToSign));
        string authorization =
            $"{Algorithm} Credential={credentials.AccessKeyId}/{scope}, SignedHeaders={signedHeaders}, Signature={signature}";

        return new AwsSignedRequest([.. signed], canonicalRequest, stringToSign, signature, authorization);
    }

    /// <summary>RFC 3986 percent-encoding with AWS's unreserved set and upper-case hex.</summary>
    internal static string Encode(string value)
    {
        StringBuilder builder = new(value.Length);
        foreach (byte b in Encoding.UTF8.GetBytes(value))
        {
            if (char.IsAsciiLetterOrDigit((char)b) || b is (byte)'-' or (byte)'_' or (byte)'.' or (byte)'~')
            {
                builder.Append((char)b);
            }
            else
            {
                builder.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    private static string CanonicalPath(Uri url)
    {
        string path = url.AbsolutePath;
        if (path.Length == 0)
        {
            return "/";
        }

        // Only unreserved path characters, so no encoding or normalisation rules apply.
        foreach (char c in path)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '/' or '-' or '_' or '.' or '~'))
            {
                throw new InvalidOperationException("The AWS request path must contain only unreserved characters.");
            }
        }

        return path.Contains("/./", StringComparison.Ordinal) || path.Contains("/../", StringComparison.Ordinal)
            ? throw new InvalidOperationException("The AWS request path must be normalised.")
            : path;
    }

    private static string CanonicalQuery(string query)
    {
        if (query.Length <= 1)
        {
            return string.Empty;
        }

        List<(string Key, string Value)> parameters = [];
        foreach (string pair in query[1..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int equals = pair.IndexOf('=', StringComparison.Ordinal);
            string key = equals < 0 ? pair : pair[..equals];
            string value = equals < 0 ? string.Empty : pair[(equals + 1)..];
            parameters.Add((Encode(Uri.UnescapeDataString(key)), Encode(Uri.UnescapeDataString(value))));
        }

        return string.Join(
            '&',
            parameters
                .OrderBy(item => item.Key, StringComparer.Ordinal)
                .ThenBy(item => item.Value, StringComparer.Ordinal)
                .Select(item => $"{item.Key}={item.Value}"));
    }

    /// <summary>Trims and collapses sequential spaces, as SigV4 canonical headers require.</summary>
    private static string TrimValue(string value)
    {
        StringBuilder builder = new(value.Length);
        bool space = false;
        foreach (char c in value.Trim())
        {
            if (c == ' ')
            {
                if (!space)
                {
                    builder.Append(c);
                }

                space = true;
            }
            else
            {
                builder.Append(c);
                space = false;
            }
        }

        return builder.ToString();
    }

    private static byte[] Hmac(byte[] key, string data) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(data));

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
}

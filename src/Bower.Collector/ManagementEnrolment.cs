using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Bower.Collector.Jobs;
using Bower.Integrity;
using Bower.Packs;

namespace Bower.Collector;

/// <summary>
/// Short-lived proof that this collector holds the private key of its management credential:
/// <c>bwc1.&lt;base64url canonical payload&gt;.&lt;base64url P1363 signature&gt;</c>. The payload
/// bytes must match the management API's <c>CollectorEnrolment.AssertionBytes</c> and the
/// Rust collector byte for byte. The signed <c>kind</c> keeps it from verifying as any other
/// Bower document.
/// </summary>
public static class ManagementAssertion
{
    public const string Prefix = "bwc1.";
    public const string Kind = "bower.collector-assertion/v1";

    /// <summary>Validity window of each assertion. Management accepts at most 10 minutes.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    public static byte[] SignedBytes(
        string collectorId,
        string credentialId,
        string issuedAt,
        string expiresAt,
        string nonce) =>
        CanonicalJson.Bytes(new JsonObject
        {
            ["kind"] = Kind,
            ["collectorId"] = collectorId,
            ["credentialId"] = credentialId,
            ["issuedAt"] = issuedAt,
            ["expiresAt"] = expiresAt,
            ["nonce"] = nonce
        });

    public static string Create(string collectorId, string credentialId, string privateKeyPem, DateTimeOffset now)
    {
        byte[] payload = SignedBytes(
            collectorId,
            credentialId,
            ManagementCommandVerifier.FormatTimestamp(now),
            ManagementCommandVerifier.FormatTimestamp(now + Lifetime),
            Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)));
        DetachedSignature signature = DetachedSigner.Sign(payload, privateKeyPem);
        return Prefix + Base64Url.EncodeToString(payload) + "."
            + Base64Url.EncodeToString(Convert.FromBase64String(signature.Value));
    }
}

/// <summary>
/// The collector's key-bound management credential, persisted owner-only in
/// <c>management-credential/credential.json</c>. Same format in the C# and Rust collectors.
/// Holds the private key (never sent) and hashes of tokens already exchanged or refused, never a token.
/// </summary>
public sealed record ManagementCredentialState(
    int SchemaVersion,
    string CollectorId,
    string? CredentialId,
    string? PrivateKeyPem,
    string? ExpiresAt,
    string? PendingPrivateKeyPem,
    string? ConsumedTokenSha256,
    string? RefusedTokenSha256)
{
    public const int CurrentSchemaVersion = 1;
}

/// <summary>Reads and writes the credential file. Writes are atomic and owner-only.</summary>
public sealed class ManagementCredentialStore(string directory)
{
    public const string FileName = "credential.json";

    private readonly string path = Path.Combine(directory, FileName);

    /// <summary>Null when there is no file. A file that cannot be read is treated as no credential.</summary>
    public ManagementCredentialState? Load()
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            ManagementCredentialState? state = JsonSerializer.Deserialize(
                File.ReadAllBytes(path), CollectorJsonContext.Default.ManagementCredentialState);
            return state is { SchemaVersion: ManagementCredentialState.CurrentSchemaVersion, CollectorId: not null }
                ? state
                : null;
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Save(ManagementCredentialState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        string temporary = Path.Combine(directory, $".{FileName}.{Guid.NewGuid():N}.tmp");
        FileStreamOptions options = new()
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        try
        {
            using (FileStream stream = new(temporary, options))
            {
                stream.Write(JsonSerializer.SerializeToUtf8Bytes(state, CollectorJsonContext.Default.ManagementCredentialState));
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}

/// <summary>
/// Token enrolment and credential rotation for collectors without an Azure identity (#109).
/// Enrols once per token: the collector generates a P-256 key, persists it, then exchanges
/// the one-time token and the public key for a credential (the record waits in Pending).
/// Rotation registers a new key under the current credential; management keeps the old one
/// valid until the new one is first used, so no request is ever refused. Never logs or
/// stores a token, key or assertion.
/// </summary>
public sealed partial class ManagementEnrolment(
    IHttpClientFactory httpClientFactory,
    CollectorSettings settings,
    PolicyBundle bundle,
    TimeProvider clock,
    ILogger<ManagementEnrolment> logger) : IDisposable
{
    /// <summary>Scheduled rotation: when 10 of the credential's 30 days remain.</summary>
    public static readonly TimeSpan RotateBefore = TimeSpan.FromDays(10);

    public const int MaximumTokenFileBytes = 1024;
    public const int MaximumResponseBytes = 16 * 1024;

    public const string CredentialRotated = "credential-rotated";
    public const string RotationRefused = "rotation-refused";
    public const string RotationFailed = "rotation-failed";
    public const string NotEnrolled = "not-enrolled";

    private readonly ManagementCredentialStore store = new(settings.ManagementCredentialDirectory);
    private readonly SemaphoreSlim gate = new(1, 1);
    private ManagementCredentialState? state;
    private bool loaded;

    /// <summary>The persisted state (loaded on first use).</summary>
    public ManagementCredentialState? State
    {
        get
        {
            EnsureLoaded();
            return Volatile.Read(ref state);
        }
    }

    /// <summary>True when an unexpired credential for this collector id is held.</summary>
    public bool Enrolled => Usable(State, clock.GetUtcNow());

    /// <summary>A fresh assertion for the current credential.</summary>
    public string CreateAssertion()
    {
        ManagementCredentialState? current = State;
        DateTimeOffset now = clock.GetUtcNow();
        if (!Usable(current, now))
        {
            throw new Azure.Identity.CredentialUnavailableException(
                "The collector has no usable management credential; enrol with a new token.");
        }

        return ManagementAssertion.Create(current!.CollectorId, current.CredentialId!, current.PrivateKeyPem!, now);
    }

    /// <summary>
    /// Enrols when the token file holds a token not yet exchanged or refused. Transient
    /// failures leave the generated key pending so a retry reuses it (management treats a
    /// retry with the same token, collector and key as the same exchange).
    /// </summary>
    public async Task EnsureEnrolledAsync(CancellationToken cancellationToken)
    {
        string? token = ReadToken();
        if (token is null)
        {
            if (!Enrolled)
            {
                LogNotEnrolled(logger);
            }

            return;
        }

        string tokenHash = Sha256Hex.Of(token);
        ManagementCredentialState? current = State;
        if (current is not null && string.Equals(current.CollectorId, settings.CollectorId, StringComparison.Ordinal)
            && (tokenHash == current.ConsumedTokenSha256 || tokenHash == current.RefusedTokenSha256))
        {
            RemoveTokenAfterUse(tokenHash);
            if (!Enrolled)
            {
                LogNotEnrolled(logger);
            }

            return;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            current = Mine(State);
            string pending = current?.PendingPrivateKeyPem ?? DetachedSigner.GenerateKeyPair().PrivateKeyPem;
            ManagementCredentialState prepared = (current ?? Empty()) with { PendingPrivateKeyPem = pending };
            Save(prepared);

            string publicKey = PublicKeyPem(pending);
            using HttpRequestMessage request = new(HttpMethod.Post, "api/collectors/enrol")
            {
                Content = JsonContent.Create(
                    new CollectorEnrolmentRequest(
                        token,
                        settings.CollectorId,
                        System.Environment.MachineName,
                        settings.Environment,
                        settings.Version,
                        settings.ConfigurationHash(),
                        bundle.Hash,
                        publicKey),
                    CollectorJsonContext.Default.CollectorEnrolmentRequest)
            };
            using HttpResponseMessage response = await httpClientFactory
                .CreateClient(ManagementHeartbeatJob.HttpClientName)
                .SendAsync(request, cancellationToken);
            if (IsDefinitiveRefusal(response.StatusCode))
            {
                Save(prepared with { PendingPrivateKeyPem = null, RefusedTokenSha256 = tokenHash });
                LogEnrolmentRefused(logger, (int)response.StatusCode);
                RemoveTokenAfterUse(tokenHash);
                return;
            }

            response.EnsureSuccessStatusCode();
            IssuedCollectorCredential issued = await ReadIssuedAsync(response, pending, cancellationToken);
            Save(prepared with
            {
                CredentialId = issued.CredentialId,
                PrivateKeyPem = pending,
                ExpiresAt = ManagementCommandVerifier.FormatTimestamp(issued.ExpiresAt),
                PendingPrivateKeyPem = null,
                ConsumedTokenSha256 = tokenHash,
                RefusedTokenSha256 = null
            });
            LogEnrolled(logger, issued.CredentialId, issued.Status);
            RemoveTokenAfterUse(tokenHash);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Rotates when the credential is within <see cref="RotateBefore"/> of expiry.</summary>
    public async Task RotateIfDueAsync(CancellationToken cancellationToken)
    {
        ManagementCredentialState? current = State;
        DateTimeOffset now = clock.GetUtcNow();
        if (Usable(current, now) && ParseExpiry(current!) - now <= RotateBefore)
        {
            (string status, string code) = await RotateAsync(cancellationToken);
            if (status != ManagementCommandResults.Succeeded)
            {
                LogRotationFailed(logger, code);
            }
        }
    }

    /// <summary>
    /// Registers a new key under the current credential and switches to it. The new key is
    /// persisted as pending first, so a lost response is retried with the same key.
    /// </summary>
    public async Task<(string Status, string Code)> RotateAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            ManagementCredentialState? current = Mine(State);
            if (!Usable(current, clock.GetUtcNow()))
            {
                return (ManagementCommandResults.Failed, NotEnrolled);
            }

            string pending = current!.PendingPrivateKeyPem ?? DetachedSigner.GenerateKeyPair().PrivateKeyPem;
            ManagementCredentialState prepared = current with { PendingPrivateKeyPem = pending };
            Save(prepared);
            using HttpRequestMessage request = new(
                HttpMethod.Post,
                $"api/collectors/{Uri.EscapeDataString(settings.CollectorId)}/credentials/rotate")
            {
                Headers =
                {
                    Authorization = new AuthenticationHeaderValue(
                        "Bearer",
                        ManagementAssertion.Create(
                            current.CollectorId, current.CredentialId!, current.PrivateKeyPem!, clock.GetUtcNow()))
                },
                Content = JsonContent.Create(
                    new CollectorCredentialRotationRequest(PublicKeyPem(pending)),
                    CollectorJsonContext.Default.CollectorCredentialRotationRequest)
            };
            HttpResponseMessage response;
            try
            {
                response = await httpClientFactory
                    .CreateClient(ManagementHeartbeatJob.HttpClientName)
                    .SendAsync(request, cancellationToken);
            }
            catch (HttpRequestException)
            {
                return (ManagementCommandResults.Failed, RotationFailed);
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return (ManagementCommandResults.Failed, RotationFailed);
            }

            using (response)
            {
                if (IsDefinitiveRefusal(response.StatusCode))
                {
                    // Start again with a fresh key next time; the current credential still works.
                    Save(prepared with { PendingPrivateKeyPem = null });
                    return (ManagementCommandResults.Failed, RotationRefused);
                }

                if (!response.IsSuccessStatusCode)
                {
                    return (ManagementCommandResults.Failed, RotationFailed);
                }

                IssuedCollectorCredential issued;
                try
                {
                    issued = await ReadIssuedAsync(response, pending, cancellationToken);
                }
                catch (InvalidDataException)
                {
                    return (ManagementCommandResults.Failed, RotationFailed);
                }

                Save(prepared with
                {
                    CredentialId = issued.CredentialId,
                    PrivateKeyPem = pending,
                    ExpiresAt = ManagementCommandVerifier.FormatTimestamp(issued.ExpiresAt),
                    PendingPrivateKeyPem = null
                });
                LogRotated(logger, issued.CredentialId);
                return (ManagementCommandResults.Succeeded, CredentialRotated);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose() => gate.Dispose();

    private static bool IsDefinitiveRefusal(HttpStatusCode status) =>
        status is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
            or HttpStatusCode.Conflict;

    private bool Usable(ManagementCredentialState? candidate, DateTimeOffset now) =>
        candidate is { CredentialId: not null, PrivateKeyPem: not null, ExpiresAt: not null }
        && string.Equals(candidate.CollectorId, settings.CollectorId, StringComparison.Ordinal)
        && ParseExpiry(candidate) > now;

    private static DateTimeOffset ParseExpiry(ManagementCredentialState candidate) =>
        ManagementCommandVerifier.TryParseTimestamp(candidate.ExpiresAt ?? string.Empty, out DateTimeOffset value)
            ? value
            : DateTimeOffset.MinValue;

    /// <summary>The state when it belongs to this collector id; another id's credential is never used.</summary>
    private ManagementCredentialState? Mine(ManagementCredentialState? candidate) =>
        candidate is not null && string.Equals(candidate.CollectorId, settings.CollectorId, StringComparison.Ordinal)
            ? candidate
            : null;

    private ManagementCredentialState Empty() =>
        new(ManagementCredentialState.CurrentSchemaVersion, settings.CollectorId, null, null, null, null, null, null);

    private void Save(ManagementCredentialState next)
    {
        store.Save(next);
        Volatile.Write(ref state, next);
    }

    private void EnsureLoaded()
    {
        if (Volatile.Read(ref loaded))
        {
            return;
        }

        lock (store)
        {
            if (!loaded)
            {
                state = store.Load();
                Volatile.Write(ref loaded, true);
            }
        }
    }

    /// <summary>The token from the file, or null when unset, missing, unreadable or oversized.</summary>
    private string? ReadToken()
    {
        if (settings.ManagementEnrolmentTokenFile is not { } file)
        {
            return null;
        }

        try
        {
            FileInfo info = new(file);
            if (!info.Exists || info.Length is 0 or > MaximumTokenFileBytes)
            {
                return null;
            }

            string token = File.ReadAllText(file).Trim();
            return token.Length == 0 ? null : token;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// With <see cref="CollectorSettings.ManagementEnrolmentTokenRemoveAfterUse"/>, deletes the
    /// token file once its outcome is recorded in the credential file. Only the token whose
    /// hash was recorded is deleted, so a newer token written meanwhile is kept. A failure is
    /// logged (never the token) and retried on the next enrolment attempt.
    /// </summary>
    private void RemoveTokenAfterUse(string tokenHash)
    {
        if (!settings.ManagementEnrolmentTokenRemoveAfterUse || settings.ManagementEnrolmentTokenFile is not { } file
            || ReadToken() is not { } token || Sha256Hex.Of(token) != tokenHash)
        {
            return;
        }

        try
        {
            File.Delete(file);
            LogTokenRemoved(logger);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            LogTokenNotRemoved(logger, exception.GetType().Name);
        }
    }

    private static string PublicKeyPem(string privateKeyPem)
    {
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(privateKeyPem);
        return key.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>The issued credential, which must name the key this collector generated.</summary>
    private static async Task<IssuedCollectorCredential> ReadIssuedAsync(
        HttpResponseMessage response,
        string privateKeyPem,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw new InvalidDataException("Management credential response is too large.");
        }

        byte[] body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        IssuedCollectorCredential? issued;
        try
        {
            issued = body.Length > MaximumResponseBytes
                ? null
                : JsonSerializer.Deserialize(body, CollectorJsonContext.Default.IssuedCollectorCredential);
        }
        catch (JsonException)
        {
            issued = null;
        }

        return issued is { CredentialId: not null }
            && string.Equals(issued.CredentialId, DetachedSigner.KeyIdFromPublicKeyPem(PublicKeyPem(privateKeyPem)),
                StringComparison.Ordinal)
            ? issued
            : throw new InvalidDataException("Management credential response is invalid.");
    }

    [LoggerMessage(
        EventId = 1401,
        Level = LogLevel.Information,
        Message = "Collector enrolled with management credential {CredentialId}; status {Status}.")]
    private static partial void LogEnrolled(ILogger logger, string credentialId, string status);

    [LoggerMessage(
        EventId = 1402,
        Level = LogLevel.Warning,
        Message = "Management refused the enrolment token (HTTP {StatusCode}); supply a new token to enrol.")]
    private static partial void LogEnrolmentRefused(ILogger logger, int statusCode);

    [LoggerMessage(
        EventId = 1403,
        Level = LogLevel.Warning,
        Message = "Collector has no usable management credential; set BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE to a new enrolment token.")]
    private static partial void LogNotEnrolled(ILogger logger);

    [LoggerMessage(
        EventId = 1404,
        Level = LogLevel.Information,
        Message = "Management credential rotated to {CredentialId}.")]
    private static partial void LogRotated(ILogger logger, string credentialId);

    [LoggerMessage(
        EventId = 1405,
        Level = LogLevel.Warning,
        Message = "Scheduled management credential rotation failed ({Code}); the current credential stays in use.")]
    private static partial void LogRotationFailed(ILogger logger, string code);

    [LoggerMessage(
        EventId = 1406,
        Level = LogLevel.Information,
        Message = "Used enrolment token file removed.")]
    private static partial void LogTokenRemoved(ILogger logger);

    [LoggerMessage(
        EventId = 1407,
        Level = LogLevel.Warning,
        Message = "Could not remove the used enrolment token file ({ErrorType}); delete it by hand.")]
    private static partial void LogTokenNotRemoved(ILogger logger, string errorType);
}

/// <summary>
/// Supplies the enrolled credential's assertion where the management jobs expect a bearer
/// token, so the heartbeat and privacy profile requests are unchanged. Scopes are ignored.
/// </summary>
public sealed class EnrolledManagementCredential(ManagementEnrolment enrolment, TimeProvider clock) : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new(enrolment.CreateAssertion(), clock.GetUtcNow() + ManagementAssertion.Lifetime);

    public override ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}

internal sealed record CollectorEnrolmentRequest(
    string Token,
    string CollectorId,
    string MachineName,
    string Environment,
    string Version,
    string ConfigurationHash,
    string PolicyHash,
    string PublicKey);

internal sealed record CollectorCredentialRotationRequest(string PublicKey);

internal sealed record IssuedCollectorCredential(
    string CollectorId,
    string CredentialId,
    string Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);

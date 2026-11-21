using System.Security.Claims;
using Bower.Evidence;

namespace Bower.Management.Api;

/// <summary>
/// Trusted ECDSA P-256 public keys permitted to sign air-gapped offline site reports
/// (<c>BOWER_OFFLINE_IMPORT_TRUSTED_KEYS</c>). Fail-closed: when unconfigured, offline
/// imports are refused with HTTP 503.
/// </summary>
public sealed class OfflineSiteTrustKeys(IReadOnlyList<string> publicKeyPems)
{
    public const string SettingName = "BOWER_OFFLINE_IMPORT_TRUSTED_KEYS";

    public IReadOnlyList<string> PublicKeyPems { get; } = publicKeyPems;

    public bool IsConfigured => PublicKeyPems.Count > 0;

    public static OfflineSiteTrustKeys FromConfiguration(IConfiguration configuration)
    {
        string? raw = configuration[SettingName];
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new OfflineSiteTrustKeys([]);
        }

        List<string> pems = [];
        foreach (string path in raw.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            pems.Add(File.ReadAllText(path));
        }

        return new OfflineSiteTrustKeys(pems);
    }
}

internal static class OfflineSiteEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost(
                "/fleet/offline-import",
                async (
                    SignedOfflineSiteReport signedReport,
                    ClaimsPrincipal user,
                    OfflineSiteTrustKeys trustKeys,
                    ManagementStore store,
                    TimeProvider clock,
                    CancellationToken cancellationToken) =>
                {
                    if (!trustKeys.IsConfigured)
                    {
                        return Results.Json(
                            new ErrorResponse("Offline bundle import is not enabled (configure BOWER_OFFLINE_IMPORT_TRUSTED_KEYS)."),
                            ManagementJsonContext.Default.ErrorResponse,
                            statusCode: StatusCodes.Status503ServiceUnavailable);
                    }

                    if (!AirGappedBundle.VerifyOfflineSiteReport(signedReport, trustKeys.PublicKeyPems))
                    {
                        return Results.BadRequest(new ErrorResponse("Offline site report signature is missing, invalid or untrusted."));
                    }

                    DateTimeOffset now = clock.GetUtcNow();
                    string actorId = user.FindFirstValue("oid") ?? user.Identity?.Name ?? "unknown";
                    string actorName = user.FindFirstValue("name") ?? user.Identity?.Name ?? actorId;
                    try
                    {
                        _ = await store.ImportOfflineSiteReportAsync(signedReport.Report, actorId, actorName, now, cancellationToken);
                        FleetRecord fleet = await store.FleetAsync(now, cancellationToken);
                        FleetCollector? collector = fleet.Collectors.FirstOrDefault(
                            item => string.Equals(item.Id, signedReport.Report.CollectorId, StringComparison.Ordinal));
                        return collector is null ? Results.Ok(fleet) : Results.Ok(collector);
                    }
                    catch (OfflineBundleChainException exception)
                    {
                        return Results.Conflict(new ErrorResponse(exception.Message));
                    }
                    catch (ArgumentException exception)
                    {
                        return Results.BadRequest(new ErrorResponse(exception.Message));
                    }
                })
            .RequireAuthorization("Operate");
    }
}

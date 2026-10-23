namespace Bower.Evidence;

/// <summary>
/// Maps evidence results to Australian control requirements. Statuses are evidence
/// statements for an assessor, not compliance determinations. Identifiers follow the
/// ISM release current when this was written; confirm them against your ISM version.
/// </summary>
public static class ControlMapping
{
    public const int IsmMinimumRetentionDays = 365;

    public static IReadOnlyList<ControlRecord> Map(string mode, ArrivalRecord arrival, RetentionRecord? retention)
    {
        bool verified = mode == EvidenceModes.Verified && arrival.Found;
        string delivery = verified
            ? $"Canary {arrival.Table} row found by KQL after {arrival.LatencySeconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "?"} s."
            : mode == EvidenceModes.Simulated
                ? "Simulated: no destination query was run."
                : $"Canary not found ({arrival.QueryError ?? "unknown"}).";
        string deliveryStatus = verified ? "evidenced" : mode == EvidenceModes.Simulated ? "not-assessed" : "not-evidenced";

        string retentionStatus;
        string retentionEvidence;
        if (retention?.TotalDays is int total)
        {
            retentionStatus = total >= IsmMinimumRetentionDays ? "not-assessed" : "not-evidenced";
            retentionEvidence = $"Table total retention {total} days (plan {retention.Plan ?? "unknown"}). " +
                "Configured total retention does not establish searchable retention or historical data availability.";
        }
        else
        {
            retentionStatus = "not-assessed";
            retentionEvidence = "Retention not read (no workspace resource id or no ARM read access).";
        }

        return
        [
            new("ISM", "ISM-0580", "A security monitoring (event logging) policy is implemented; events are centrally logged.",
                deliveryStatus, delivery),
            new("ISM", "ISM-1988", "Event logs are retained and searchable for at least 12 months.",
                retentionStatus, retentionEvidence),
            new("Essential Eight", "E8-ML2-LOGGING", "Event logs are centrally stored and protected from unauthorised modification and deletion.",
                "not-assessed", delivery + " Protection against modification and deletion was not assessed."),
            new("Privacy Act", "APP-11", "Technical measures protect personal information (redaction before data leaves the host).",
                "not-assessed",
                "Canary arrival and policy hashes do not establish redaction effectiveness. Independent privacy tests were not assessed.")
        ];
    }
}

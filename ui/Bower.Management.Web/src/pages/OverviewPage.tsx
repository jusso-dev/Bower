import { ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import {
  Page,
  CollectorTable,
  Metric,
  CoverageRow,
  EmptyState,
  ResourceState
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate, shortHash } from "../lib/format";
import type { Overview, PrivacyProfileDrift } from "../types";

export function OverviewPage() {
  const { data, loading, error } = useResource<Overview>("/api/overview");
  return (
    <Page
      title="Fleet posture"
      description="Exceptions first: approval, collection, queue, delivery and privacy profile conditions needing action."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(overview) => {
          // Reporting + degraded is every known source; unknown is the part of degraded
          // whose collector has no fresh heartbeat or is not active.
          const totalSources = overview.sourcesReporting + overview.sourcesDegraded;
          const unknownSources = overview.sourcesUnknown ?? 0;
          const privacyExceptions = overview.privacyProfileExceptions ?? [];
          return (
            <>
              <div className="metric-strip" aria-label="Fleet summary">
                <Metric label="Collectors" value={overview.totalCollectors} />
                <Metric label="Pending" value={overview.pendingApproval} tone="warning" />
                <Metric label="Unhealthy" value={overview.unhealthyCollectors} tone="danger" />
                <Metric label="Stale" value={overview.staleCollectors} tone="warning" />
                <Metric label="Queued" value={overview.totalQueueDepth} />
                <Metric label="Policy drift" value={overview.policyDrift ?? 0} tone="danger" />
                <Metric
                  label="Privacy drift"
                  value={overview.privacyProfileDrift ?? 0}
                  tone="danger"
                />
                <Metric label="Dead letters" value={overview.deadLettered ?? 0} tone="warning" />
              </div>
              <div className="workbench-grid">
                <section className="sheet">
                  <div className="section-heading">
                    <h2>Exceptions</h2>
                    <span>{overview.exceptions.length} open</span>
                  </div>
                  {overview.exceptions.length ? (
                    <CollectorTable collectors={overview.exceptions} compact />
                  ) : (
                    <EmptyState
                      icon={<ShieldCheck aria-hidden="true" />}
                      title="No fleet exceptions"
                      detail="All enrolled collectors are reporting without a detected approval, delivery or privacy profile exception."
                    />
                  )}
                </section>
                <aside className="coverage-panel">
                  <h2>Source coverage</h2>
                  <CoverageRow
                    label="Reporting"
                    value={overview.sourcesReporting}
                    total={totalSources}
                  />
                  <CoverageRow
                    label="Degraded"
                    value={overview.sourcesDegraded - unknownSources}
                    total={totalSources}
                    tone="warning"
                  />
                  <CoverageRow
                    label="Unknown"
                    value={unknownSources}
                    total={totalSources}
                    tone="warning"
                  />
                  <p>
                    Coverage reflects fresh heartbeats from active collectors. Sources of stale,
                    pending, suspended or revoked collectors, and pending sources not yet seen
                    inside their allowance, are unknown and stay in the total.
                    It does not prove destination queryability; use a Bower Evidence Bundle for
                    that claim.
                  </p>
                </aside>
              </div>
              {privacyExceptions.length > 0 && (
                <PrivacyProfileDriftTable
                  records={privacyExceptions}
                  total={overview.privacyProfileDrift ?? privacyExceptions.length}
                />
              )}
            </>
          );
        }}
      </ResourceState>
    </Page>
  );
}

function PrivacyProfileDriftTable({
  records,
  total
}: {
  records: PrivacyProfileDrift[];
  /** Every drifting collector; the API lists at most 12. */
  total: number;
}) {
  return (
    <section className="sheet section-gap" aria-labelledby="privacy-drift-title">
      <div className="section-heading">
        <h2 id="privacy-drift-title">Privacy profile not applied</h2>
        <span>
          {records.length < total
            ? `${records.length} of ${total} shown`
            : "Assigned version against the hash in the latest heartbeat"}
        </span>
      </div>
      <div className="responsive-table">
        <table>
          <thead>
            <tr>
              <th>Machine</th>
              <th>Assigned</th>
              <th>Reported</th>
              <th>Evidence</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {records.map((record) => (
              <tr key={record.collectorId}>
                <td data-label="Machine">
                  <strong>{record.machineName}</strong>
                  <small>{record.collectorId}</small>
                </td>
                <td data-label="Assigned">
                  <span title={record.assignedHash}>
                    {record.profileId}@{record.version} · {shortHash(record.assignedHash)}
                  </span>
                  <small>
                    Revision {record.assignmentRevision} · {formatDate(record.assignedAt)}
                  </small>
                </td>
                <td data-label="Reported">
                  <span
                    className={`policy-label policy-label--wrap ${
                      record.mismatchConfirmed ? "policy-label--drift" : "policy-label--unset"
                    }`}
                    title={record.observedHash ?? undefined}
                  >
                    {record.mismatchConfirmed ? "Not applied" : "Awaiting heartbeat"} ·{" "}
                    {shortHash(record.observedHash)}
                  </span>
                </td>
                <td data-label="Evidence">Heartbeat {formatDate(record.observedAt)}</td>
                <td data-label="Details">
                  <Link
                    to={`/privacy-profiles?version=${encodeURIComponent(record.versionId)}`}
                    aria-label={`Privacy profile details for ${record.machineName}`}
                  >
                    Privacy profile details
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

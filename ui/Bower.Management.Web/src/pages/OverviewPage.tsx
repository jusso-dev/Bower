import { ShieldCheck } from "lucide-react";
import {
  Page,
  CollectorTable,
  Metric,
  CoverageRow,
  EmptyState,
  ResourceState
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import type { Overview } from "../types";

export function OverviewPage() {
  const { data, loading, error } = useResource<Overview>("/api/overview");
  return (
    <Page
      title="Fleet posture"
      description="Exceptions first: approval, collection, queue and delivery conditions needing action."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(overview) => (
          <>
            <div className="metric-strip" aria-label="Fleet summary">
              <Metric label="Collectors" value={overview.totalCollectors} />
              <Metric label="Pending" value={overview.pendingApproval} tone="warning" />
              <Metric label="Unhealthy" value={overview.unhealthyCollectors} tone="danger" />
              <Metric label="Stale" value={overview.staleCollectors} tone="warning" />
              <Metric label="Queued" value={overview.totalQueueDepth} />
              <Metric label="Policy drift" value={overview.policyDrift ?? 0} tone="danger" />
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
                    detail="All enrolled collectors are reporting without a detected approval or delivery exception."
                  />
                )}
              </section>
              <aside className="coverage-panel">
                <h2>Source coverage</h2>
                <CoverageRow
                  label="Reporting"
                  value={overview.sourcesReporting}
                  total={overview.sourcesReporting + overview.sourcesDegraded}
                />
                <CoverageRow
                  label="Degraded"
                  value={overview.sourcesDegraded}
                  total={overview.sourcesReporting + overview.sourcesDegraded}
                  tone="warning"
                />
                <p>
                  Coverage reflects collector heartbeats. It does not prove destination
                  queryability; use a Bower Evidence Bundle for that claim.
                </p>
              </aside>
            </div>
          </>
        )}
      </ResourceState>
    </Page>
  );
}

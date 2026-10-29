import { CheckCircle2, KeyRound } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../api";
import { SourcePlanView } from "../components/SourcePlanView";
import { EmptyState, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Access, SourceSetupRequestDetail, SourceSetupRequestSummary } from "../types";

/**
 * Source setup requests waiting for a decision. The API refuses a decision by the requester
 * (four-eyes); the console says so up front instead of offering a button that cannot work.
 */
export function SourceSetupApprovals({ access, canApprove }: { access: Access | null; canApprove: boolean }) {
  const [refresh, setRefresh] = useState(0);
  const requests = useResource<SourceSetupRequestSummary[]>("/api/sources/requests", refresh);

  return (
    <section className="sheet section-gap" aria-labelledby="source-approvals-heading">
      <div className="section-heading">
        <h2 id="source-approvals-heading">Source setup requests</h2>
        <span>Two people: one asks, another decides</span>
      </div>
      <ResourceState loading={requests.loading} error={requests.error} data={requests.data}>
        {(items) => {
          const pending = items.filter((item) => item.status === "pending-review");
          return pending.length ? (
            <div className="approval-list">
              {pending.map((item) => (
                <SourceSetupApproval
                  key={item.id}
                  id={item.id}
                  access={access}
                  canApprove={canApprove}
                  onDecided={() => setRefresh((value) => value + 1)}
                />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<CheckCircle2 aria-hidden="true" />}
              title="No source setups waiting"
              detail="When someone sets up a source on the Sources page, it waits here for another person's decision."
            />
          );
        }}
      </ResourceState>
    </section>
  );
}

function SourceSetupApproval({
  id,
  access,
  canApprove,
  onDecided
}: {
  id: string;
  access: Access | null;
  canApprove: boolean;
  onDecided: () => void;
}) {
  const api = useApi();
  const request = useResource<SourceSetupRequestDetail>(`/api/sources/requests/${encodeURIComponent(id)}`);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(action: "approve" | "reject") {
    if (!reason.trim()) {
      setError("Enter a reason before recording the decision.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api(`/api/sources/requests/${encodeURIComponent(id)}/${action}`, {
        method: "POST",
        body: JSON.stringify({ reason: reason.trim() })
      });
      onDecided();
    } catch (decisionError) {
      setError(decisionError instanceof Error ? decisionError.message : "Decision failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ResourceState loading={request.loading} error={request.error} data={request.data}>
      {(detail) => {
        const own = access !== null && access.objectId === detail.requestedByObjectId;
        return (
          <article className="approval-item approval-item--source">
            <div>
              <h3>
                {detail.typeTitle} on {detail.collectorId}
              </h3>
              <dl className="detail-list">
                <div>
                  <dt>Asked for by</dt>
                  <dd>
                    {detail.requestedByName}, {formatDate(detail.requestedAt)}
                  </dd>
                </div>
                <div>
                  <dt>Reason</dt>
                  <dd>{detail.reason}</dd>
                </div>
              </dl>
              <details className="source-approval__details">
                <summary>What will be installed</summary>
                <SourcePlanView plan={detail.plan} headingLevel={4} />
              </details>
              <p className="form-help">
                <Link to={`/sources?request=${detail.id}`}>Open the request</Link>
              </p>
            </div>
            {!canApprove ? (
              <div className="permission-note">
                <KeyRound aria-hidden="true" />
                <p>
                  Viewing only. An Entra assignment for <code>Bower.Approver</code> or{" "}
                  <code>Bower.Administrator</code> is required to decide.
                </p>
              </div>
            ) : own ? (
              <div className="permission-note">
                <KeyRound aria-hidden="true" />
                <p>You asked for this source, so another approver must decide it.</p>
              </div>
            ) : (
              <form
                className="approval-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void decide("approve");
                }}
              >
                {error && (
                  <div className="alert alert--danger" role="alert">
                    {error}
                  </div>
                )}
                <label htmlFor={`source-reason-${detail.id}`}>Decision reason for this source</label>
                <textarea
                  id={`source-reason-${detail.id}`}
                  value={reason}
                  maxLength={500}
                  required
                  aria-describedby={`source-reason-help-${detail.id}`}
                  placeholder="Example: matches change BWR-210 and the firewall team's sender list"
                  onChange={(event) => setReason(event.target.value)}
                />
                <span className="approval-help" id={`source-reason-help-${detail.id}`}>
                  Required. Recorded in the management audit log.
                </span>
                <div className="button-row">
                  <button className="button button--primary" type="submit" disabled={busy}>
                    {busy ? "Recording…" : "Approve source"}
                  </button>
                  <button
                    className="button button--danger"
                    type="button"
                    disabled={busy}
                    onClick={() => void decide("reject")}
                  >
                    Reject
                  </button>
                </div>
              </form>
            )}
          </article>
        );
      }}
    </ResourceState>
  );
}

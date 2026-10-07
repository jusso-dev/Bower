import { CheckCircle2, KeyRound } from "lucide-react";
import { useState } from "react";
import { useApi } from "../api";
import {
  Page,
  HistoryTable,
  StatusBadge,
  EmptyState,
  ResourceState
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Access, Approval, Collector } from "../types";

export function ApprovalsPage() {
  const api = useApi();
  const [refresh, setRefresh] = useState(0);
  const pending = useResource<Collector[]>("/api/collectors?status=Pending", refresh);
  const history = useResource<Approval[]>("/api/approvals", refresh);
  const access = useResource<Access>("/api/access/me");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const canApprove =
    access.data?.roles.some(
      (role) => role === "Bower.Approver" || role === "Bower.Administrator"
    ) ?? false;

  async function decide(
    formElement: HTMLFormElement,
    collectorId: string,
    action: "approve" | "reject"
  ) {
    const form = new FormData(formElement);
    const reason = String(form.get("reason") ?? "").trim();
    if (!reason) {
      setActionError("Enter a reason before recording the decision.");
      return;
    }
    setBusyId(collectorId);
    setActionError(null);
    try {
      await api(`/api/approvals/${encodeURIComponent(collectorId)}/${action}`, {
        method: "POST",
        body: JSON.stringify({ reason })
      });
      setRefresh((value) => value + 1);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Decision failed.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Page
      title="Enrollment approvals"
      description="A collector cannot heartbeat as active until an authorized approver records a decision."
    >
      {actionError && <div className="alert alert--danger">{actionError}</div>}
      <ResourceState loading={pending.loading} error={pending.error} data={pending.data}>
        {(collectors) =>
          collectors.length ? (
            <div className="approval-list">
              {collectors.map((collector) => (
                <article className="approval-item" key={collector.id}>
                  <div>
                    <StatusBadge status={collector.status} />
                    <h2>{collector.machineName}</h2>
                    <dl className="detail-list">
                      <div>
                        <dt>Collector ID</dt>
                        <dd>{collector.id}</dd>
                      </div>
                      <div>
                        <dt>Environment</dt>
                        <dd>{collector.environment}</dd>
                      </div>
                      <div>
                        <dt>Principal</dt>
                        <dd>{collector.principalObjectId}</dd>
                      </div>
                    </dl>
                  </div>
                  {canApprove ? (
                    <form
                      className="approval-form"
                      onSubmit={(event) => {
                        event.preventDefault();
                        void decide(event.currentTarget, collector.id, "approve");
                      }}
                    >
                    <label htmlFor={`reason-${collector.id}`}>Decision reason</label>
                    <textarea
                      id={`reason-${collector.id}`}
                      name="reason"
                      maxLength={500}
                      aria-describedby={`reason-help-${collector.id}`}
                      placeholder="Example: matched approved server inventory request BWR-142"
                      required
                    />
                    <span
                      className="approval-help"
                      id={`reason-help-${collector.id}`}
                    >
                      Required. Recorded in approval history and management audit.
                    </span>
                    <div className="button-row">
                      <button
                        className="button button--primary"
                        type="submit"
                        disabled={busyId === collector.id}
                      >
                        {busyId === collector.id ? "Recording…" : "Approve"}
                      </button>
                      <button
                        className="button button--danger"
                        type="button"
                        disabled={busyId === collector.id}
                        onClick={(event) => {
                          const form = event.currentTarget.form;
                          if (form) {
                            void decide(form, collector.id, "reject");
                          }
                        }}
                      >
                        Reject
                      </button>
                    </div>
                    </form>
                  ) : (
                    <div className="permission-note">
                      <KeyRound aria-hidden="true" />
                      <p>
                        Viewing only. An Entra assignment for{" "}
                        <code>Bower.Approver</code> or{" "}
                        <code>Bower.Administrator</code> is required to decide.
                      </p>
                    </div>
                  )}
                </article>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<CheckCircle2 aria-hidden="true" />}
              title="Approval queue clear"
              detail="New collector identities will remain pending here until an approver records a reasoned decision."
            />
          )
        }
      </ResourceState>

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Decision history</h2>
          <span>Latest 250</span>
        </div>
        <ResourceState loading={history.loading} error={history.error} data={history.data}>
          {(records) =>
            records.length ? (
              <HistoryTable
                headings={["When", "Collector", "Decision", "Actor", "Reason"]}
                rows={records.map((item) => [
                  formatDate(item.occurredAt),
                  item.collectorId,
                  item.action,
                  item.actorName,
                  item.reason
                ])}
              />
            ) : (
              <EmptyState
                title="No decisions recorded"
                detail="Approval and rejection decisions will appear here with actor and reason."
              />
            )
          }
        </ResourceState>
      </section>
    </Page>
  );
}

import { CheckCircle2, KeyRound } from "lucide-react";
import { useState } from "react";
import { useApi } from "../api";
import { EmptyState, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Access, PackInstallRequestRecord } from "../types";

export function PackInstallApprovals({ access, canApprove }: { access: Access | null; canApprove: boolean }) {
  const [refresh, setRefresh] = useState(0);
  const requests = useResource<PackInstallRequestRecord[]>("/api/packs/install-requests", refresh);

  return (
    <section className="sheet section-gap" aria-labelledby="pack-approvals-heading">
      <div className="section-heading">
        <h2 id="pack-approvals-heading">Pack installation requests</h2>
        <span>Two people: one asks, another decides</span>
      </div>
      <ResourceState loading={requests.loading} error={requests.error} data={requests.data}>
        {(items) => {
          const pending = Array.isArray(items)
            ? items.filter((item) => item.status === "pending-review")
            : [];
          return pending.length ? (
            <div className="approval-list">
              {pending.map((item) => (
                <PackInstallApprovalCard
                  key={item.id}
                  item={item}
                  access={access}
                  canApprove={canApprove}
                  onDecided={() => setRefresh((value) => value + 1)}
                />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<CheckCircle2 aria-hidden="true" />}
              title="No pack installs waiting"
              detail="When someone requests a pack install from the Packs page, it waits here for another person's decision."
            />
          );
        }}
      </ResourceState>
    </section>
  );
}

function PackInstallApprovalCard({
  item,
  access,
  canApprove,
  onDecided
}: {
  item: PackInstallRequestRecord;
  access: Access | null;
  canApprove: boolean;
  onDecided: () => void;
}) {
  const api = useApi();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const own = access !== null && access.objectId === item.requestedByObjectId;

  async function decide(action: "approve" | "reject") {
    if (!reason.trim()) {
      setError("Enter a reason before recording the decision.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api(`/api/packs/install-requests/${encodeURIComponent(item.id)}/${action}`, {
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
    <article className="approval-item">
      <div>
        <h3>
          {item.packName} v{item.packVersion} → {item.targetEnvironment ?? item.targetCollectorId}
        </h3>
        <dl className="detail-list">
          <div>
            <dt>Asked for by</dt>
            <dd>
              {item.requestedByName}, {formatDate(item.requestedAt)}
            </dd>
          </div>
          <div>
            <dt>Reason</dt>
            <dd>{item.reason}</dd>
          </div>
          <div>
            <dt>Signed key / Pack hash</dt>
            <dd>
              <code>{item.signedByKeyId}</code> · <code>{item.packHash.slice(0, 12)}</code>
            </dd>
          </div>
          <div>
            <dt>Population diff</dt>
            <dd>
              {item.diff.affectedCollectors.length} collector
              {item.diff.affectedCollectors.length === 1 ? "" : "s"} · {item.diff.eventTypesAdded.join(", ")}
            </dd>
          </div>
        </dl>
      </div>
      {!canApprove ? (
        <div className="permission-note">
          <KeyRound aria-hidden="true" />
          <p>
            Viewing only. <code>Bower.Approver</code> or <code>Bower.Administrator</code> is required to decide.
          </p>
        </div>
      ) : own ? (
        <div className="permission-note">
          <KeyRound aria-hidden="true" />
          <p>You requested this pack install, so another approver must decide it.</p>
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
          <label htmlFor={`pack-reason-${item.id}`}>Decision reason</label>
          <textarea
            id={`pack-reason-${item.id}`}
            value={reason}
            maxLength={500}
            required
            placeholder="Example: reviewed population diff and signed pack hash"
            onChange={(event) => setReason(event.target.value)}
          />
          <div className="button-row">
            <button className="button button--primary" type="submit" disabled={busy}>
              {busy ? "Recording…" : "Approve"}
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
}

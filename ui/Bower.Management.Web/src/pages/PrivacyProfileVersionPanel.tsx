import { KeyRound, ShieldCheck } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useApi } from "../api";
import { ResourceState, VersionStatusBadge } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { collapseUnchanged, diffLines, maxDiffLines } from "../lib/diff";
import { formatDate } from "../lib/format";
import type { Access, Collector, PrivacyProfileVersionDetail } from "../types";

export const versionDetailHeadingId = "privacy-version-detail-title";

const reviewerRoles = ["Bower.Approver", "Bower.Administrator"];

function versionPath(id: string) {
  return `/api/privacy-profiles/versions/${encodeURIComponent(id)}`;
}

/** Detail, diff, review and assignment for one privacy profile version. */
export function PrivacyProfileVersionPanel({
  id,
  access,
  collectors,
  refresh,
  onChanged
}: {
  id: string;
  access: Access | null;
  collectors: Collector[] | null;
  refresh: number;
  onChanged: (message: string) => void;
}) {
  const detail = useResource<PrivacyProfileVersionDetail>(versionPath(id), refresh);
  // Kept outside ResourceState so per-collector results survive the post-assignment reload.
  const [assignResults, setAssignResults] = useState<AssignResult[]>([]);
  return (
    <section className="sheet section-gap" aria-labelledby={versionDetailHeadingId}>
      <div className="section-heading">
        <h2 id={versionDetailHeadingId} tabIndex={-1}>
          {detail.data && detail.data.id === id
            ? `${detail.data.profileId}@${detail.data.version}`
            : "Privacy profile version"}
        </h2>
        {detail.data && detail.data.id === id && (
          <VersionStatusBadge status={detail.data.status} />
        )}
      </div>
      <div className="sheet-body">
        <ResourceState loading={detail.loading} error={detail.error} data={detail.data}>
          {(version) => (
            <div className="version-detail">
              <VersionMetadata version={version} />
              <ReviewSection version={version} access={access} onChanged={onChanged} />
              <AssignSection
                version={version}
                access={access}
                collectors={collectors}
                onChanged={onChanged}
                onResults={setAssignResults}
              />
              <div>
                <h3>Content</h3>
                <pre className="code-block code-block--tall" tabIndex={0} aria-label="Privacy profile content">
                  {version.content}
                </pre>
              </div>
              <VersionDiff version={version} />
            </div>
          )}
        </ResourceState>
        {assignResults.length > 0 && (
          <div className="result-panel section-gap" role="status">
            <h3>Assignment results</h3>
            <ul className="result-list">
              {assignResults.map((item) => (
                <li
                  key={item.collectorId}
                  className={item.ok ? "result-list__ok" : "result-list__failed"}
                >
                  <span className="mono">{item.collectorId}</span>: {item.message}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

function VersionMetadata({ version }: { version: PrivacyProfileVersionDetail }) {
  const rows: [string, string][] = [
    ["Version ID", version.id],
    ["Content hash", version.contentHash],
    ["Change summary", version.changeSummary],
    ["Description", version.description ?? "—"],
    ["Author", version.authorName ?? version.authorObjectId],
    ["Created", formatDate(version.createdAt)],
    ["Reviewer", version.reviewerName ?? "—"],
    ["Reviewed", version.reviewedAt ? formatDate(version.reviewedAt) : "—"],
    ["Review reason", version.reviewReason ?? "—"],
    ["Assigned collectors", version.assignedCollectors.toLocaleString()]
  ];
  return (
    <dl className="detail-list">
      {rows.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function ReviewSection({
  version,
  access,
  onChanged
}: {
  version: PrivacyProfileVersionDetail;
  access: Access | null;
  onChanged: (message: string) => void;
}) {
  const api = useApi();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (version.status !== "PendingReview" || !access) {
    return null;
  }
  const canReview = access.roles.some((role) => reviewerRoles.includes(role));
  if (!canReview) {
    return (
      <div className="permission-note">
        <KeyRound aria-hidden="true" />
        <p>
          Viewing only. An Entra assignment for <code>Bower.Approver</code> or{" "}
          <code>Bower.Administrator</code> is required to approve or reject a privacy profile
          version.
        </p>
      </div>
    );
  }
  // Guidance only: the API enforces the two-person rule regardless (409).
  if (access.objectId && access.objectId === version.authorObjectId) {
    return (
      <div className="permission-note">
        <KeyRound aria-hidden="true" />
        <p>You authored this version. Another approver must review it.</p>
      </div>
    );
  }

  async function decide(action: "approve" | "reject") {
    const trimmed = reason.trim();
    if (!trimmed) {
      setError("Enter a reason before recording the decision.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api<PrivacyProfileVersionDetail>(`${versionPath(version.id)}/${action}`, {
        method: "POST",
        body: JSON.stringify({ reason: trimmed })
      });
      setReason("");
      onChanged(
        `${action === "approve" ? "Approved" : "Rejected"} ${version.profileId}@${version.version}.`
      );
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Decision failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="approval-form"
      aria-labelledby="privacy-review-title"
      onSubmit={(event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        void decide("approve");
      }}
    >
      <h3 id="privacy-review-title">Review</h3>
      {error && (
        <div className="alert alert--danger" role="alert">
          {error}
        </div>
      )}
      <label htmlFor="privacy-review-reason">Decision reason</label>
      <textarea
        id="privacy-review-reason"
        value={reason}
        maxLength={500}
        required
        aria-describedby="privacy-review-help"
        placeholder="Example: reviewed diff and preview against change BWR-210"
        onChange={(event) => setReason(event.target.value)}
      />
      <span className="approval-help" id="privacy-review-help">
        Required. Recorded on the version and in management audit.
      </span>
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
  );
}

interface AssignResult {
  collectorId: string;
  ok: boolean;
  message: string;
}

function AssignSection({
  version,
  access,
  collectors,
  onChanged,
  onResults
}: {
  version: PrivacyProfileVersionDetail;
  access: Access | null;
  collectors: Collector[] | null;
  onChanged: (message: string) => void;
  onResults: (results: AssignResult[]) => void;
}) {
  const api = useApi();
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (version.status !== "Approved" || !access) {
    return null;
  }
  if (!access.roles.includes("Bower.Administrator")) {
    return (
      <div className="permission-note">
        <KeyRound aria-hidden="true" />
        <p>
          Approved. An Entra assignment for <code>Bower.Administrator</code> is required to
          assign this version to collectors.
        </p>
      </div>
    );
  }

  const eligible = (collectors ?? []).filter((collector) => collector.status !== "Revoked");

  async function assign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = reason.trim();
    if (!selected.length) {
      setError("Select at least one collector.");
      return;
    }
    if (!trimmed) {
      setError("Enter a reason before assigning.");
      return;
    }
    setBusy(true);
    setError(null);
    onResults([]);
    const outcome: AssignResult[] = [];
    for (const collectorId of selected) {
      try {
        await api<Collector>(
          `/api/collectors/${encodeURIComponent(collectorId)}/privacy-profile`,
          {
            method: "POST",
            body: JSON.stringify({ versionId: version.id, reason: trimmed })
          }
        );
        outcome.push({ collectorId, ok: true, message: "Assigned" });
      } catch (requestError) {
        outcome.push({
          collectorId,
          ok: false,
          message: requestError instanceof Error ? requestError.message : "Assignment failed."
        });
      }
    }
    onResults(outcome);
    setSelected(outcome.filter((item) => !item.ok).map((item) => item.collectorId));
    setBusy(false);
    const assigned = outcome.filter((item) => item.ok).length;
    if (assigned > 0) {
      setReason("");
      onChanged(
        `Assigned ${version.profileId}@${version.version} to ${assigned} of ${outcome.length} collector${outcome.length === 1 ? "" : "s"}.`
      );
    }
  }

  return (
    <form
      className="approval-form"
      aria-labelledby="privacy-assign-title"
      onSubmit={(event) => void assign(event)}
    >
      <h3 id="privacy-assign-title">Assign to collectors</h3>
      {error && (
        <div className="alert alert--danger" role="alert">
          {error}
        </div>
      )}
      {eligible.length ? (
        <fieldset className="checkbox-list">
          <legend>Collectors</legend>
          {eligible.map((collector) => (
            <label key={collector.id}>
              <input
                type="checkbox"
                checked={selected.includes(collector.id)}
                onChange={(event) =>
                  setSelected((current) =>
                    event.target.checked
                      ? [...current, collector.id]
                      : current.filter((value) => value !== collector.id)
                  )
                }
              />
              <span>
                <strong>{collector.machineName}</strong>
                <small>
                  {collector.id} · {collector.status}
                  {collector.desiredPrivacyProfile
                    ? ` · has ${collector.desiredPrivacyProfile.profileId}@${collector.desiredPrivacyProfile.version}`
                    : ""}
                </small>
              </span>
            </label>
          ))}
        </fieldset>
      ) : (
        <p className="form-help">
          {collectors === null ? "Collector list unavailable." : "No assignable collectors."}
        </p>
      )}
      <label htmlFor="privacy-assign-reason">Assignment reason</label>
      <textarea
        id="privacy-assign-reason"
        value={reason}
        maxLength={500}
        required
        aria-describedby="privacy-assign-help"
        placeholder="Example: roll out employee-id masking per change BWR-211"
        onChange={(event) => setReason(event.target.value)}
      />
      <span className="approval-help" id="privacy-assign-help">
        Required. Each collector applies the version on its next sync and restart.
      </span>
      <div className="button-row">
        <button
          className="button button--primary"
          type="submit"
          disabled={busy || !eligible.length}
        >
          <ShieldCheck aria-hidden="true" />
          {busy ? "Assigning…" : "Assign to collectors"}
        </button>
      </div>
    </form>
  );
}

function VersionDiff({ version }: { version: PrivacyProfileVersionDetail }) {
  if (!version.previousApprovedVersionId) {
    return (
      <div>
        <h3>Changes</h3>
        <p className="form-help">
          No earlier approved version of this privacy profile. The full content above is
          the baseline.
        </p>
      </div>
    );
  }
  return <PreviousDiff previousId={version.previousApprovedVersionId} version={version} />;
}

function PreviousDiff({
  previousId,
  version
}: {
  previousId: string;
  version: PrivacyProfileVersionDetail;
}) {
  const previous = useResource<PrivacyProfileVersionDetail>(versionPath(previousId));
  return (
    <div>
      <h3>
        Changes since {previous.data ? `${previous.data.version} (approved)` : "previous approved version"}
      </h3>
      <ResourceState loading={previous.loading} error={previous.error} data={previous.data}>
        {(base) => <DiffView previous={base.content} next={version.content} />}
      </ResourceState>
    </div>
  );
}

export function DiffView({ previous, next }: { previous: string; next: string }) {
  const diff = diffLines(previous, next);
  if (diff.tooLarge) {
    return (
      <p className="form-help" role="note">
        Diff unavailable: one version exceeds {maxDiffLines.toLocaleString()} lines. Compare
        the content directly.
      </p>
    );
  }
  if (!diff.added && !diff.removed) {
    return <p className="form-help">Content is identical to the previous approved version.</p>;
  }
  const segments = collapseUnchanged(diff.lines);
  return (
    <>
      <p className="form-help">
        {diff.added} line{diff.added === 1 ? "" : "s"} added, {diff.removed} line
        {diff.removed === 1 ? "" : "s"} removed.
      </p>
      <div className="diff-view" tabIndex={0} role="region" aria-label="Line diff">
        {segments.map((segment, index) =>
          segment.kind === "collapsed" ? (
            <div className="diff-collapsed" key={`c-${index}`}>
              … {segment.count} unchanged line{segment.count === 1 ? "" : "s"}
            </div>
          ) : (
            segment.lines.map((line) => (
              <div
                className={`diff-line diff-line--${line.kind}`}
                key={`${line.kind}-${line.oldLine ?? ""}-${line.newLine ?? ""}`}
              >
                <span className="diff-gutter" aria-hidden="true">
                  {line.oldLine ?? ""}
                </span>
                <span className="diff-gutter" aria-hidden="true">
                  {line.newLine ?? ""}
                </span>
                <span className="diff-marker">
                  {line.kind === "add" ? (
                    <>
                      <span aria-hidden="true">+</span>
                      <span className="visually-hidden">Added: </span>
                    </>
                  ) : line.kind === "remove" ? (
                    <>
                      <span aria-hidden="true">-</span>
                      <span className="visually-hidden">Removed: </span>
                    </>
                  ) : (
                    " "
                  )}
                </span>
                <span className="diff-text">{line.text}</span>
              </div>
            ))
          )
        )}
      </div>
    </>
  );
}

import { CheckCircle2, KeyRound, Package, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../api";
import { EmptyState, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type {
  Access,
  PackGalleryItem,
  PackGalleryResponse,
  PackInstallRequestRecord
} from "../types";

export function PacksPage() {
  const api = useApi();
  const [refresh, setRefresh] = useState(0);
  const gallery = useResource<PackGalleryResponse>("/api/packs", refresh);
  const requests = useResource<PackInstallRequestRecord[]>("/api/packs/install-requests", refresh);
  const access = useResource<Access>("/api/access/me");
  const [installingKey, setInstallingKey] = useState<string | null>(null);
  const [targetEnvironment, setTargetEnvironment] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState<PackInstallRequestRecord | null>(null);

  const canOperate =
    access.data?.roles.some(
      (role) =>
        role === "Bower.Operator" ||
        role === "Bower.Approver" ||
        role === "Bower.Administrator"
    ) ?? false;

  function startInstall(pack: PackGalleryItem, defaultGroup: string) {
    setInstallingKey(`${pack.id}@${pack.version}`);
    setTargetEnvironment(defaultGroup);
    setReason("");
    setError(null);
    setSubmitted(null);
  }

  async function submitInstall(pack: PackGalleryItem) {
    if (!pack.id || !pack.version) {
      return;
    }
    if (!targetEnvironment.trim()) {
      setError("Choose a collector group first.");
      return;
    }
    if (!reason.trim()) {
      setError("Enter a short reason before submitting for approval.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api<PackInstallRequestRecord>("/api/packs/install-requests", {
        method: "POST",
        body: JSON.stringify({
          packId: pack.id,
          version: pack.version,
          targetEnvironment: targetEnvironment.trim(),
          reason: reason.trim()
        })
      });
      setSubmitted(created);
      setInstallingKey(null);
      setRefresh((value) => value + 1);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Could not submit pack install request.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Page
      title="Signed packs"
      description="Browse cryptographically verified telemetry packs, inspect what events they keep and redact, and request installation to a collector group through Approvals."
    >
      {error && (
        <div className="alert alert--danger" role="alert">
          {error}
        </div>
      )}
      {submitted && (
        <div className="alert" role="status">
          <strong>Pack install submitted for approval:</strong> {submitted.packName} v{submitted.packVersion} for{" "}
          <code>{submitted.targetEnvironment ?? submitted.targetCollectorId}</code> (
          {submitted.diff.affectedCollectors.length} collector
          {submitted.diff.affectedCollectors.length === 1 ? "" : "s"}).{" "}
          <Link className="inline-action" to="/approvals">
            Open Approvals
          </Link>
        </div>
      )}

      <ResourceState loading={gallery.loading} error={gallery.error} data={gallery.data}>
        {(data) => {
          const trusted = data.packs.filter((item) => item.trusted);
          const refused = data.packs.filter((item) => !item.trusted);
          const defaultGroup = data.groups[0]?.environment ?? "";

          if (!data.configured) {
            return (
              <EmptyState
                icon={<Package aria-hidden="true" />}
                title="Pack gallery directory is not configured"
                detail="Set BOWER_PACK_GALLERY_DIR and BOWER_PACK_TRUSTED_KEYS on the management API to list and verify signed .bowerpack archives."
              />
            );
          }

          return (
            <>
              <section className="sheet" aria-labelledby="trusted-packs-heading">
                <div className="section-heading">
                  <h2 id="trusted-packs-heading">Verified packs</h2>
                  <span>
                    {trusted.length} trusted · {data.trustedKeyCount} signing key
                    {data.trustedKeyCount === 1 ? "" : "s"}
                  </span>
                </div>

                {trusted.length === 0 ? (
                  <EmptyState
                    icon={<Package aria-hidden="true" />}
                    title="No trusted packs found"
                    detail="Add signed .bowerpack files signed by a key in BOWER_PACK_TRUSTED_KEYS to list them here."
                  />
                ) : (
                  <div className="approval-list">
                    {trusted.map((pack) => {
                      const key = `${pack.id}@${pack.version}`;
                      const isInstalling = installingKey === key;
                      const selectedGroup = data.groups.find((group) => group.environment === targetEnvironment);
                      const passedSamples = pack.sampleResults.filter((sample) => sample.passed).length;

                      return (
                        <article className="approval-item" key={key}>
                          <div>
                            <div className="button-row">
                              <span className="badge badge--healthy">
                                <ShieldCheck aria-hidden="true" /> Signed & verified
                              </span>
                              <span>v{pack.version}</span>
                              {pack.signedByKeyId && <code>key {pack.signedByKeyId}</code>}
                            </div>
                            <h3>{pack.name ?? pack.id}</h3>
                            {pack.description && <p>{pack.description}</p>}

                            <dl className="detail-list">
                              <div>
                                <dt>Pack ID</dt>
                                <dd>{pack.id}</dd>
                              </div>
                              <div>
                                <dt>Owner</dt>
                                <dd>{pack.owner ?? "—"}</dd>
                              </div>
                              <div>
                                <dt>Event types ({pack.eventTypes.length})</dt>
                                <dd>{pack.eventTypes.join(", ") || "None"}</dd>
                              </div>
                              <div>
                                <dt>What gets redacted</dt>
                                <dd>{pack.redactions.join(" ") || "Default Australian privacy policy."}</dd>
                              </div>
                              <div>
                                <dt>Sample checks</dt>
                                <dd>
                                  {pack.sampleResults.length === 0
                                    ? "No samples"
                                    : `${passedSamples} of ${pack.sampleResults.length} passed`}
                                </dd>
                              </div>
                            </dl>

                            {pack.sampleResults.length > 0 && (
                              <details className="source-approval__details">
                                <summary>Sample results (decisions only, post-redaction)</summary>
                                <ul>
                                  {pack.sampleResults.map((sample) => (
                                    <li key={sample.name}>
                                      <strong>{sample.name}</strong>: {sample.passed ? "passed" : "failed"} (expected{" "}
                                      <code>{sample.expectedDecision}</code>, got <code>{sample.actualDecision}</code>)
                                    </li>
                                  ))}
                                </ul>
                              </details>
                            )}
                          </div>

                          <div>
                            {!canOperate ? (
                              <div className="permission-note">
                                <KeyRound aria-hidden="true" />
                                <p>
                                  Viewing only. <code>Bower.Operator</code> or higher is required to request a pack
                                  install.
                                </p>
                              </div>
                            ) : data.groups.length === 0 ? (
                              <div className="permission-note">
                                <p>Approve at least one collector before installing packs to a group.</p>
                              </div>
                            ) : !isInstalling ? (
                              <button
                                className="button button--primary"
                                type="button"
                                onClick={() => startInstall(pack, defaultGroup)}
                              >
                                Install to group
                              </button>
                            ) : (
                              <form
                                className="approval-form"
                                onSubmit={(event) => {
                                  event.preventDefault();
                                  void submitInstall(pack);
                                }}
                              >
                                <label htmlFor={`group-${key}`}>Collector group</label>
                                <select
                                  id={`group-${key}`}
                                  value={targetEnvironment}
                                  onChange={(event) => setTargetEnvironment(event.target.value)}
                                >
                                  {data.groups.map((group) => (
                                    <option key={group.environment} value={group.environment}>
                                      {group.environment} ({group.eligibleCollectors} collector
                                      {group.eligibleCollectors === 1 ? "" : "s"})
                                    </option>
                                  ))}
                                </select>

                                <div className="sheet-body" aria-label="Population diff preview">
                                  <strong>Population diff preview</strong>
                                  <p>
                                    Will assign pack hash <code>{pack.packHash?.slice(0, 12)}</code> to{" "}
                                    {selectedGroup?.eligibleCollectors ?? 0} collector
                                    {selectedGroup?.eligibleCollectors === 1 ? "" : "s"} in{" "}
                                    <strong>{targetEnvironment}</strong>, enabling {pack.eventTypes.length} event type
                                    {pack.eventTypes.length === 1 ? "" : "s"} ({pack.eventTypes.join(", ")}).
                                  </p>
                                </div>

                                <label htmlFor={`reason-${key}`}>Reason for change</label>
                                <textarea
                                  id={`reason-${key}`}
                                  value={reason}
                                  maxLength={500}
                                  required
                                  placeholder="Example: enable SSH gateway monitoring for production Linux hosts"
                                  onChange={(event) => setReason(event.target.value)}
                                />
                                <div className="button-row">
                                  <button className="button button--primary" type="submit" disabled={busy}>
                                    {busy ? "Submitting…" : "Submit for approval"}
                                  </button>
                                  <button
                                    className="button button--secondary"
                                    type="button"
                                    disabled={busy}
                                    onClick={() => setInstallingKey(null)}
                                  >
                                    Cancel
                                  </button>
                                </div>
                              </form>
                            )}
                          </div>
                        </article>
                      );
                    })}
                  </div>
                )}
              </section>

              {refused.length > 0 && (
                <section className="sheet section-gap" aria-labelledby="refused-packs-heading">
                  <div className="section-heading">
                    <h2 id="refused-packs-heading">Refused packs (untrusted)</h2>
                    <span>Blocked by signature or integrity verification</span>
                  </div>
                  <div className="approval-list">
                    {refused.map((pack) => (
                      <article className="approval-item" key={pack.fileName}>
                        <div>
                          <span className="badge badge--unhealthy">
                            <ShieldAlert aria-hidden="true" /> Refused — untrusted
                          </span>
                          <h3>{pack.fileName}</h3>
                          <p role="alert">{pack.refusalReason ?? "Pack failed signature verification."}</p>
                        </div>
                      </article>
                    ))}
                  </div>
                </section>
              )}
            </>
          );
        }}
      </ResourceState>

      <section className="sheet section-gap" aria-labelledby="pack-requests-heading">
        <div className="section-heading">
          <h2 id="pack-requests-heading">Pack install requests</h2>
          <span>Reviewed through Approvals</span>
        </div>
        <ResourceState loading={requests.loading} error={requests.error} data={requests.data}>
          {(items) =>
            items.length === 0 ? (
              <EmptyState
                icon={<CheckCircle2 aria-hidden="true" />}
                title="No pack install requests yet"
                detail="Choose a verified pack above and click Install to group to create a four-eyes approval request."
              />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Pack</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Requested by</th>
                      <th>Reviewed by</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.id}>
                        <td>
                          {item.packName} v{item.packVersion}
                        </td>
                        <td>{item.targetEnvironment ?? item.targetCollectorId}</td>
                        <td>
                          <span
                            className={`badge ${
                              item.status === "approved"
                                ? "badge--healthy"
                                : item.status === "rejected"
                                  ? "badge--unhealthy"
                                  : "badge--pending"
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>
                        <td>
                          {item.requestedByName} ({formatDate(item.requestedAt)})
                        </td>
                        <td>{item.reviewerName ?? "Awaiting approver"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </ResourceState>
      </section>
    </Page>
  );
}

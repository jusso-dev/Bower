import { KeyRound, Ticket } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useApi } from "../api";
import { EmptyState, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Access, CollectorCredential, EnrolmentToken, IssuedEnrolmentToken } from "../types";

type Revocation = { kind: "token"; id: string } | { kind: "credential"; id: string; collectorId: string };

/**
 * One-time enrolment tokens for collectors without an Azure identity, and the key-bound
 * credentials they hold. The token is shown once and kept only in component state.
 */
export function EnrolmentPage() {
  const api = useApi();
  const [refresh, setRefresh] = useState(0);
  const tokens = useResource<EnrolmentToken[]>("/api/enrolment-tokens", refresh);
  const credentials = useResource<CollectorCredential[]>("/api/collector-credentials", refresh);
  const access = useResource<Access>("/api/access/me");
  const [issued, setIssued] = useState<IssuedEnrolmentToken | null>(null);
  const [revoking, setRevoking] = useState<Revocation | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "positive" | "danger"; text: string } | null>(
    null
  );
  const canAdminister = access.data?.roles.includes("Bower.Administrator") ?? false;

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const environment = String(form.get("environment") ?? "").trim();
    const reason = String(form.get("reason") ?? "").trim();
    const collectorId = String(form.get("collectorId") ?? "").trim();
    const hours = Number(form.get("expiresInHours") ?? 24);
    if (!environment || !reason) {
      setMessage({ tone: "danger", text: "Enter an environment and a reason." });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const result = await api<IssuedEnrolmentToken>("/api/enrolment-tokens", {
        method: "POST",
        body: JSON.stringify({
          environment,
          reason,
          collectorId: collectorId || null,
          expiresInHours: hours
        })
      });
      setIssued(result);
      formElement.reset();
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage({
        tone: "danger",
        text: error instanceof Error ? error.message : "Could not create the token."
      });
    } finally {
      setBusy(false);
    }
  }

  async function revoke(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!revoking) {
      return;
    }
    const reason = String(new FormData(event.currentTarget).get("reason") ?? "").trim();
    if (!reason) {
      setMessage({ tone: "danger", text: "Enter a reason before revoking." });
      return;
    }
    const path =
      revoking.kind === "token"
        ? `/api/enrolment-tokens/${encodeURIComponent(revoking.id)}/revoke`
        : `/api/collectors/${encodeURIComponent(revoking.collectorId)}/credentials/${encodeURIComponent(revoking.id)}/revoke`;
    setBusy(true);
    setMessage(null);
    try {
      await api(path, { method: "POST", body: JSON.stringify({ reason }) });
      setMessage({
        tone: "positive",
        text:
          revoking.kind === "token"
            ? `Revoked token ${revoking.id}. It can no longer enrol a collector.`
            : `Revoked credential ${revoking.id}. The collector's next heartbeat is refused.`
      });
      setRevoking(null);
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage({
        tone: "danger",
        text: error instanceof Error ? error.message : "Could not revoke."
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Page
      title="Token enrolment"
      description="For collectors without an Azure identity. A one-time token lets a collector register its own key; it still waits in Approvals for a reasoned decision."
    >
      {message && (
        <div className={`alert alert--${message.tone}`} role="status">
          {message.text}
        </div>
      )}

      {issued && (
        <section className="sheet" aria-labelledby="issued-token-heading">
          <div className="sheet-body parser-form">
            <h2 id="issued-token-heading">Copy this token now</h2>
            <p className="form-help">
              Shown once. Bower stores only its hash, so it cannot be displayed again. Put it in
              the file named by <code>BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE</code> on the
              collector. It works once, in environment <strong>{issued.record.environment}</strong>
              {issued.record.collectorId ? (
                <>
                  {" "}for collector <strong>{issued.record.collectorId}</strong>
                </>
              ) : null}
              , until {formatDate(issued.record.expiresAt)}.
            </p>
            <pre className="code-block token-value" aria-label="Enrolment token">
              {issued.token}
            </pre>
            <div className="button-row">
              <button
                className="button button--secondary"
                type="button"
                onClick={() => void navigator.clipboard?.writeText(issued.token)}
              >
                Copy token
              </button>
              <button className="button button--primary" type="button" onClick={() => setIssued(null)}>
                Done
              </button>
            </div>
          </div>
        </section>
      )}

      {canAdminister ? (
        <section className="sheet section-gap" aria-labelledby="create-token-heading">
          <form className="sheet-body parser-form" onSubmit={(event) => void create(event)}>
            <h2 id="create-token-heading">Create an enrolment token</h2>
            <label htmlFor="token-environment">Environment</label>
            <input id="token-environment" name="environment" type="text" maxLength={128} required />
            <label htmlFor="token-collector">Collector ID (optional)</label>
            <input id="token-collector" name="collectorId" type="text" maxLength={128} />
            <label htmlFor="token-hours">Valid for (hours, 1–168)</label>
            <input
              id="token-hours"
              name="expiresInHours"
              type="number"
              min={1}
              max={168}
              defaultValue={24}
              required
            />
            <label htmlFor="token-reason">Reason</label>
            <textarea
              id="token-reason"
              name="reason"
              maxLength={500}
              placeholder="Example: new on-prem gateway for change BWR-142"
              required
            />
            <p className="form-help">Recorded in the management audit.</p>
            <button className="button button--primary" type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create token"}
            </button>
          </form>
        </section>
      ) : (
        <div className="permission-note section-gap">
          <KeyRound aria-hidden="true" />
          <p>
            Viewing only. An Entra assignment for <code>Bower.Administrator</code> is required to
            create or revoke tokens and credentials.
          </p>
        </div>
      )}

      {revoking && (
        <section className="sheet section-gap" aria-labelledby="revoke-heading">
          <form className="sheet-body parser-form" onSubmit={(event) => void revoke(event)}>
            <h2 id="revoke-heading">
              Revoke {revoking.kind === "token" ? "token" : "credential"}{" "}
              <span className="mono">{revoking.id}</span>
            </h2>
            <label htmlFor="revoke-reason">Revocation reason</label>
            <textarea id="revoke-reason" name="reason" maxLength={500} required />
            <div className="button-row">
              <button className="button button--danger" type="submit" disabled={busy}>
                {busy ? "Revoking…" : "Revoke"}
              </button>
              <button className="button button--secondary" type="button" onClick={() => setRevoking(null)}>
                Cancel
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Enrolment tokens</h2>
          <span>Latest 250 · metadata only</span>
        </div>
        <ResourceState loading={tokens.loading} error={tokens.error} data={tokens.data}>
          {(records) =>
            records.length ? (
              <div className="responsive-table">
                <table>
                  <thead>
                    <tr>
                      <th>Token</th>
                      <th>Scope</th>
                      <th>Status</th>
                      <th>Expires</th>
                      <th>Used by</th>
                      <th>
                        <span className="visually-hidden">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((token) => (
                      <tr key={token.id}>
                        <td data-label="Token">
                          <strong className="mono">{token.id}</strong>
                          <small>
                            {token.createdByName} · {formatDate(token.createdAt)}
                          </small>
                        </td>
                        <td data-label="Scope">
                          {token.environment}
                          {token.collectorId ? <small>{token.collectorId}</small> : null}
                        </td>
                        <td data-label="Status">{token.status}</td>
                        <td data-label="Expires">{formatDate(token.expiresAt)}</td>
                        <td data-label="Used by">{token.usedByCollectorId ?? "—"}</td>
                        <td data-label="Actions">
                          {canAdminister && token.status === "active" ? (
                            <button
                              className="button button--secondary"
                              type="button"
                              onClick={() => setRevoking({ kind: "token", id: token.id })}
                            >
                              Revoke
                            </button>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                icon={<Ticket aria-hidden="true" />}
                title="No enrolment tokens"
                detail="Collectors with an Azure identity enrol with Entra and need no token."
              />
            )
          }
        </ResourceState>
      </section>

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Collector credentials</h2>
          <span>Key-bound · rotated before expiry</span>
        </div>
        <ResourceState
          loading={credentials.loading}
          error={credentials.error}
          data={credentials.data}
        >
          {(records) =>
            records.length ? (
              <div className="responsive-table">
                <table>
                  <thead>
                    <tr>
                      <th>Collector</th>
                      <th>Credential</th>
                      <th>Status</th>
                      <th>Expires</th>
                      <th>Last used</th>
                      <th>
                        <span className="visually-hidden">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((credential) => (
                      <tr key={credential.id}>
                        <td data-label="Collector">{credential.collectorId}</td>
                        <td data-label="Credential">
                          <strong className="mono">{credential.id}</strong>
                          <small>
                            {credential.origin} · {formatDate(credential.issuedAt)}
                          </small>
                        </td>
                        <td data-label="Status">{credential.status}</td>
                        <td data-label="Expires">{formatDate(credential.expiresAt)}</td>
                        <td data-label="Last used">
                          {credential.lastUsedAt ? formatDate(credential.lastUsedAt) : "—"}
                        </td>
                        <td data-label="Actions">
                          {canAdminister && credential.status === "active" ? (
                            <button
                              className="button button--secondary"
                              type="button"
                              onClick={() =>
                                setRevoking({
                                  kind: "credential",
                                  id: credential.id,
                                  collectorId: credential.collectorId
                                })
                              }
                            >
                              Revoke
                            </button>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                icon={<KeyRound aria-hidden="true" />}
                title="No collector credentials"
                detail="A credential appears when a collector exchanges an enrolment token."
              />
            )
          }
        </ResourceState>
      </section>
    </Page>
  );
}

import { Download, KeyRound, Plug, RefreshCw, Send } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ApiError, useApi, useApiDownload } from "../api";
import { CheckList, GuidedStep, PlainStatus, Stepper, type StepperItem } from "../components/guided";
import { initialSourceValues, SourceForm, visibleSourceValues } from "../components/SourceForm";
import { SourcePlanView, SourcePreviewView } from "../components/SourcePlanView";
import { EmptyState, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate, shortHash } from "../lib/format";
import type {
  Access,
  Collector,
  GuidedState,
  SourceSetupPlanResult,
  SourceSetupRequestDetail,
  SourceSetupRequestSummary,
  SourceTypeDefinition
} from "../types";

/** Waiting states poll the server's check; nothing here decides whether a source works. */
const POLL_MILLISECONDS = 15000;

const operateRoles = ["Bower.Operator", "Bower.Approver", "Bower.Administrator"];

export function SourcesPage() {
  const [params, setParams] = useSearchParams();
  const requestId = params.get("request");
  const [refresh, setRefresh] = useState(0);
  const types = useResource<SourceTypeDefinition[]>("/api/sources/types");
  const requests = useResource<SourceSetupRequestSummary[]>("/api/sources/requests", refresh);
  const access = useResource<Access>("/api/access/me");
  const canOperate = access.data?.roles.some((role) => operateRoles.includes(role)) ?? false;

  return (
    <Page
      title="Sources"
      description="Guided setup for each kind of source. Bower writes the settings, someone else approves them, then Bower checks the collector is receiving events."
    >
      {access.error && (
        <div className="alert alert--danger" role="alert">
          Could not check your permissions. Editing is unavailable until this check succeeds.
          <button className="button button--secondary" type="button" onClick={() => void access.reload()}>Retry permission check</button>
        </div>
      )}
      {requestId ? (
        <SourceRequestView
          key={requestId}
          id={requestId}
          canOperate={canOperate}
        />
      ) : (
        <ResourceState loading={types.loading} error={types.error} data={types.data}>
          {(definitions) => (
            <SourceSetupWizard
              types={definitions}
              canOperate={canOperate}
              accessLoaded={access.data !== null}
              onSubmitted={(id) => {
                setRefresh((value) => value + 1);
                setParams({ request: id });
              }}
            />
          )}
        </ResourceState>
      )}

      <section className="sheet section-gap" aria-labelledby="source-requests-heading">
        <div className="section-heading">
          <h2 id="source-requests-heading">Source setup requests</h2>
          {requestId && (
            <Link className="button button--secondary" to="/sources">
              <Plug aria-hidden="true" />
              Add another source
            </Link>
          )}
        </div>
        <ResourceState loading={requests.loading} error={requests.error} data={requests.data}>
          {(items) =>
            items.length ? (
              <div className="responsive-table">
                <table>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Collector</th>
                      <th>Status</th>
                      <th>Asked for by</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.id} className={item.id === requestId ? "row--selected" : undefined}>
                        <td data-label="Source">{item.typeTitle}</td>
                        <td data-label="Collector">{item.collectorId}</td>
                        <td data-label="Status">
                          <PlainStatus state={item.check.state} label={item.check.label} />
                        </td>
                        <td data-label="Asked for by">
                          {item.requestedByName}
                          <small>{formatDate(item.requestedAt)}</small>
                        </td>
                        <td data-label="Details">
                          <Link to={`/sources?request=${item.id}`} aria-label={`Open ${item.typeTitle} on ${item.collectorId}`}>
                            Open
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="No sources set up here yet"
                detail="Choose a source above and ask for approval. If you can only view this page, ask an operator to submit the request. Each request shows whether the collector is receiving events."
              />
            )
          }
        </ResourceState>
      </section>
    </Page>
  );
}

type WizardStep = "type" | "settings" | "review" | "approval";

const wizardTitles: Record<WizardStep, string> = {
  type: "Choose a source",
  settings: "Fill in the settings",
  review: "Review and preview",
  approval: "Ask for approval"
};

function SourceSetupWizard({
  types,
  canOperate,
  accessLoaded,
  onSubmitted
}: {
  types: SourceTypeDefinition[];
  canOperate: boolean;
  accessLoaded: boolean;
  onSubmitted: (id: string) => void;
}) {
  const api = useApi();
  const collectors = useResource<Collector[]>("/api/collectors");
  const [current, setCurrent] = useState<WizardStep>("type");
  const [typeId, setTypeId] = useState<string | null>(null);
  const [collectorId, setCollectorId] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [result, setResult] = useState<SourceSetupPlanResult | null>(null);
  const revision = useRef(0);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const type = types.find((item) => item.id === typeId) ?? null;
  const eligible = (collectors.data ?? []).filter((item) => item.status === "Approved" || item.status === "Active");
  const valid = result?.valid === true;

  function choose(id: string) {
    const chosen = types.find((item) => item.id === id);
    if (!chosen) {
      return;
    }
    revision.current++;
    setTypeId(id);
    setValues(initialSourceValues(chosen));
    setResult(null);
    setError(null);
  }

  function change(id: string, value: string) {
    revision.current++;
    setValues((previous) => ({ ...previous, [id]: value }));
    // Any change needs a fresh server check before it can be reviewed.
    setResult(null);
  }

  async function check() {
    if (!type) {
      return;
    }
    const checkedRevision = revision.current;
    setBusy(true);
    setError(null);
    try {
      const planned = await api<SourceSetupPlanResult>("/api/sources/plan", {
        method: "POST",
        body: JSON.stringify({ type: type.id, collectorId, values: visibleSourceValues(type, values) })
      });
      if (checkedRevision !== revision.current) return;
      setResult(planned);
      if (planned.valid) {
        setCurrent("review");
      }
    } catch (checkError) {
      if (checkedRevision !== revision.current) return;
      setError(checkError instanceof Error ? checkError.message : "The check failed.");
    } finally {
      setBusy(false);
    }
  }

  async function submit() {
    if (!type || !valid) {
      return;
    }
    if (!reason.trim()) {
      setError("Enter a reason before asking for approval.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api<SourceSetupRequestDetail>("/api/sources/requests", {
        method: "POST",
        body: JSON.stringify({
          type: type.id,
          collectorId,
          values: visibleSourceValues(type, values),
          reason: reason.trim()
        })
      });
      onSubmitted(created.id);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  const states: Record<WizardStep, GuidedState> = {
    type: type ? "complete" : "not-started",
    settings: !type ? "blocked" : valid ? "complete" : result ? "attention" : "in-progress",
    review: valid ? "in-progress" : "blocked",
    approval: valid ? "not-started" : "blocked"
  };
  const steps: StepperItem[] = (Object.keys(wizardTitles) as WizardStep[]).map((id) => ({
    id,
    title: wizardTitles[id],
    state: states[id]
  }));
  const index = steps.findIndex((step) => step.id === current);
  const fieldIds = new Set(type?.fields.map((field) => field.id) ?? []);

  return (
    <>
      {accessLoaded && !canOperate && (
        <div className="permission-note setup-note">
          <KeyRound aria-hidden="true" />
          <p>
            Viewing only. Someone with the <code>Bower.Operator</code> app role sets up sources; you can read what
            each one needs and follow requests below.
          </p>
        </div>
      )}
      <div className="setup-layout">
        <Stepper label="Source setup steps" steps={steps} current={current} onSelect={(id) => setCurrent(id as WizardStep)} />
        <GuidedStep
          id={current}
          number={index + 1}
          total={steps.length}
          title={wizardTitles[current]}
          state={states[current]}
          why={whyFor(current, type)}
        >
          {error && (
            <div className="alert alert--danger" role="alert">
              {error}
            </div>
          )}
          {current === "type" && (
            <>
              <fieldset className="choice-list">
                <legend>What do you want to connect?</legend>
                {types.map((item) => (
                  <label className="choice-list__item" key={item.id}>
                    <input
                      type="radio"
                      name="source-type"
                      value={item.id}
                      checked={item.id === typeId}
                      onChange={() => choose(item.id)}
                    />
                    <span>
                      <strong>{item.title}</strong>
                      {item.summary}
                    </span>
                  </label>
                ))}
              </fieldset>
              <div className="button-row guided-step__nav">
                <button
                  className="button button--primary"
                  type="button"
                  disabled={!type}
                  onClick={() => setCurrent("settings")}
                >
                  Continue
                </button>
              </div>
            </>
          )}

          {current === "settings" && type && (
            <form
              className="parser-form setup-form"
              onSubmit={(event) => {
                event.preventDefault();
                void check();
              }}
            >
              <div className="setup-subsection">
                <h3>What you need</h3>
                <ul className="source-needs">
                  {type.needs.map((need) => (
                    <li key={need}>{need}</li>
                  ))}
                </ul>
              </div>
              {collectors.error && (
                <div className="alert alert--danger" role="alert">
                  Could not load collectors. Try again before choosing where this source sends events.
                  <button className="button button--secondary" type="button" onClick={() => void collectors.reload()}>Retry collectors</button>
                </div>
              )}
              <label htmlFor="source-collector">Collector</label>
              <select
                id="source-collector"
                value={collectorId}
                disabled={!canOperate}
                aria-describedby="source-collector-help"
                onChange={(event) => {
                  revision.current++;
                  setCollectorId(event.target.value);
                  setResult(null);
                }}
              >
                <option value="">Choose a collector</option>
                {eligible.map((collector) => (
                  <option key={collector.id} value={collector.id}>
                    {collector.machineName} ({collector.id}, {collector.environment})
                  </option>
                ))}
              </select>
              <p className="form-help" id="source-collector-help">
                Required. Only approved collectors are listed. The source's events go through this collector.
              </p>
              <SourceForm
                type={type}
                values={values}
                checks={result?.checks ?? []}
                disabled={!canOperate}
                onChange={change}
              />
              {result && !result.valid && (
                <div className="alert" role="status">
                  Some settings need changing. Each one says how to fix it.
                </div>
              )}
              <CheckList
                label="Other checks"
                checks={(result?.checks ?? []).filter((item) => !fieldIds.has(item.id) && item.state !== "pass")}
              />
              <p className="form-help">
                Full guide: <code>{type.guide}</code> in the Bower repository.
              </p>
              <div className="button-row">
                <button className="button button--primary" type="submit" disabled={busy || !canOperate}>
                  {busy ? "Checking…" : "Check settings"}
                </button>
              </div>
            </form>
          )}
          {current === "settings" && !type && <p className="form-help">Choose a source first.</p>}

          {current === "review" && (
            valid && result?.plan && type ? (
              <>
                <CheckList label="Settings checks" checks={result.checks} />
                <div className="setup-subsection">
                  <h3>What an event will look like</h3>
                  {result.preview && <SourcePreviewView preview={result.preview} />}
                </div>
                <div className="setup-subsection">
                  <h3>What will be installed</h3>
                  <SourcePlanView plan={result.plan} headingLevel={4} />
                </div>
                <div className="setup-subsection">
                  <h3>How Bower checks it works</h3>
                  <p className="form-help">{type.checkDescription}</p>
                </div>
                <div className="button-row guided-step__nav">
                  <button className="button button--primary" type="button" onClick={() => setCurrent("approval")}>
                    Continue
                  </button>
                </div>
              </>
            ) : (
              <p className="form-help">Check the settings first; the review shows what the server generated.</p>
            )
          )}

          {current === "approval" && (
            valid ? (
              <form
                className="parser-form setup-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void submit();
                }}
              >
                <p className="supporting-copy setup-copy">
                  Nothing changes on the collector yet. Someone with the <code>Bower.Approver</code> role, other than
                  you, approves the request on the Approvals page. Then you install the approved settings and Bower
                  checks the collector is receiving events.
                </p>
                <label htmlFor="source-reason">Why this source is needed</label>
                <textarea
                  id="source-reason"
                  value={reason}
                  maxLength={500}
                  required
                  aria-describedby="source-reason-help"
                  placeholder="Example: SSH sign-in failures from the edge gateway, change BWR-210"
                  onChange={(event) => setReason(event.target.value)}
                />
                <p className="form-help" id="source-reason-help">
                  Required. The approver sees it, and it is kept in the audit log.
                </p>
                <div className="button-row">
                  <button className="button button--primary" type="submit" disabled={busy || !canOperate}>
                    <Send aria-hidden="true" />
                    {busy ? "Sending…" : "Ask for approval"}
                  </button>
                </div>
              </form>
            ) : (
              <p className="form-help">Check the settings first.</p>
            )
          )}
        </GuidedStep>
      </div>
    </>
  );
}

function whyFor(step: WizardStep, type: SourceTypeDefinition | null) {
  switch (step) {
    case "type":
      return "Each kind of source needs different settings. Bower asks only for what yours needs.";
    case "settings":
      return type?.why ?? "Bower checks every setting on the server before anything is written.";
    case "review":
      return "A second person approves exactly what is shown here. The preview shows what Bower keeps after its privacy rules.";
    case "approval":
      return "Bower never changes a collector without a second person's approval. Every request and decision is in the audit log.";
  }
}

type RequestStep = "approval" | "install" | "check";

const requestTitles: Record<RequestStep, string> = {
  approval: "Approval",
  install: "Install the settings",
  check: "Check it works"
};

function SourceRequestView({ id, canOperate }: { id: string; canOperate: boolean }) {
  const request = useResource<SourceSetupRequestDetail>(`/api/sources/requests/${encodeURIComponent(id)}`);
  const { revalidate } = request;
  const download = useApiDownload();
  const [selected, setSelected] = useState<RequestStep | null>(null);
  const [polls, setPolls] = useState(0);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const data = request.data;
  const waiting =
    data !== null &&
    (data.status === "pending-review" || (data.status === "approved" && data.check.state !== "complete"));

  // The server re-evaluates the collector's heartbeat on every read.
  useEffect(() => {
    if (!waiting) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void revalidate().then(() => setPolls((count) => count + 1));
    }, POLL_MILLISECONDS);
    return () => window.clearTimeout(timer);
  }, [waiting, revalidate, polls]);

  return (
    <>
      <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
        {data ? `Source status: ${data.check.label}.` : ""}
      </p>
      {request.refreshError && data && (
        <div className="alert" role="status">
          Could not refresh the check. Showing what was last loaded; trying again shortly.
        </div>
      )}
      <ResourceState loading={request.loading} error={request.error} data={data}>
        {(detail) => {
          const approved = detail.status === "approved";
          const states: Record<RequestStep, GuidedState> = {
            approval:
              detail.status === "approved" ? "complete" : detail.status === "rejected" ? "attention" : "in-progress",
            install: !approved ? "blocked" : detail.check.state === "complete" ? "complete" : "in-progress",
            check: !approved ? "blocked" : detail.check.state
          };
          const steps: StepperItem[] = (Object.keys(requestTitles) as RequestStep[]).map((step) => ({
            id: step,
            title: requestTitles[step],
            state: states[step]
          }));
          const current = selected ?? (steps.find((step) => step.state !== "complete")?.id as RequestStep | undefined) ?? "check";
          const index = steps.findIndex((step) => step.id === current);
          return (
            <>
              <div className="section-heading">
                <h2>
                  {detail.typeTitle} on {detail.collectorId}
                </h2>
                <PlainStatus state={detail.check.state} label={detail.check.label} />
              </div>
              <div className="setup-layout">
                <Stepper label="Source request steps" steps={steps} current={current} onSelect={(step) => setSelected(step as RequestStep)} />
                <GuidedStep
                  id={current}
                  number={index + 1}
                  total={steps.length}
                  title={requestTitles[current]}
                  state={states[current]}
                  stateLabel={current === "check" && approved ? detail.check.label : undefined}
                  why={requestWhy[current]}
                >
                  {current === "approval" && (
                    <>
                      {!approved && <CheckList label="Approval" checks={detail.check.checks} />}
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
                        <div>
                          <dt>Content hash</dt>
                          <dd>
                            <code title={detail.contentHash}>{shortHash(detail.contentHash)}</code>
                          </dd>
                        </div>
                        {detail.reviewerName && detail.reviewedAt && (
                          <div>
                            <dt>{approved ? "Approved by" : "Rejected by"}</dt>
                            <dd>
                              {detail.reviewerName}, {formatDate(detail.reviewedAt)}: {detail.reviewReason}
                            </dd>
                          </div>
                        )}
                      </dl>
                      {detail.status === "pending-review" && (
                        <p className="form-help">
                          Approvers decide on the <Link to="/approvals">Approvals</Link> page.
                        </p>
                      )}
                    </>
                  )}
                  {current === "install" && (
                    <>
                      {!approved && (
                        <p className="form-help">
                          Install nothing until the request is approved. This is what will be installed.
                        </p>
                      )}
                      {approved && canOperate && (
                        <div className="setup-subsection">
                          <h3>Signed copy</h3>
                          <p className="form-help">
                            The approved files and settings, signed by the management server, so the person installing
                            them can check they are what was approved.
                          </p>
                          {downloadError && (
                            <div className="alert alert--danger" role="alert">
                              {downloadError}
                            </div>
                          )}
                          <div className="button-row">
                            <button
                              className="button button--secondary"
                              type="button"
                              onClick={() => {
                                setDownloadError(null);
                                download(
                                  `/api/sources/requests/${encodeURIComponent(detail.id)}/signed`,
                                  `bower-source-setup-${detail.id}.json`
                                ).catch((failure: unknown) =>
                                  setDownloadError(
                                    failure instanceof ApiError && failure.status === 503
                                      ? "Signing is not set up on the management server. Ask an administrator to configure a source setup signing key, or install from the approved text below."
                                      : "The signed copy could not be downloaded."
                                  )
                                );
                              }}
                            >
                              <Download aria-hidden="true" />
                              Download signed copy
                            </button>
                          </div>
                        </div>
                      )}
                      <SourcePlanView plan={detail.plan} />
                    </>
                  )}
                  {current === "check" && (
                    <>
                      <CheckList label="Source check" checks={detail.check.checks} />
                      <dl className="detail-list">
                        <div>
                          <dt>Watching</dt>
                          <dd>{detail.plan.verification.description}</dd>
                        </div>
                        <div>
                          <dt>Last event</dt>
                          <dd>{detail.check.lastEventAt ? formatDate(detail.check.lastEventAt) : "None reported yet"}</dd>
                        </div>
                        <div>
                          <dt>Collector last reported</dt>
                          <dd>{detail.check.collectorSeenAt ? formatDate(detail.check.collectorSeenAt) : "Never"}</dd>
                        </div>
                        <div>
                          <dt>Checked</dt>
                          <dd>{formatDate(detail.check.checkedAt)}</dd>
                        </div>
                      </dl>
                      <p className="form-help">
                        Bower checks the collector's own reports on the server. The page checks again every 15 seconds
                        while it waits.
                      </p>
                      <div className="button-row">
                        <button
                          className="button button--secondary"
                          type="button"
                          disabled={checking}
                          onClick={() => {
                            setChecking(true);
                            void revalidate().finally(() => setChecking(false));
                          }}
                        >
                          <RefreshCw aria-hidden="true" />
                          {checking ? "Checking…" : "Check now"}
                        </button>
                      </div>
                    </>
                  )}
                </GuidedStep>
              </div>
            </>
          );
        }}
      </ResourceState>
    </>
  );
}

const requestWhy: Record<RequestStep, string> = {
  approval: "A second person checks the exact settings before anything is installed, so one mistake or one account cannot add a source alone.",
  install: "Bower does not push settings to collectors. Someone with access to the hosts installs the approved text.",
  check: "A source only counts as working when the collector reports events from it, not when someone says it is done."
};

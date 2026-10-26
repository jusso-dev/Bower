import { Download, KeyRound, Send } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useApi, useApiDownload } from "../api";
import { CheckList, GuidedStep, Stepper } from "../components/guided";
import { Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type {
  SetupCanaryRun,
  SetupCheckResult,
  SetupStatus,
  SetupStep,
  SetupStepId
} from "../types";

const stepCopy: Record<SetupStepId, { title: string; why: string }> = {
  "sign-in": {
    title: "Sign in",
    why: "Bower uses your organisation's Entra ID account and app roles, so every change is tied to a person and kept in the audit log."
  },
  entra: {
    title: "Connect Entra apps",
    why: "People and collectors sign in with separate Bower app roles. Without them, collectors cannot enrol and nobody can approve them."
  },
  destination: {
    title: "Choose where events go",
    why: "Bower sends security events to one Log Analytics workspace that Microsoft Sentinel reads. The data collection rule decides which columns arrive."
  },
  collector: {
    title: "Approve the first collector",
    why: "A collector cannot report until a person approves it, so an unknown machine cannot join your fleet."
  },
  probe: {
    title: "Choose what the test proves",
    why: "The test event can prove Bower's general event path, or that a specific pack parser works end to end."
  },
  canary: {
    title: "Send a test event",
    why: "A synthetic test event goes through privacy rules, policy, the queue and delivery exactly like real events. It holds no real data."
  },
  proof: {
    title: "See proof it arrived",
    why: "A collector accepting an event does not prove it reached Sentinel. Only a Sentinel query that finds the exact test event does."
  }
};

const POLL_MILLISECONDS = 5000;

export function SetupPage() {
  const setup = useResource<SetupStatus>("/api/setup");
  const { revalidate } = setup;
  const [selected, setSelected] = useState<SetupStepId | null>(null);
  const running = setup.data?.latestRun?.state === "running";

  // Open the first unfinished step once, then stay on the step the person chose, so saving
  // shows that step's new state instead of jumping ahead.
  useEffect(() => {
    if (selected === null && setup.data) {
      setSelected(firstUnfinished(setup.data.steps));
    }
  }, [selected, setup.data]);

  useEffect(() => {
    if (!running) {
      return undefined;
    }
    const timer = window.setTimeout(() => void revalidate(), POLL_MILLISECONDS);
    return () => window.clearTimeout(timer);
  }, [running, revalidate, setup.data]);

  return (
    <Page
      title="Set up Bower"
      description="Seven steps from an empty tenant to a test event Bower has found in Microsoft Sentinel. Progress is saved on the server, so you can stop and come back."
    >
      <ResourceState loading={setup.loading} error={setup.error} data={setup.data}>
        {(status) => {
          const current = selected ?? firstUnfinished(status.steps);
          const index = status.steps.findIndex((item) => item.id === current);
          const step = status.steps[index];
          const previous = status.steps[index - 1];
          const next = status.steps[index + 1];
          if (!step) {
            return null;
          }
          return (
            <>
              {!status.canChange && (
                <div className="permission-note setup-note">
                  <KeyRound aria-hidden="true" />
                  <p>
                    Viewing only. Someone with the <code>Bower.Administrator</code> app role makes
                    setup changes; you can follow progress here.
                  </p>
                </div>
              )}
              <div className="setup-layout">
                <Stepper
                  label="Setup steps"
                  current={current}
                  steps={status.steps.map((item) => ({
                    id: item.id,
                    title: stepCopy[item.id].title,
                    state: item.state
                  }))}
                  onSelect={(id) => setSelected(id as SetupStepId)}
                />
                <GuidedStep
                  id={step.id}
                  number={index + 1}
                  total={status.steps.length}
                  title={stepCopy[step.id].title}
                  state={step.state}
                  stateLabel={stateLabel(step, status.latestRun)}
                  why={stepCopy[step.id].why}
                >
                  <CheckList label={`${stepCopy[step.id].title} checks`} checks={step.checks} />
                  <UpdatedLine step={step} />
                  <StepBody step={step} status={status} onChanged={revalidate} />
                  <div className="button-row guided-step__nav">
                    {previous && (
                      <button
                        className="button button--secondary"
                        type="button"
                        onClick={() => setSelected(previous.id)}
                      >
                        Back
                      </button>
                    )}
                    {next && (
                      <button
                        className="button button--secondary"
                        type="button"
                        onClick={() => setSelected(next.id)}
                      >
                        Next step
                      </button>
                    )}
                  </div>
                </GuidedStep>
              </div>
            </>
          );
        }}
      </ResourceState>
    </Page>
  );
}

function firstUnfinished(steps: SetupStep[]): SetupStepId {
  return (steps.find((step) => step.state !== "complete") ?? steps.at(-1))?.id ?? "sign-in";
}

/** Proof wording: only a verified run says "Verified"; simulated always says so. */
function stateLabel(step: SetupStep, run: SetupCanaryRun | null): string | undefined {
  if (step.id !== "proof" || !run || run.state === "running") {
    return undefined;
  }
  if (run.mode === "verified") {
    return "Verified in Sentinel";
  }
  if (run.mode === "simulated") {
    return "Simulated, not proof";
  }
  return undefined;
}

function UpdatedLine({ step }: { step: SetupStep }) {
  if (!step.updatedBy || !step.updatedAt) {
    return null;
  }
  return (
    <p className="form-help">
      Last changed by {step.updatedBy}, {formatDate(step.updatedAt)}.
    </p>
  );
}

function StepBody({
  step,
  status,
  onChanged
}: {
  step: SetupStep;
  status: SetupStatus;
  onChanged: () => Promise<void>;
}) {
  switch (step.id) {
    case "entra":
      return (
        <p className="supporting-copy setup-copy">
          Bower can only check what the API sees: the tenant it trusts and the roles in tokens. Compare
          your app registrations with <code>deploy/entra/api-app-manifest.json</code> and{" "}
          <code>deploy/entra/spa-app-manifest.json</code>. Your own roles are on the{" "}
          <Link to="/access">Access</Link> page.
        </p>
      );
    case "destination":
      return <DestinationBody status={status} onChanged={onChanged} />;
    case "collector":
      return (
        <p className="supporting-copy setup-copy">
          Approval needs a reason and is recorded in approval history and the audit log. Open{" "}
          <Link to="/approvals">Approvals</Link> to review waiting collectors.
        </p>
      );
    case "probe":
      return <ProbeBody status={status} onChanged={onChanged} />;
    case "canary":
      return <CanaryBody step={step} status={status} onChanged={onChanged} />;
    case "proof":
      return <ProofBody run={status.latestRun} />;
    default:
      return null;
  }
}

function useAction(onChanged: () => Promise<void>) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await onChanged();
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, run };
}

function ActionError({ error }: { error: string | null }) {
  return error ? (
    <div className="alert alert--danger" role="alert">
      {error}
    </div>
  ) : null;
}

function DestinationBody({
  status,
  onChanged
}: {
  status: SetupStatus;
  onChanged: () => Promise<void>;
}) {
  const api = useApi();
  const download = useApiDownload();
  const save = useAction(onChanged);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [result, setResult] = useState<SetupCheckResult | null>(null);
  const destination = status.destination;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    void save.run(() =>
      api("/api/setup/destination", {
        method: "POST",
        body: JSON.stringify({
          workspaceId: String(form.get("workspaceId") ?? ""),
          workspaceResourceId: String(form.get("workspaceResourceId") ?? ""),
          dcrResourceId: String(form.get("dcrResourceId") ?? ""),
          table: String(form.get("table") ?? "")
        })
      })
    );
  }

  async function check() {
    setChecking(true);
    setCheckError(null);
    try {
      setResult(await api<SetupCheckResult>("/api/setup/destination/check", { method: "POST" }));
    } catch (error) {
      setResult(null);
      setCheckError(error instanceof Error ? error.message : "The check failed.");
    } finally {
      setChecking(false);
    }
  }

  const canCheck =
    status.canChange &&
    status.canary.verifierConfigured &&
    Boolean(destination?.dcrResourceId || destination?.workspaceResourceId);

  return (
    <>
      {status.canChange ? (
        <form className="parser-form setup-form" onSubmit={submit}>
          <ActionError error={save.error} />
          <label htmlFor="setup-workspace-id">Workspace ID</label>
          <input
            id="setup-workspace-id"
            name="workspaceId"
            type="text"
            required
            autoComplete="off"
            spellCheck={false}
            defaultValue={destination?.workspaceId ?? ""}
            aria-describedby="setup-workspace-id-help"
          />
          <p className="form-help" id="setup-workspace-id-help">
            Required. A GUID on the workspace's Overview page in the Azure portal.
          </p>
          <label htmlFor="setup-workspace-resource-id">Workspace resource ID (optional)</label>
          <input
            id="setup-workspace-resource-id"
            name="workspaceResourceId"
            type="text"
            autoComplete="off"
            spellCheck={false}
            defaultValue={destination?.workspaceResourceId ?? ""}
            aria-describedby="setup-workspace-resource-id-help"
          />
          <p className="form-help" id="setup-workspace-resource-id-help">
            Starts with <code>/subscriptions/</code>. Lets Bower check the table and read its retention.
          </p>
          <label htmlFor="setup-dcr-resource-id">Data collection rule resource ID (optional)</label>
          <input
            id="setup-dcr-resource-id"
            name="dcrResourceId"
            type="text"
            autoComplete="off"
            spellCheck={false}
            defaultValue={destination?.dcrResourceId ?? ""}
            aria-describedby="setup-dcr-resource-id-help"
          />
          <p className="form-help" id="setup-dcr-resource-id-help">
            The rule your collector sends through. Lets Bower check it for drift.
          </p>
          <label htmlFor="setup-table">Table</label>
          <input
            id="setup-table"
            name="table"
            type="text"
            autoComplete="off"
            spellCheck={false}
            defaultValue={destination?.table ?? "BowerSecurity_CL"}
          />
          <div className="button-row">
            <button className="button button--primary" type="submit" disabled={save.busy}>
              {save.busy ? "Saving…" : "Save destination"}
            </button>
          </div>
        </form>
      ) : (
        destination && (
          <dl className="detail-list">
            <div>
              <dt>Workspace ID</dt>
              <dd>{destination.workspaceId}</dd>
            </div>
            <div>
              <dt>Table</dt>
              <dd>{destination.table}</dd>
            </div>
          </dl>
        )
      )}

      <div className="setup-subsection">
        <h3>Check the rule and table</h3>
        <p className="form-help">
          Read-only. Bower reads the deployed rule and table with its verifier identity and compares
          them with what it sends, as <code>bower doctor</code> does.
        </p>
        <div className="button-row">
          <button
            className="button button--secondary"
            type="button"
            disabled={!canCheck || checking}
            onClick={() => void check()}
          >
            {checking ? "Checking…" : "Check the rule and table"}
          </button>
          <button
            className="button button--secondary"
            type="button"
            onClick={() =>
              void download("/api/setup/dcr-template", "bower-dcr.json").catch((error: unknown) =>
                setCheckError(error instanceof Error ? error.message : "The download failed.")
              )
            }
          >
            <Download aria-hidden="true" />
            Download DCR template
          </button>
        </div>
        {!status.canary.verifierConfigured && (
          <p className="form-help">
            The check needs a read-only verifier identity on the management server
            (<code>Bower:Setup:Canary:Credential</code>).
          </p>
        )}
        <p className="form-help">
          Bower never creates Azure resources. Deploy the template yourself, for example with{" "}
          <code>az deployment group create -g RESOURCE-GROUP -f bower-dcr.json -p workspaceName=WORKSPACE</code>.
        </p>
        <ActionError error={checkError} />
        {result && (
          <div role="status">
            <CheckList label="Rule and table check results" checks={result.checks} />
            <p className="form-help">Checked {formatDate(result.checkedAt)}.</p>
          </div>
        )}
      </div>
    </>
  );
}

function ProbeBody({ status, onChanged }: { status: SetupStatus; onChanged: () => Promise<void> }) {
  const api = useApi();
  const save = useAction(onChanged);
  const chosen = status.probe?.profile;

  if (!status.canChange) {
    const option = status.probeOptions.find((item) => item.profile === chosen);
    return option ? <p className="supporting-copy setup-copy">{option.description}</p> : null;
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const profile = new FormData(event.currentTarget).get("profile");
    if (!profile) {
      return;
    }
    void save.run(() =>
      api("/api/setup/probe-profile", {
        method: "POST",
        body: JSON.stringify({ profile: String(profile) })
      })
    );
  }

  return (
    <form className="setup-form" onSubmit={submit}>
      <ActionError error={save.error} />
      <fieldset className="choice-list">
        <legend>Test to run</legend>
        {status.probeOptions.map((option) => (
          <label key={option.profile} className="choice-list__item">
            <input
              type="radio"
              name="profile"
              value={option.profile}
              defaultChecked={option.profile === (chosen ?? "generic")}
            />
            <span>
              <strong>{option.title}</strong>
              <span>{option.description}</span>
              <code>{option.profile}</code>
            </span>
          </label>
        ))}
      </fieldset>
      <div className="button-row">
        <button className="button button--primary" type="submit" disabled={save.busy}>
          {save.busy ? "Saving…" : "Save choice"}
        </button>
      </div>
    </form>
  );
}

function CanaryBody({
  step,
  status,
  onChanged
}: {
  step: SetupStep;
  status: SetupStatus;
  onChanged: () => Promise<void>;
}) {
  const api = useApi();
  const send = useAction(onChanged);
  const run = status.latestRun;
  const ready = step.state !== "blocked" && step.state !== "in-progress";

  return (
    <>
      {run && (
        <dl className="detail-list">
          <Detail label="Test">{run.profile}</Detail>
          <Detail label="Test event ID">{run.eventId ?? "Not sent"}</Detail>
          <Detail label="Requested">
            {run.requestedBy}, {formatDate(run.requestedAt)}
          </Detail>
        </dl>
      )}
      {status.canChange && (
        <>
          <ActionError error={send.error} />
          <div className="button-row">
            <button
              className="button button--primary"
              type="button"
              disabled={!ready || send.busy}
              onClick={() => void send.run(() => api("/api/setup/canary", { method: "POST" }))}
            >
              <Send aria-hidden="true" />
              {step.state === "in-progress"
                ? "Test in progress…"
                : run
                  ? "Send another test event"
                  : "Send test event"}
            </button>
          </div>
          <p className="form-help">
            The server waits up to {status.canary.timeoutMinutes} minutes for the event to appear in
            Sentinel. You can leave this page; progress is saved.
          </p>
        </>
      )}
    </>
  );
}

function ProofBody({ run }: { run: SetupCanaryRun | null }) {
  const download = useApiDownload();
  const [error, setError] = useState<string | null>(null);
  if (!run || run.state === "running") {
    return null;
  }
  return (
    <>
      <dl className="detail-list">
        <Detail label="Result">{proofResult(run)}</Detail>
        <Detail label="Test event ID">{run.eventId ?? "Not sent"}</Detail>
        <Detail label="Workspace and table">
          {run.workspaceId} · {run.table}
        </Detail>
        {run.mode === "verified" && run.latencySeconds !== null && (
          <Detail label="Time to arrive">{run.latencySeconds} seconds</Detail>
        )}
        {run.completedAt && <Detail label="Finished">{formatDate(run.completedAt)}</Detail>}
        <Detail label="Evidence signature">{run.hasSignature ? "Signed" : "Unsigned"}</Detail>
      </dl>
      {run.hasBundle && (
        <>
          <ActionError error={error} />
          <div className="button-row">
            <button
              className="button button--secondary"
              type="button"
              onClick={() =>
                void download(
                  `/api/setup/canary/runs/${encodeURIComponent(run.id)}/bundle`,
                  `bower-evidence-${run.id}.json`
                ).catch((downloadError: unknown) =>
                  setError(
                    downloadError instanceof Error ? downloadError.message : "The download failed."
                  )
                )
              }
            >
              <Download aria-hidden="true" />
              {run.mode === "simulated"
                ? "Download simulated evidence bundle"
                : "Download evidence bundle"}
            </button>
          </div>
          <p className="form-help">
            Metadata only. Check it with <code>bower evidence verify</code> and your public key.
          </p>
        </>
      )}
    </>
  );
}

function proofResult(run: SetupCanaryRun): string {
  if (run.mode === "verified") {
    return "Verified in Sentinel";
  }
  if (run.mode === "simulated") {
    return "Simulated: no Sentinel query ran, so this is not proof";
  }
  return run.collectorAccepted ? "Not proven: accepted by the collector, not found in Sentinel" : "Not sent";
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}


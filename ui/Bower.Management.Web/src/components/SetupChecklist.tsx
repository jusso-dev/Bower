import { useState } from "react";
import { Link } from "react-router-dom";
import { useResource } from "../hooks/useResource";
import { stepCopy } from "../lib/setupSteps";
import type { SetupStatus } from "../types";
import { PlainStatus } from "./guided";
import { ResourceState } from "./ui";

/** Progress is read from the onboarding API on every visit, never stored in the browser. */
export function SetupChecklist() {
  const setup = useResource<SetupStatus>("/api/setup");
  const [refreshing, setRefreshing] = useState(false);
  const refresh = async () => {
    setRefreshing(true);
    try { await setup.revalidate(); } finally { setRefreshing(false); }
  };
  return <section className="sheet section-gap" aria-labelledby="setup-checklist">
    <div className="section-heading">
      <h2 id="setup-checklist" tabIndex={-1}>Setup checklist</h2>
      <button className="button button--secondary" type="button" disabled={refreshing || setup.loading} onClick={() => void refresh()}>
        {refreshing ? "Checking progress…" : "Refresh progress"}
      </button>
    </div>
    {setup.refreshError && <p className="alert" role="status">
      Could not refresh setup progress. {setup.data ? "Showing the last loaded progress; it may be out of date." : "Try again when your access or connection is restored."}
    </p>}
    <ResourceState loading={setup.loading} error={setup.error} data={setup.data}>
      {status => <div className="sheet-body">
        <p>Progress is saved on the server. Refresh to check for changes made elsewhere.</p>
        {!status.canChange && <p>Viewing only. Ask a Bower administrator to complete the remaining steps.</p>}
        {status.steps.length ? <ol className="setup-checklist">
          {status.steps.map(step => {
            const unproven = step.id === "proof" && status.latestRun?.mode !== "verified";
            return <li key={step.id}>
              <Link to={`/setup?step=${step.id}`}>{stepCopy[step.id].title}</Link>
              <PlainStatus state={unproven && step.state === "complete" ? "attention" : step.state}
                label={step.id === "proof" && status.latestRun?.mode === "simulated" ? "Simulated, not proof" : undefined} />
            </li>;
          })}
        </ol> : <p>No setup steps were returned. Refresh progress; if it stays empty, ask your administrator to check the management service.</p>}
        <p>Opening Setup in simple view asks you to show technical pages. Your permissions stay the same.</p>
      </div>}
    </ResourceState>
  </section>;
}

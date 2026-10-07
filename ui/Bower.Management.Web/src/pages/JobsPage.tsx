import { Play, Timer } from "lucide-react";
import { useState } from "react";
import { useApi } from "../api";
import { EmptyState, JobStateLabel, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Access, BackgroundJob, Collector } from "../types";

const jobDescriptions: Record<string, string> = {
  "collector-staleness":
    "Flags approved collectors that stopped reporting for 15 minutes and audits the change.",
  "queue-retention":
    "Removes acknowledged events after the duplicate-detection window. Never touches undelivered events.",
  "queue-maintenance": "Checkpoints the SQLite write-ahead log and refreshes query statistics.",
  "management-heartbeat": "Registers the collector and reports queue, output and job health."
};

const schedules: Record<string, string> = {
  "* * * * *": "Every minute",
  "*/5 * * * *": "Every 5 minutes",
  "0 * * * *": "Hourly",
  "0 3 * * *": "Daily, 03:00 UTC"
};

export function describeSchedule(cron: string): string {
  return schedules[cron] ?? cron;
}

export function JobsPage() {
  const api = useApi();
  const [refresh, setRefresh] = useState(0);
  const jobs = useResource<BackgroundJob[]>("/api/jobs", refresh);
  const collectors = useResource<Collector[]>("/api/collectors", refresh);
  const access = useResource<Access>("/api/access/me");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: "positive" | "danger"; text: string } | null>(
    null
  );
  const canRun = access.data?.roles.includes("Bower.Administrator") ?? false;

  async function runNow(id: string) {
    setBusyId(id);
    setMessage(null);
    try {
      await api(`/api/jobs/${encodeURIComponent(id)}/trigger`, { method: "POST" });
      setMessage({ tone: "positive", text: `Queued ${id}. The run is recorded in the audit log.` });
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage({
        tone: "danger",
        text: error instanceof Error ? error.message : "Could not queue the job."
      });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Page
      title="Background jobs"
      description="Scheduled maintenance and health reporting. Event delivery never runs here; it stays in each collector's durable queue."
    >
      {message && (
        <div className={`alert alert--${message.tone}`} role="status">
          {message.text}
        </div>
      )}

      <section className="sheet">
        <div className="section-heading">
          <h2>Management plane</h2>
          <span>Hangfire · in-memory schedule</span>
        </div>
        <ResourceState loading={jobs.loading} error={jobs.error} data={jobs.data}>
          {(records) =>
            records.length ? (
              <div className="responsive-table">
                <table>
                  <thead>
                    <tr>
                      <th>Job</th>
                      <th>Schedule</th>
                      <th>Last run</th>
                      <th>State</th>
                      <th>Next run</th>
                      <th>
                        <span className="visually-hidden">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((job) => (
                      <tr key={job.id}>
                        <td data-label="Job">
                          <strong className="mono">{job.id}</strong>
                          <small className="job-description">
                            {jobDescriptions[job.id] ?? "Bower recurring job."}
                          </small>
                        </td>
                        <td data-label="Schedule">{describeSchedule(job.schedule)}</td>
                        <td data-label="Last run">
                          {job.lastRunAt ? formatDate(job.lastRunAt) : "—"}
                        </td>
                        <td data-label="State">
                          <JobStateLabel value={job.lastState} />
                        </td>
                        <td data-label="Next run">
                          {job.nextRunAt ? formatDate(job.nextRunAt) : "—"}
                        </td>
                        <td data-label="Actions">
                          {canRun ? (
                            <button
                              className="button button--secondary"
                              type="button"
                              disabled={busyId === job.id}
                              onClick={() => void runNow(job.id)}
                            >
                              <Play aria-hidden="true" />
                              {busyId === job.id ? "Queuing…" : "Run now"}
                            </button>
                          ) : (
                            <span className="muted">Administrator only</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                icon={<Timer aria-hidden="true" />}
                title="No recurring jobs registered"
                detail="The management API registers its jobs at start-up. Restart the service if this stays empty."
              />
            )
          }
        </ResourceState>
      </section>

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Collector jobs</h2>
          <span>Reported in heartbeats</span>
        </div>
        <ResourceState
          loading={collectors.loading}
          error={collectors.error}
          data={collectors.data}
        >
          {(records) => {
            const rows = records.flatMap((collector) =>
              (collector.jobs ?? []).map((job) => ({ collector, job }))
            );
            return rows.length ? (
              <div className="responsive-table">
                <table>
                  <thead>
                    <tr>
                      <th>Collector</th>
                      <th>Job</th>
                      <th>Schedule</th>
                      <th>Last run</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(({ collector, job }) => (
                      <tr key={`${collector.id}-${job.id}`}>
                        <td data-label="Collector">
                          <strong>{collector.machineName}</strong>
                          <small>{collector.id}</small>
                        </td>
                        <td data-label="Job" className="mono">
                          {job.id}
                        </td>
                        <td data-label="Schedule">{describeSchedule(job.schedule)}</td>
                        <td data-label="Last run">
                          {job.lastRunAt ? formatDate(job.lastRunAt) : "—"}
                        </td>
                        <td data-label="State">
                          <JobStateLabel value={job.lastState} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                icon={<Timer aria-hidden="true" />}
                title="No collector job reports yet"
                detail="Approved collectors report queue retention, maintenance and heartbeat jobs with every heartbeat."
              />
            );
          }}
        </ResourceState>
      </section>
    </Page>
  );
}

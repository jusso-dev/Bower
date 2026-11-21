import { Activity, ArrowRight, Eye, RefreshCw } from "lucide-react";
import { useState } from "react";
import { useApi } from "../api";
import { EmptyState, ResourceState } from "./ui";
import { useResource } from "../hooks/useResource";
import { formatDate, shortHash } from "../lib/format";
import type { CollectorPipelineFlow, PipelineTapResponse } from "../types";

export function PipelineFlowDiagram({ canOperate }: { canOperate: boolean }) {
  const [refresh, setRefresh] = useState(0);
  const flows = useResource<CollectorPipelineFlow[]>("/api/pipelines/live", refresh);
  const [selectedCollectorId, setSelectedCollectorId] = useState<string>("");
  const [selectedStageId, setSelectedStageId] = useState<string>("collect");
  const [tapResult, setTapResult] = useState<PipelineTapResponse | null>(null);
  const [tapBusy, setTapBusy] = useState(false);
  const [tapError, setTapError] = useState<string | null>(null);
  const api = useApi();

  async function runTap(collectorId: string) {
    setTapBusy(true);
    setTapError(null);
    try {
      const response = await api<PipelineTapResponse>(
        `/api/pipelines/collectors/${encodeURIComponent(collectorId)}/tap`,
        {
          method: "POST",
          body: JSON.stringify({ limit: 10 })
        }
      );
      setTapResult(response);
    } catch (error) {
      setTapError(error instanceof Error ? error.message : "Could not sample events.");
    } finally {
      setTapBusy(false);
    }
  }

  return (
    <section className="sheet" aria-labelledby="live-pipeline-heading">
      <div className="section-heading">
        <div>
          <h2 id="live-pipeline-heading">Live pipeline flow</h2>
          <p className="muted">
            Collect → Redact → Select → Queue → Deliver, backed by collector heartbeat counters and top sources.
          </p>
        </div>
        <button
          type="button"
          className="button button--secondary"
          onClick={() => setRefresh((n) => n + 1)}
        >
          <RefreshCw aria-hidden="true" />
          Refresh flow
        </button>
      </div>

      <div className="sheet-body">
        <ResourceState loading={flows.loading} error={flows.error} data={flows.data}>
          {(items) => {
            if (!items.length) {
              return (
                <EmptyState
                  icon={<Activity aria-hidden="true" />}
                  title="No collectors reporting yet"
                  detail="Once a collector is approved and sends its first heartbeat, its five-stage flow and busiest sources appear here."
                  action={{ to: "/collectors", label: "View collectors" }}
                />
              );
            }

            const active =
              items.find((item) => item.collectorId === selectedCollectorId) ?? items[0];
            if (!active) {
              return null;
            }
            const activeStage =
              active.stages.find((stage) => stage.id === selectedStageId) ?? active.stages[0];
            if (!activeStage) {
              return null;
            }

            return (
              <>
                <div className="pipeline-toolbar">
                  <label htmlFor="pipeline-collector-select">
                    Collector
                    <select
                      id="pipeline-collector-select"
                      value={active.collectorId}
                      onChange={(event) => {
                        setSelectedCollectorId(event.target.value);
                        setTapResult(null);
                        setTapError(null);
                      }}
                    >
                      {items.map((item) => (
                        <option key={item.collectorId} value={item.collectorId}>
                          {item.machineName} ({item.site}) — {item.connectivity}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="pipeline-summary-chips">
                    <span>
                      Events in: <strong>{active.eventsIn.toLocaleString()}</strong>
                    </span>
                    <span>
                      Queued: <strong>{active.eventsQueued.toLocaleString()}</strong>
                    </span>
                    {active.reductionPercent !== null && (
                      <span>
                        Noise filtered: <strong>{active.reductionPercent}%</strong>
                      </span>
                    )}
                    <span>
                      Last seen: <strong>{formatDate(active.lastSeenAt)}</strong>
                    </span>
                  </div>
                </div>

                <ol className="pipeline-flow" aria-label="Pipeline stages">
                  {active.stages.map((stage, index) => {
                    const selected = stage.id === activeStage.id;
                    return (
                      <li key={stage.id} className="pipeline-flow__item">
                        <button
                          type="button"
                          className={`pipeline-stage pipeline-stage--${stage.light}${
                            selected ? " pipeline-stage--selected" : ""
                          }`}
                          aria-pressed={selected}
                          onClick={() => setSelectedStageId(stage.id)}
                        >
                          <span className="pipeline-stage__title">{stage.title}</span>
                          <strong className="pipeline-stage__headline">{stage.headline}</strong>
                          <span className="pipeline-stage__detail">{stage.detail}</span>
                        </button>
                        {index < active.stages.length - 1 && (
                          <ArrowRight className="pipeline-flow__arrow" aria-hidden="true" />
                        )}
                      </li>
                    );
                  })}
                </ol>

                <div className="pipeline-stage-panel" role="region" aria-label={`${activeStage.title} stage details`}>
                  <div className="subsection-heading">
                    <h3>{activeStage.title} stage details</h3>
                    <span className="mono">
                      policy {shortHash(active.policyHash)} · privacy {shortHash(active.privacyProfileHash)}
                    </span>
                  </div>

                  {activeStage.id === "collect" && (
                    <div className="workbench-grid">
                      <div>
                        <h4>Busiest sources (top)</h4>
                        {active.topSources.length ? (
                          <div className="responsive-table">
                            <table>
                              <thead>
                                <tr>
                                  <th>Application</th>
                                  <th>Environment</th>
                                  <th>Events</th>
                                  <th>Last seen</th>
                                </tr>
                              </thead>
                              <tbody>
                                {active.topSources.map((source) => (
                                  <tr key={`${source.application}/${source.environment}`}>
                                    <td>{source.application}</td>
                                    <td>{source.environment}</td>
                                    <td>{source.eventCount.toLocaleString()}</td>
                                    <td>{formatDate(source.lastSeenAt)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <p className="muted">No source activity counters reported yet.</p>
                        )}
                      </div>
                      <div>
                        <h4>Configured sources</h4>
                        {active.sources.length ? (
                          <ul className="compact-list">
                            {active.sources.map((source) => (
                              <li key={source.id}>
                                <span className="mono">{source.id}</span> ({source.type}) —{" "}
                                <strong>{source.status}</strong>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="muted">No sources reported on the last heartbeat.</p>
                        )}
                      </div>
                    </div>
                  )}

                  {activeStage.id === "redact" && (
                    <div>
                      <p>
                        All privacy redaction runs before events enter the local queue. Raw sensitive values are never stored or shown.
                      </p>
                      {active.redactions.length ? (
                        <ul className="compact-list">
                          {active.redactions.map((item) => (
                            <li key={item.type}>
                              <strong>{item.label}</strong> (<span className="mono">{item.type}</span>):{" "}
                              {item.events.toLocaleString()} event(s) protected
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="muted">No sensitive values have needed redaction since this collector started.</p>
                      )}
                    </div>
                  )}

                  {activeStage.id === "select" && (
                    <div>
                      <p>
                        Accepted and queued: <strong>{active.eventsQueued.toLocaleString()}</strong> · Suppressed:{" "}
                        <strong>{active.eventsSuppressed.toLocaleString()}</strong> · Rejected / quarantined:{" "}
                        <strong>{active.eventsRejected.toLocaleString()}</strong> · Duplicates:{" "}
                        <strong>{active.duplicates.toLocaleString()}</strong>
                      </p>
                      {active.policyBreakdown.length ? (
                        <div className="responsive-table">
                          <table>
                            <thead>
                              <tr>
                                <th>Stage</th>
                                <th>Policy</th>
                                <th>Action</th>
                                <th>Events</th>
                                <th>Queued</th>
                                <th>Suppressed</th>
                              </tr>
                            </thead>
                            <tbody>
                              {active.policyBreakdown.map((row, idx) => (
                                <tr key={`${row.stage}-${row.policyId}-${row.action}-${idx}`}>
                                  <td>{row.stage}</td>
                                  <td className="mono">{row.policyId}</td>
                                  <td>{row.action}</td>
                                  <td>{row.events.toLocaleString()}</td>
                                  <td>{row.queued.toLocaleString()}</td>
                                  <td>{row.suppressed.toLocaleString()}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <p className="muted">No per-policy breakdown reported yet.</p>
                      )}
                    </div>
                  )}

                  {activeStage.id === "queue" && (
                    <dl className="detail-list">
                      <div>
                        <dt>Queue depth</dt>
                        <dd>{active.queueDepth.toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt>Dead-lettered</dt>
                        <dd>{active.deadLettered.toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt>Oldest waiting event</dt>
                        <dd>
                          {active.oldestUndeliveredAgeSeconds !== null
                            ? `${active.oldestUndeliveredAgeSeconds} seconds`
                            : "None waiting"}
                        </dd>
                      </div>
                      <div>
                        <dt>Bytes in / queued</dt>
                        <dd>
                          {active.bytesIn.toLocaleString()} / {active.bytesQueued.toLocaleString()}
                        </dd>
                      </div>
                    </dl>
                  )}

                  {activeStage.id === "deliver" && (
                    <div>
                      <p>
                        Delivery status: <strong>{active.deliveryStatus}</strong>
                        {active.lastSuccessfulDeliveryAt
                          ? ` · Last acknowledged: ${formatDate(active.lastSuccessfulDeliveryAt)}`
                          : " · No delivery acknowledged yet."}
                      </p>
                      {active.outputs.length ? (
                        <ul className="compact-list">
                          {active.outputs.map((output) => (
                            <li key={output.id}>
                              <span className="mono">{output.id}</span> ({output.type}) —{" "}
                              <strong>{output.status}</strong>
                              {output.lastErrorCode ? ` (${output.lastErrorCode})` : ""}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="muted">No outputs reported on the last heartbeat.</p>
                      )}
                    </div>
                  )}
                </div>

                {canOperate && (
                  <div className="pipeline-tap-bar">
                    <button
                      type="button"
                      className="button button--primary"
                      disabled={tapBusy}
                      onClick={() => void runTap(active.collectorId)}
                    >
                      <Eye aria-hidden="true" />
                      {tapBusy ? "Sampling redacted events…" : "Sample redacted events"}
                    </button>
                    <span className="muted">
                      Operator-only, post-redaction tap. Audited in the management log.
                    </span>
                  </div>
                )}

                {tapError && (
                  <div className="alert alert--danger" role="alert">
                    {tapError}
                  </div>
                )}

                {tapResult && (
                  <div className="pipeline-tap-result" role="region" aria-label="Redacted event sample">
                    <p>{tapResult.note}</p>
                    <pre className="code-block">
                      <code>{tapResult.command}</code>
                    </pre>
                    {tapResult.frames.length > 0 && (
                      <ul className="compact-list">
                        {tapResult.frames.map((frame, index) => (
                          <li key={`${frame.observedAt}-${index}`}>
                            <span className="mono">{frame.decision}</span> · {frame.eventType ?? "event"} ·{" "}
                            {frame.policyId ?? "no policy"}
                            {frame.redactedPayload && (
                              <pre className="code-block">
                                <code>{frame.redactedPayload}</code>
                              </pre>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </>
            );
          }}
        </ResourceState>
      </div>
    </section>
  );
}

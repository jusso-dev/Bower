import { BellOff, CheckCircle2, CircleDashed, Clock3, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../api";
import { GlossaryText } from "../components/glossary";
import { TrafficLight } from "../components/guided";
import { EmptyState, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Access, Home, HomeAttention, HomeFix, HomeSentinelProof } from "../types";

/** The home view refreshes in place, like the setup wizard's progress. */
const refreshMilliseconds = 60_000;

const pageNames: Record<string, string> = {
  "/setup": "Setup",
  "/collectors": "Collectors",
  "/approvals": "Approvals",
  "/privacy-profiles": "Privacy profiles",
  "/audit": "Audit",
  "/overview": "Overview"
};

/**
 * Plain-English home: is data flowing, what was protected this week and what needs
 * attention. Every state and sentence is computed by the API from real management state.
 */
export function HomePage({ view = "home" }: { view?: "home" | "alerts" | "reports" }) {
  const api = useApi();
  const { data, loading, error, refreshError, revalidate } = useResource<Home>("/api/home");
  const access = useResource<Access>("/api/access/me");
  const [mutingId, setMutingId] = useState<string | null>(null);
  const [muteDuration, setMuteDuration] = useState(240);
  const [muteReason, setMuteReason] = useState("");
  const [muteBusy, setMuteBusy] = useState(false);
  const [muteError, setMuteError] = useState<string | null>(null);

  const canOperate =
    access.data?.roles.some(
      (role) =>
        role === "Bower.Operator" ||
        role === "Bower.Approver" ||
        role === "Bower.Administrator"
    ) ?? false;

  useEffect(() => {
    const timer = window.setInterval(() => void revalidate(), refreshMilliseconds);
    return () => window.clearInterval(timer);
  }, [revalidate]);

  async function submitMute(conditionId: string) {
    if (!muteReason.trim()) {
      setMuteError("Enter a reason before muting this alert.");
      return;
    }
    setMuteBusy(true);
    setMuteError(null);
    try {
      await api("/api/alerts/mute", {
        method: "POST",
        body: JSON.stringify({
          conditionId,
          durationMinutes: muteDuration,
          reason: muteReason.trim()
        })
      });
      setMutingId(null);
      setMuteReason("");
      await revalidate();
    } catch (err) {
      setMuteError(err instanceof Error ? err.message : "Could not mute alert.");
    } finally {
      setMuteBusy(false);
    }
  }

  async function unmute(item: HomeAttention) {
    if (!item.muteId) {
      return;
    }
    setMuteBusy(true);
    setMuteError(null);
    try {
      await api(`/api/alerts/mutes/${encodeURIComponent(item.muteId)}/unmute`, {
        method: "POST"
      });
      await revalidate();
    } catch (err) {
      setMuteError(err instanceof Error ? err.message : "Could not unmute alert.");
    } finally {
      setMuteBusy(false);
    }
  }

  return (
    <Page
      title={view === "home" ? "Home" : view === "alerts" ? "Alerts" : "Reports"}
      description={view === "alerts" ? "What needs attention and what to do next, from the latest collector reports."
        : view === "reports" ? "Reported privacy protection this week and the latest destination proof."
        : "Is your data flowing, what was protected this week, and what needs your attention."}
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(home) => (
          <>
            {refreshError && (
              <div className="alert" role="status">
                <strong>Could not refresh.</strong>
                <span>Showing the status from {formatDate(home.generatedAt)}.</span>
              </div>
            )}
            {view !== "alerts" && <div className="home-grid">
              <section className="sheet home-card" aria-labelledby="home-flow">
                <header className="home-card__header">
                  <h2 id="home-flow">Is my data flowing?</h2>
                  <TrafficLight state={home.flow.state} />
                </header>
                <p className="home-card__lead">
                  <GlossaryText text={home.flow.summary} />
                </p>
                {home.flow.lastAcceptedAt && (
                  <p className="home-card__note">
                    Last accepted for sending: {formatDate(home.flow.lastAcceptedAt)}. Acceptance
                    alone does not prove arrival.
                  </p>
                )}
                <SentinelProof proof={home.flow.proof} />
              </section>

              <section className="sheet home-card" aria-labelledby="home-protected">
                <header className="home-card__header">
                  <h2 id="home-protected">What was protected this week?</h2>
                </header>
                <p className="home-card__lead">
                  <GlossaryText text={home.protection.summary} />
                </p>
                {home.protection.byType.length > 0 && (
                  <ul className="redaction-list" aria-label="Sensitive details removed this week">
                    {home.protection.byType.map((item) => (
                      <li key={item.type}>
                        <span>{item.label} removed</span>
                        <strong>{item.events.toLocaleString()}</strong>
                        <small>{item.events === 1 ? "event" : "events"}</small>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="home-card__note">
                  Counts of events since {formatDay(home.protection.since)}, by kind of detail.
                  Bower never shows the removed values.
                  {home.protection.collectorsNotReporting > 0 &&
                    ` ${count(home.protection.collectorsNotReporting, "working collector runs", "working collectors run")} an older version that does not report these counts yet.`}
                </p>
              </section>
            </div>}

            {view !== "reports" && <section className="sheet section-gap home-card" aria-labelledby="home-attention">
              <header className="home-card__header">
                <h2 id="home-attention">What needs my attention?</h2>
                <TrafficLight state={home.state} />
              </header>
              {muteError && (
                <div className="alert alert--danger" role="alert">
                  {muteError}
                </div>
              )}
              {home.attention.length ? (
                <ul className="attention-list">
                  {home.attention.map((item) => (
                    <li key={item.id} className={`attention-list__item attention-list__item--${item.state}`}>
                      <TrafficLight state={item.state} />
                      <div>
                        <p>
                          <GlossaryText text={item.message} />
                          {item.muted && (
                            <>
                              {" "}
                              <span className="badge badge--pending">
                                <BellOff aria-hidden="true" /> Muted
                                {item.mutedUntil ? ` until ${formatDate(item.mutedUntil)}` : ""}
                              </span>
                            </>
                          )}
                        </p>
                        {item.muted && item.muteReason && (
                          <p className="home-card__note">Mute reason: {item.muteReason}</p>
                        )}
                        <FixLine fix={item.fix} context={item.message} />
                        {view === "alerts" && canOperate && (
                          <div className="button-row">
                            {item.muted && item.muteId ? (
                              <button
                                className="button button--secondary"
                                type="button"
                                disabled={muteBusy}
                                onClick={() => void unmute(item)}
                              >
                                Unmute notifications
                              </button>
                            ) : mutingId === item.id ? (
                              <form
                                className="approval-form"
                                onSubmit={(event) => {
                                  event.preventDefault();
                                  void submitMute(item.id);
                                }}
                              >
                                <label htmlFor={`mute-duration-${item.id}`}>Mute duration</label>
                                <select
                                  id={`mute-duration-${item.id}`}
                                  value={muteDuration}
                                  onChange={(event) => setMuteDuration(Number(event.target.value))}
                                >
                                  <option value={60}>1 hour</option>
                                  <option value={240}>4 hours</option>
                                  <option value={1440}>24 hours</option>
                                  <option value={10080}>7 days</option>
                                </select>
                                <label htmlFor={`mute-reason-${item.id}`}>Reason for muting (audited)</label>
                                <input
                                  id={`mute-reason-${item.id}`}
                                  type="text"
                                  maxLength={500}
                                  required
                                  value={muteReason}
                                  placeholder="Example: scheduled maintenance window CHG-412"
                                  onChange={(event) => setMuteReason(event.target.value)}
                                />
                                <div className="button-row">
                                  <button className="button button--primary" type="submit" disabled={muteBusy}>
                                    {muteBusy ? "Muting…" : "Confirm mute"}
                                  </button>
                                  <button
                                    className="button button--secondary"
                                    type="button"
                                    disabled={muteBusy}
                                    onClick={() => setMutingId(null)}
                                  >
                                    Cancel
                                  </button>
                                </div>
                              </form>
                            ) : (
                              <button
                                className="button button--secondary"
                                type="button"
                                onClick={() => {
                                  setMutingId(item.id);
                                  setMuteReason("");
                                  setMuteError(null);
                                }}
                              >
                                Mute alert
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState
                  icon={<ShieldCheck aria-hidden="true" />}
                  title="Nothing needs your attention"
                  detail="Bower will list anything that needs a person here, with what to do about it. Check Reports for the latest delivery test."
                  action={{ to: "/reports", label: "Check delivery reports" }}
                />
              )}
            </section>}

            {view === "home" && <section className="sheet section-gap home-card" aria-labelledby="home-groups">
              <header className="home-card__header">
                <h2 id="home-groups">
                  <GlossaryText text="Collector groups" />
                </h2>
                <span className="home-card__count">
                  {home.groups.length < home.groupsTotal
                    ? `${home.groups.length} of ${home.groupsTotal} shown, most urgent first`
                    : "Most urgent first"}
                </span>
              </header>
              {home.groups.length ? (
                <ul className="group-list">
                  {home.groups.map((group) => (
                    <li key={group.name} className={`group-list__item group-list__item--${group.state}`}>
                      <div className="group-list__title">
                        <h3>{group.name}</h3>
                        <TrafficLight state={group.state} />
                      </div>
                      <p>
                        <GlossaryText text={group.reason} />
                      </p>
                      <p className="home-card__note">
                        {group.healthy} of {group.collectors} working normally
                        {group.otherIssues > 0 &&
                          `, plus ${count(group.otherIssues, "other issue", "other issues")}`}
                        .
                      </p>
                      {group.fix && <FixLine fix={group.fix} context={`${group.name}: ${group.reason}`} />}
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState
                  icon={<CircleDashed aria-hidden="true" />}
                  title="No collectors yet"
                  detail="Groups appear here once a collector asks to join. Ask your administrator to connect the first machine using Setup."
                  action={{ to: "/help#setup-checklist", label: "View setup checklist" }}
                />
              )}
            </section>}

            {view === "home" && <p className="home-footer">
              <Link to="/overview">See the detailed overview</Link> for machine names, queues and
              policy versions.
            </p>}
          </>
        )}
      </ResourceState>
    </Page>
  );
}

function SentinelProof({ proof }: { proof: HomeSentinelProof }) {
  const verified = proof.state === "verified";
  const Icon = verified ? CheckCircle2 : proof.state === "in-progress" ? Clock3 : TriangleAlert;
  return (
    <div className={`proof-line proof-line--${proof.state}`}>
      <Icon aria-hidden="true" />
      <div>
        <p>
          <GlossaryText text={proof.message} />
          {proof.at && ` (${formatDate(proof.at)})`}
        </p>
        {proof.fix && <FixLine fix={proof.fix} context={proof.message} />}
      </div>
    </div>
  );
}

/** "How to fix:" with a link to the page that does it. The link name says what it is for. */
function FixLine({ fix, context }: { fix: HomeFix; context: string }) {
  const name = pageNames[fix.page];
  return (
    <p className="fix-line">
      <strong>How to fix:</strong> {fix.action}{" "}
      {name && (
        <Link to={fix.page} aria-label={`Go to ${name} for: ${context}`}>
          Go to {name}
        </Link>
      )}
    </p>
  );
}

function count(value: number, one: string, many: string): string {
  return `${value.toLocaleString()} ${value === 1 ? one : many}`;
}

function formatDay(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" }).format(
    new Date(value)
  );
}

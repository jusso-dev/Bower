import { CheckCircle2, CircleDashed, Clock3, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect } from "react";
import { Link } from "react-router-dom";
import { GlossaryText } from "../components/glossary";
import { TrafficLight } from "../components/guided";
import { EmptyState, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Home, HomeFix, HomeSentinelProof } from "../types";

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
export function HomePage() {
  const { data, loading, error, refreshError, revalidate } = useResource<Home>("/api/home");

  useEffect(() => {
    const timer = window.setInterval(() => void revalidate(), refreshMilliseconds);
    return () => window.clearInterval(timer);
  }, [revalidate]);

  return (
    <Page
      title="Home"
      description="Is your data flowing, what was protected this week, and what needs your attention."
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
            <div className="home-grid">
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
            </div>

            <section className="sheet section-gap home-card" aria-labelledby="home-attention">
              <header className="home-card__header">
                <h2 id="home-attention">What needs my attention?</h2>
                <TrafficLight state={home.state} />
              </header>
              {home.attention.length ? (
                <ul className="attention-list">
                  {home.attention.map((item) => (
                    <li key={item.id} className={`attention-list__item attention-list__item--${item.state}`}>
                      <TrafficLight state={item.state} />
                      <div>
                        <p>
                          <GlossaryText text={item.message} />
                        </p>
                        <FixLine fix={item.fix} context={item.message} />
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState
                  icon={<ShieldCheck aria-hidden="true" />}
                  title="Nothing needs your attention"
                  detail="Bower will list anything that needs a person here, with what to do about it."
                />
              )}
            </section>

            <section className="sheet section-gap home-card" aria-labelledby="home-groups">
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
                  detail="Groups appear here once a collector asks to join."
                />
              )}
            </section>

            <p className="home-footer">
              <Link to="/overview">See the detailed overview</Link> for machine names, queues and
              policy versions.
            </p>
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

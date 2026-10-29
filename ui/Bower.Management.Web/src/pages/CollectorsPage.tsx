import { Boxes, CheckCircle2, CircleDashed, Search, TriangleAlert, XCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigationType, useParams, useSearchParams } from "react-router-dom";
import { CollectorTable, EmptyState, Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Collector, Fleet, FleetCollector } from "../types";

const fixPages: Record<string, string> = {
  "/approvals": "Approvals", "/audit": "Audit", "/enrolment": "Enrolment",
  "/privacy-profiles": "Privacy profiles"
};

export function CollectorsPage() {
  const { data, loading, error, refreshError, revalidate } = useResource<Fleet>("/api/fleet");
  const [params, setParams] = useSearchParams();
  const [refreshing, setRefreshing] = useState(false);
  const refreshInFlight = useRef(false);
  const navigation = useNavigationType();
  const [filters, setFilters] = useState(() => new URLSearchParams(params));
  const currentFilters = useRef(filters);
  const state = filters.get("state") ?? "";
  const site = filters.get("site") ?? "";
  const search = filters.get("search") ?? "";

  // Inputs update immediately; router transitions may complete later. Only external
  // navigation resets them. Our own REPLACE writes must not restore an older edit.
  useEffect(() => {
    if (navigation !== "REPLACE") {
      const next = new URLSearchParams(params);
      currentFilters.current = next;
      setFilters(next);
    }
  }, [params, navigation]);

  const refresh = useCallback(async () => {
    if (loading || refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    try { await revalidate(); } finally {
      refreshInFlight.current = false;
      setRefreshing(false);
    }
  }, [loading, revalidate]);

  useEffect(() => {
    const timer = window.setInterval(() => void refresh(), 60_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  function setFilterValues(next: URLSearchParams) {
    currentFilters.current = next;
    setFilters(next);
    setParams(next, { replace: true });
  }

  function filter(name: string, value: string) {
    const next = new URLSearchParams(currentFilters.current);
    if (value) next.set(name, value); else next.delete(name);
    setFilterValues(next);
  }


  return (
    <Page title="Collectors" description="See which machines need attention, what happened, and what to do next.">
      {error && <button className="button button--secondary" type="button" onClick={() => void refresh()} disabled={refreshing}>Try again</button>}
      <ResourceState loading={loading} error={error} data={data}>
        {(fleet) => {
          const query = search.trim().toLocaleLowerCase();
          const shown = fleet.collectors.filter((item) =>
            (!state || item.state === state) && (!site || item.site === site) &&
            (!query || `${item.machineName} ${item.id}`.toLocaleLowerCase().includes(query)));
          return (
            <>
              <div className="fleet-updated">
                <p>Updated {formatDate(fleet.generatedAt)} · Most urgent first</p>
                <button className="button button--secondary" type="button" disabled={refreshing} onClick={() => void refresh()}>
                  {refreshing ? "Refreshing…" : "Refresh"}
                </button>
              </div>
              {refreshError && <div className="alert" role="status"><strong>Status may be out of date.</strong><span>Could not refresh. Showing the last successful update above.</span></div>}
              <p className="home-card__note fleet-proof">These states come from collector check-ins. <Link to="/setup">Check arrival in Microsoft Sentinel</Link> separately.</p>
              {fleet.collectors.length ? (
                <>
                  <section className="sheet fleet-filters" aria-label="Filter collectors">
                    <div className="fleet-field"><label htmlFor="fleet-state">State</label><select id="fleet-state" value={state} onChange={(event) => filter("state", event.target.value)}>
                      <option value="">All states</option>
                      {state && !fleet.states.some((item) => item.state === state) && <option value={state}>Previous state (no collectors)</option>}
                      {fleet.states.map((item) => <option key={item.state} value={item.state}>{item.label} ({item.collectors})</option>)}
                    </select></div>
                    <div className="fleet-field"><label htmlFor="fleet-site">Site</label><select id="fleet-site" value={site} onChange={(event) => filter("site", event.target.value)}>
                      <option value="">All sites</option>
                      {site && !fleet.sites.some((item) => item.name === site) && <option value={site}>{site} (no collectors)</option>}
                      {fleet.sites.map((item) => <option key={item.name} value={item.name}>{item.name} ({item.collectors})</option>)}
                    </select></div>
                    <div className="fleet-field"><label htmlFor="fleet-search">Find a machine</label><input id="fleet-search" type="search" value={search} onChange={(event) => filter("search", event.target.value)} placeholder="Machine name or collector ID" /></div>
                    {(state || site || search) && <button className="text-button" type="button" onClick={() => setFilterValues(new URLSearchParams())}>Clear filters</button>}
                  </section>
                  <p role="status" className="home-card__note">Showing {shown.length} of {fleet.collectors.length} collectors</p>
                  {shown.length ? <ul className="fleet-list" aria-label="Collectors by urgency">
                    {shown.map((item) => <li key={item.id} className="sheet fleet-card">
                      <div className="fleet-card__heading">
                        <div><h2><Link to={`/collectors/${encodeURIComponent(item.id)}`}>{item.machineName}</Link></h2><p>{item.site} · {item.id}</p></div>
                        <FleetBadge collector={item} />
                      </div>
                      <FleetReason collector={item} />
                      <p className="home-card__note">Last check-in: {formatDate(item.lastSeenAt)}{item.path === "relay" && " · Through a relay"}</p>
                      <Link to={`/collectors/${encodeURIComponent(item.id)}`} aria-label={`View details for ${item.machineName}`}>View details</Link>
                    </li>)}
                  </ul> : <EmptyState icon={<Search aria-hidden="true" />} title="No matching collectors" detail="Try another state, site or machine name, or clear the filters." />}
                </>
              ) : <EmptyState icon={<Boxes aria-hidden="true" />} title="No collectors yet" detail="Connect your first machine using Setup. It will appear here when it asks to join." />}
              {!fleet.collectors.length && <Link to="/setup">Open Setup</Link>}
            </>
          );
        }}
      </ResourceState>
    </Page>
  );
}

function FleetBadge({ collector }: { collector: FleetCollector }) {
  const Icon = collector.light === "green" ? CheckCircle2 : collector.light === "red" ? XCircle : collector.light === "amber" ? TriangleAlert : CircleDashed;
  return <span className={`traffic-light traffic-light--${collector.light}`}><Icon aria-hidden="true" />{collector.label}</span>;
}

function FleetReason({ collector }: { collector: FleetCollector }) {
  const page = collector.fix?.page;
  return <>
    <p>{collector.reason}</p>
    {collector.fix && <p className="fix-line"><strong>What to do:</strong> {collector.fix.action}{page && fixPages[page] && <> <Link to={page}>Open {fixPages[page]}</Link></>}</p>}
    {collector.otherIssues > 0 && <p className="home-card__note">Also has {collector.otherIssues} other {collector.otherIssues === 1 ? "issue" : "issues"}. Review the machine details.</p>}
  </>;
}

export function CollectorDetailPage() {
  const { id = "" } = useParams();
  // Remount on identity changes so a late response cannot replace a different machine's details.
  return <CollectorDetail key={id} id={id} />;
}

function CollectorDetail({ id }: { id: string }) {
  const summary = useResource<FleetCollector>(`/api/fleet/${encodeURIComponent(id)}`);
  const detail = useResource<Collector>(`/api/collectors/${encodeURIComponent(id)}`);
  return <Page title="Collector details" description="Reported machine health and the next step to take.">
    <Link className="fleet-return" to="/collectors">Back to collectors</Link>
    <ResourceState loading={summary.loading} error={summary.error} data={summary.data}>
      {(item) => <section className="sheet fleet-card section-gap" aria-label={item.machineName}>
        <div className="fleet-card__heading"><h2>{item.machineName}</h2><FleetBadge collector={item} /></div>
        <FleetReason collector={item} />
        <dl className="fleet-facts">
          <div><dt>Site</dt><dd>{item.site}</dd></div>
          <div><dt>Bower version</dt><dd>{item.version}</dd></div>
          <div><dt>Last check-in</dt><dd>{formatDate(item.lastSeenAt)}</dd></div>
          <div><dt>Delivery path</dt><dd>{item.path === "relay" ? "Through a relay" : item.path === "direct" ? "Direct from this machine" : "Not reported yet"}</dd></div>
        </dl>
        <p className="home-card__note">This is the latest reported snapshot. <Link to="/setup">Check arrival in Microsoft Sentinel</Link> separately.</p>
      </section>}
    </ResourceState>
    <ResourceState loading={detail.loading} error={detail.error} data={detail.data}>
      {(item) => <section className="sheet fleet-card section-gap" aria-label="Machine details">
        <h2>Machine details</h2>
        <CollectorTable collectors={[item]} />
        <h3>Configured sources</h3>
        {item.sources.length ? <ul>{item.sources.map((source) => <li key={source.id}>{source.id} · {source.type} · {source.status}{source.lastEventAt && ` · Last event: ${formatDate(source.lastEventAt)}`}</li>)}</ul> : <p>No sources reported yet.</p>}
        <h3>Destinations</h3>
        {item.outputs.length ? <ul>{item.outputs.map((output) => <li key={output.id}>{output.id} · {output.type} · {output.status}{output.lastAcknowledgedAt ? ` · Last accepted for sending: ${formatDate(output.lastAcknowledgedAt)}` : " · No acceptance reported yet"}</li>)}</ul> : <p>No destinations reported yet.</p>}
      </section>}
    </ResourceState>
  </Page>;
}

import {
  Activity,
  Boxes,
  CheckCircle2,
  ClipboardCheck,
  GitBranch,
  KeyRound,
  Menu,
  Moon,
  ScrollText,
  ShieldCheck,
  Sun,
  X
} from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useApi } from "./api";
import { useAuth } from "./auth";
import type { Access, Approval, Audit, Collector, Overview, PipelineTemplate } from "./types";

const navItems = [
  { to: "/", label: "Overview", icon: Activity },
  { to: "/collectors", label: "Collectors", icon: Boxes },
  { to: "/pipelines", label: "Pipelines", icon: GitBranch },
  { to: "/approvals", label: "Approvals", icon: ClipboardCheck },
  { to: "/access", label: "Access", icon: KeyRound },
  { to: "/audit", label: "Audit", icon: ScrollText }
];

export function App() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [dark, setDark] = useState(
    () =>
      localStorage.getItem("bower-theme") === "dark" ||
      (!localStorage.getItem("bower-theme") &&
        window.matchMedia("(prefers-color-scheme: dark)").matches)
  );
  const { accountName, authenticated, development, signIn, signOut } = useAuth();

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("bower-theme", dark ? "dark" : "light");
  }, [dark]);

  if (!authenticated) {
    return (
      <main className="sign-in-shell">
        <div className="sign-in-panel">
          <Brand />
          <h1>Sign in to Bower</h1>
          <p>
            Use your organization’s Microsoft Entra ID account. Access is granted
            through assigned Bower app roles.
          </p>
          <button
            className="button button--primary"
            type="button"
            onClick={() => void signIn()}
          >
            Sign in with Entra ID
          </button>
        </div>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <header className="mobile-header">
        <Brand />
        <button
          className="icon-button"
          type="button"
          aria-label={menuOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((value) => !value)}
        >
          {menuOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
        </button>
      </header>

      <aside className={`side-rail${menuOpen ? " side-rail--open" : ""}`}>
        <Brand />
        <nav aria-label="Primary navigation">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              onClick={() => setMenuOpen(false)}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="rail-footer">
          <button
            className="rail-action"
            type="button"
            onClick={() => setDark((value) => !value)}
          >
            {dark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
            <span>{dark ? "Light mode" : "Dark mode"}</span>
          </button>
          <div className="identity-block">
            <span className="identity-name">{accountName || "Not signed in"}</span>
            <span className="identity-mode">{development ? "Development auth" : "Entra ID"}</span>
          </div>
          <button
            className="text-button"
            type="button"
            onClick={() => void (accountName ? signOut() : signIn())}
          >
            {accountName ? "Sign out" : "Sign in"}
          </button>
        </div>
      </aside>

      <main id="main-content">
        {development && (
          <div className="development-banner" role="status">
            Development authentication active. Never enable this mode in production.
          </div>
        )}
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/collectors" element={<CollectorsPage />} />
          <Route path="/pipelines" element={<PipelinesPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
          <Route path="/access" element={<AccessPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function Brand() {
  return (
    <div className="brand" aria-label="Bower Management">
      <span className="brand-mark" aria-hidden="true">
        <i />
        <i />
        <i />
      </span>
      <span>
        <strong>Bower</strong>
        <small>Management</small>
      </span>
    </div>
  );
}

function Page({
  title,
  description,
  children
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="page">
      <header className="page-heading">
        <div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        <span className="live-indicator">
          <span aria-hidden="true" />
          Tenant controlled
        </span>
      </header>
      {children}
    </section>
  );
}

function OverviewPage() {
  const { data, loading, error } = useResource<Overview>("/api/overview");
  return (
    <Page
      title="Fleet posture"
      description="Exceptions first: approval, collection, queue and delivery conditions needing action."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(overview) => (
          <>
            <div className="metric-strip" aria-label="Fleet summary">
              <Metric label="Collectors" value={overview.totalCollectors} />
              <Metric label="Pending" value={overview.pendingApproval} tone="warning" />
              <Metric label="Unhealthy" value={overview.unhealthyCollectors} tone="danger" />
              <Metric label="Stale" value={overview.staleCollectors} tone="warning" />
              <Metric label="Queued" value={overview.totalQueueDepth} />
            </div>
            <div className="workbench-grid">
              <section className="sheet">
                <div className="section-heading">
                  <h2>Exceptions</h2>
                  <span>{overview.exceptions.length} open</span>
                </div>
                {overview.exceptions.length ? (
                  <CollectorTable collectors={overview.exceptions} />
                ) : (
                  <EmptyState
                    icon={<ShieldCheck aria-hidden="true" />}
                    title="No fleet exceptions"
                    detail="All enrolled collectors are reporting without a detected approval or delivery exception."
                  />
                )}
              </section>
              <aside className="coverage-panel">
                <h2>Source coverage</h2>
                <CoverageRow
                  label="Reporting"
                  value={overview.sourcesReporting}
                  total={overview.sourcesReporting + overview.sourcesDegraded}
                />
                <CoverageRow
                  label="Degraded"
                  value={overview.sourcesDegraded}
                  total={overview.sourcesReporting + overview.sourcesDegraded}
                  tone="warning"
                />
                <p>
                  Coverage reflects collector heartbeats. It does not prove destination
                  queryability; use a Bower Evidence Bundle for that claim.
                </p>
              </aside>
            </div>
          </>
        )}
      </ResourceState>
    </Page>
  );
}

function CollectorsPage() {
  const { data, loading, error } = useResource<Collector[]>("/api/collectors");
  return (
    <Page
      title="Collectors"
      description="Machines, configured sources, queue pressure and acknowledged output health."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(collectors) =>
          collectors.length ? (
            <section className="sheet">
              <CollectorTable collectors={collectors} />
            </section>
          ) : (
            <EmptyState
              icon={<Boxes aria-hidden="true" />}
              title="No collectors enrolled"
              detail="Install a Bower Collector and register its service principal to start the approval flow."
            />
          )
        }
      </ResourceState>
    </Page>
  );
}

function PipelinesPage() {
  const { data, loading, error } = useResource<PipelineTemplate[]>(
    "/api/pipelines/templates"
  );
  return (
    <Page
      title="Pipeline builder"
      description="Reusable telemetry pipeline templates with validation-ready node graphs."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(templates) =>
          templates.length ? (
            <div className="workbench-grid">
              {templates.map((template) => (
                <section className="sheet" key={template.id}>
                  <div className="section-heading">
                    <h2>{template.name}</h2>
                    <span className="mono">{template.version}</span>
                  </div>
                  <p>{template.description}</p>
                  <p className="muted">
                    {template.nodes.length} nodes · {template.edges.length} edges
                  </p>
                  <ol className="compact-list">
                    {template.nodes.map((node) => (
                      <li key={node.id}>
                        <span className="mono">{node.id}</span> · {node.kind} ·{" "}
                        {node.type}
                      </li>
                    ))}
                  </ol>
                </section>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<GitBranch aria-hidden="true" />}
              title="No pipeline templates"
              detail="Publish a template through the management API to design telemetry paths."
            />
          )
        }
      </ResourceState>
    </Page>
  );
}

function ApprovalsPage() {
  const api = useApi();
  const [refresh, setRefresh] = useState(0);
  const pending = useResource<Collector[]>("/api/collectors?status=Pending", refresh);
  const history = useResource<Approval[]>("/api/approvals", refresh);
  const access = useResource<Access>("/api/access/me");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const canApprove =
    access.data?.roles.some(
      (role) => role === "Bower.Approver" || role === "Bower.Administrator"
    ) ?? false;

  async function decide(
    formElement: HTMLFormElement,
    collectorId: string,
    action: "approve" | "reject"
  ) {
    const form = new FormData(formElement);
    const reason = String(form.get("reason") ?? "").trim();
    if (!reason) {
      setActionError("Enter a reason before recording the decision.");
      return;
    }
    setBusyId(collectorId);
    setActionError(null);
    try {
      await api(`/api/approvals/${encodeURIComponent(collectorId)}/${action}`, {
        method: "POST",
        body: JSON.stringify({ reason })
      });
      setRefresh((value) => value + 1);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Decision failed.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Page
      title="Enrollment approvals"
      description="A collector cannot heartbeat as active until an authorized approver records a decision."
    >
      {actionError && <div className="alert alert--danger">{actionError}</div>}
      <ResourceState loading={pending.loading} error={pending.error} data={pending.data}>
        {(collectors) =>
          collectors.length ? (
            <div className="approval-list">
              {collectors.map((collector) => (
                <article className="approval-item" key={collector.id}>
                  <div>
                    <StatusBadge status={collector.status} />
                    <h2>{collector.machineName}</h2>
                    <dl className="detail-list">
                      <div>
                        <dt>Collector ID</dt>
                        <dd>{collector.id}</dd>
                      </div>
                      <div>
                        <dt>Environment</dt>
                        <dd>{collector.environment}</dd>
                      </div>
                      <div>
                        <dt>Principal</dt>
                        <dd>{collector.principalObjectId}</dd>
                      </div>
                    </dl>
                  </div>
                  {canApprove ? (
                    <form
                      className="approval-form"
                      onSubmit={(event) => {
                        event.preventDefault();
                        void decide(event.currentTarget, collector.id, "approve");
                      }}
                    >
                    <label htmlFor={`reason-${collector.id}`}>Decision reason</label>
                    <textarea
                      id={`reason-${collector.id}`}
                      name="reason"
                      maxLength={500}
                      aria-describedby={`reason-help-${collector.id}`}
                      placeholder="Example: matched approved server inventory request BWR-142"
                      required
                    />
                    <span
                      className="approval-help"
                      id={`reason-help-${collector.id}`}
                    >
                      Required. Recorded in approval history and management audit.
                    </span>
                    <div className="button-row">
                      <button
                        className="button button--primary"
                        type="submit"
                        disabled={busyId === collector.id}
                      >
                        {busyId === collector.id ? "Recording…" : "Approve"}
                      </button>
                      <button
                        className="button button--danger"
                        type="button"
                        disabled={busyId === collector.id}
                        onClick={(event) => {
                          const form = event.currentTarget.form;
                          if (form) {
                            void decide(form, collector.id, "reject");
                          }
                        }}
                      >
                        Reject
                      </button>
                    </div>
                    </form>
                  ) : (
                    <div className="permission-note">
                      <KeyRound aria-hidden="true" />
                      <p>
                        Viewing only. An Entra assignment for{" "}
                        <code>Bower.Approver</code> or{" "}
                        <code>Bower.Administrator</code> is required to decide.
                      </p>
                    </div>
                  )}
                </article>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<CheckCircle2 aria-hidden="true" />}
              title="Approval queue clear"
              detail="New collector identities will remain pending here until an approver records a reasoned decision."
            />
          )
        }
      </ResourceState>

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Decision history</h2>
          <span>Latest 250</span>
        </div>
        <ResourceState loading={history.loading} error={history.error} data={history.data}>
          {(records) =>
            records.length ? (
              <HistoryTable
                headings={["When", "Collector", "Decision", "Actor", "Reason"]}
                rows={records.map((item) => [
                  formatDate(item.occurredAt),
                  item.collectorId,
                  item.action,
                  item.actorName,
                  item.reason
                ])}
              />
            ) : (
              <EmptyState
                title="No decisions recorded"
                detail="Approval and rejection decisions will appear here with actor and reason."
              />
            )
          }
        </ResourceState>
      </section>
    </Page>
  );
}

function AccessPage() {
  const { data, loading, error } = useResource<Access>("/api/access/me");
  const roles = [
    ["Bower.Viewer", "Read fleet, health, approvals and audit records."],
    ["Bower.Operator", "Operate collectors and investigate delivery conditions."],
    ["Bower.Approver", "Approve or reject collector enrollment."],
    ["Bower.Administrator", "Suspend, revoke and administer the management plane."],
    ["Bower.Collector", "Machine-only role for registration and heartbeat."]
  ];
  return (
    <Page
      title="Access control"
      description="Entra groups receive Bower app roles; validated role claims drive API authorization."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(access) => (
          <div className="access-layout">
            <section className="sheet">
              <div className="section-heading">
                <h2>Current session</h2>
                <span>{access.developmentAuthentication ? "Development" : "Entra ID"}</span>
              </div>
              <dl className="detail-list detail-list--wide">
                <div>
                  <dt>Display name</dt>
                  <dd>{access.displayName}</dd>
                </div>
                <div>
                  <dt>Object ID</dt>
                  <dd>{access.objectId}</dd>
                </div>
              </dl>
              <div className="role-list" aria-label="Current roles">
                {access.roles.map((role) => (
                  <span key={role}>{role}</span>
                ))}
              </div>
            </section>
            <section className="sheet">
              <div className="section-heading">
                <h2>Entra role model</h2>
                <span>Group assignable</span>
              </div>
              <div className="role-spec">
                {roles.map(([role, description]) => (
                  <div key={role}>
                    <code>{role}</code>
                    <p>{description}</p>
                  </div>
                ))}
              </div>
              <p className="supporting-copy">
                Assign security groups to these app roles on the Bower enterprise
                application. Group members then receive a compact <code>roles</code> claim;
                Bower does not depend on potentially overage-prone group claims.
              </p>
            </section>
          </div>
        )}
      </ResourceState>
    </Page>
  );
}

function AuditPage() {
  const { data, loading, error } = useResource<Audit[]>("/api/audit");
  return (
    <Page
      title="Management audit"
      description="Enrollment and lifecycle decisions. Event payloads and credentials are never displayed."
    >
      <ResourceState loading={loading} error={error} data={data}>
        {(records) =>
          records.length ? (
            <section className="sheet">
              <HistoryTable
                headings={["When", "Action", "Target", "Actor", "Object ID"]}
                rows={records.map((item) => [
                  formatDate(item.occurredAt),
                  item.action,
                  item.targetId,
                  item.actorName,
                  item.actorObjectId
                ])}
              />
            </section>
          ) : (
            <EmptyState
              icon={<ScrollText aria-hidden="true" />}
              title="No management actions recorded"
              detail="Collector registrations and approval lifecycle actions will create immutable audit rows."
            />
          )
        }
      </ResourceState>
    </Page>
  );
}

function CollectorTable({ collectors }: { collectors: Collector[] }) {
  return (
    <div className="responsive-table">
      <table>
        <thead>
          <tr>
            <th>Machine</th>
            <th>Status</th>
            <th>Environment</th>
            <th>Sources</th>
            <th>Queue</th>
            <th>Delivery</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {collectors.map((collector) => (
            <tr key={collector.id}>
              <td data-label="Machine">
                <strong>{collector.machineName}</strong>
                <small>{collector.id}</small>
              </td>
              <td data-label="Status">
                <StatusBadge status={collector.status} />
              </td>
              <td data-label="Environment">{collector.environment}</td>
              <td data-label="Sources">{collector.sources.length}</td>
              <td data-label="Queue">{collector.queueDepth.toLocaleString()}</td>
              <td data-label="Delivery">
                <HealthLabel value={collector.deliveryStatus} />
              </td>
              <td data-label="Last seen">{formatDate(collector.lastSeenAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HistoryTable({ headings, rows }: { headings: string[]; rows: string[][] }) {
  return (
    <div className="responsive-table">
      <table>
        <thead>
          <tr>
            {headings.map((heading) => (
              <th key={heading}>{heading}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={`${row[0]}-${rowIndex}`}>
              {row.map((cell, index) => (
                <td key={`${headings[index]}-${cell}`} data-label={headings[index]}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatusBadge({ status }: { status: Collector["status"] }) {
  return (
    <span className={`status-badge status-badge--${status.toLowerCase()}`}>
      <span aria-hidden="true" />
      {status}
    </span>
  );
}

function HealthLabel({ value }: { value: string }) {
  const healthy = value.toLowerCase() === "healthy";
  return (
    <span className={`health-label${healthy ? "" : " health-label--degraded"}`}>
      {healthy ? <CheckCircle2 aria-hidden="true" /> : <Activity aria-hidden="true" />}
      {value}
    </span>
  );
}

function Metric({
  label,
  value,
  tone
}: {
  label: string;
  value: number;
  tone?: "warning" | "danger";
}) {
  return (
    <div className={`metric${tone ? ` metric--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value.toLocaleString()}</strong>
    </div>
  );
}

function CoverageRow({
  label,
  value,
  total,
  tone
}: {
  label: string;
  value: number;
  total: number;
  tone?: "warning";
}) {
  const percent = total ? Math.round((value / total) * 100) : 0;
  return (
    <div className={`coverage-row${tone ? " coverage-row--warning" : ""}`}>
      <div>
        <span>{label}</span>
        <strong>{value.toLocaleString()}</strong>
      </div>
      <progress max={100} value={percent} aria-label={`${label}: ${percent}%`} />
    </div>
  );
}

function EmptyState({
  icon,
  title,
  detail
}: {
  icon?: ReactNode;
  title: string;
  detail: string;
}) {
  return (
    <div className="empty-state">
      {icon}
      <h2>{title}</h2>
      <p>{detail}</p>
    </div>
  );
}

function ResourceState<T>({
  loading,
  error,
  data,
  children
}: {
  loading: boolean;
  error: string | null;
  data: T | null;
  children: (value: T) => ReactNode;
}) {
  if (loading) {
    return (
      <div className="skeleton-stack" aria-label="Loading">
        <span />
        <span />
        <span />
      </div>
    );
  }
  if (error) {
    return (
      <div className="alert alert--danger" role="alert">
        <strong>Could not load this view.</strong>
        <span>{error}</span>
      </div>
    );
  }
  return data === null ? null : children(data);
}

function useResource<T>(path: string, refresh = 0) {
  const api = useApi();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api<T>(path));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unknown request failure.");
    } finally {
      setLoading(false);
    }
  }, [api, path]);

  useEffect(() => {
    void load();
  }, [load, refresh]);

  return { data, loading, error, reload: load };
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

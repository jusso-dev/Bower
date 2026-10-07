import { Activity, CheckCircle2, CircleDashed, XCircle } from "lucide-react";
import { type ReactNode } from "react";
import { formatDate } from "../lib/format";
import type { Collector } from "../types";

export function Brand() {
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

export function Page({
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

export function CollectorTable({ collectors }: { collectors: Collector[] }) {
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

export function HistoryTable({ headings, rows }: { headings: string[]; rows: string[][] }) {
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

export function StatusBadge({ status }: { status: Collector["status"] }) {
  return (
    <span className={`status-badge status-badge--${status.toLowerCase()}`}>
      <span aria-hidden="true" />
      {status}
    </span>
  );
}

export function HealthLabel({ value }: { value: string }) {
  const healthy = value.toLowerCase() === "healthy";
  return (
    <span className={`health-label${healthy ? "" : " health-label--degraded"}`}>
      {healthy ? <CheckCircle2 aria-hidden="true" /> : <Activity aria-hidden="true" />}
      {value}
    </span>
  );
}

export function Metric({
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

export function CoverageRow({
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

export function EmptyState({
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

export function ResourceState<T>({
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

/** Hangfire job state: Succeeded, Failed, Processing, Enqueued, Scheduled or not yet run. */
export function JobStateLabel({ value }: { value: string | null }) {
  if (!value) {
    return (
      <span className="health-label health-label--pending">
        <CircleDashed aria-hidden="true" />
        Not run yet
      </span>
    );
  }
  const state = value.toLowerCase();
  if (state === "succeeded") {
    return (
      <span className="health-label">
        <CheckCircle2 aria-hidden="true" />
        Succeeded
      </span>
    );
  }
  if (state === "failed" || state === "deleted") {
    return (
      <span className="health-label health-label--failed">
        <XCircle aria-hidden="true" />
        {value}
      </span>
    );
  }
  return (
    <span className="health-label health-label--pending">
      <Activity aria-hidden="true" />
      {value}
    </span>
  );
}

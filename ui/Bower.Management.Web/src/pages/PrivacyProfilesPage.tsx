import { FilePlus2, KeyRound, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useApi } from "../api";
import {
  EmptyState,
  HistoryTable,
  Page,
  PrivacyProfileLabel,
  ResourceState,
  StatusBadge,
  VersionStatusBadge
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type {
  Access,
  Collector,
  PrivacyProfileAssignment,
  PrivacyProfileVersionDetail,
  PrivacyProfileVersionSummary
} from "../types";
import { PrivacyProfileEditor, starterProfile } from "./PrivacyProfileEditor";
import { PrivacyProfileVersionPanel, versionDetailHeadingId } from "./PrivacyProfileVersionPanel";

const authorRoles = ["Bower.Operator", "Bower.Approver", "Bower.Administrator"];

function focusDetailHeading() {
  window.setTimeout(() => document.getElementById(versionDetailHeadingId)?.focus(), 0);
}

function groupByProfile(versions: PrivacyProfileVersionSummary[]) {
  const groups = new Map<string, PrivacyProfileVersionSummary[]>();
  for (const version of versions) {
    const group = groups.get(version.profileId);
    if (group) {
      group.push(version);
    } else {
      groups.set(version.profileId, [version]);
    }
  }
  return [...groups.entries()];
}

export function PrivacyProfilesPage() {
  const api = useApi();
  const [refresh, setRefresh] = useState(0);
  const versions = useResource<PrivacyProfileVersionSummary[]>("/api/privacy-profiles", refresh);
  const assignments = useResource<PrivacyProfileAssignment[]>(
    "/api/privacy-profiles/assignments",
    refresh
  );
  const collectors = useResource<Collector[]>("/api/collectors", refresh);
  const access = useResource<Access>("/api/access/me");
  const [params, setParams] = useSearchParams();
  const selectedId = params.get("version");
  const [editor, setEditor] = useState<{ content: string; basedOn: string | null } | null>(
    null
  );
  const [opening, setOpening] = useState(false);
  const [message, setMessage] = useState<{ tone: "positive" | "danger"; text: string } | null>(
    null
  );
  const canAuthor = access.data?.roles.some((role) => authorRoles.includes(role)) ?? false;

  function select(id: string) {
    setParams({ version: id });
    focusDetailHeading();
  }

  async function openEditor() {
    const sourceId = selectedId ?? versions.data?.[0]?.id ?? null;
    setMessage(null);
    if (!sourceId) {
      setEditor({ content: starterProfile, basedOn: null });
      return;
    }
    setOpening(true);
    try {
      const source = await api<PrivacyProfileVersionDetail>(
        `/api/privacy-profiles/versions/${encodeURIComponent(sourceId)}`
      );
      setEditor({ content: source.content, basedOn: `${source.profileId}@${source.version}` });
    } catch (error) {
      setMessage({
        tone: "danger",
        text: error instanceof Error ? error.message : "Could not load the version to prefill."
      });
    } finally {
      setOpening(false);
    }
  }

  function changed(text: string) {
    setMessage({ tone: "positive", text });
    setRefresh((value) => value + 1);
  }

  return (
    <Page
      title="Privacy profiles"
      description="Versioned privacy profiles with custom detectors. Every privacy profile version needs a second person to approve it before an administrator can assign it to collectors."
    >
      {message && (
        <div className={`alert alert--${message.tone}`} role="status">
          {message.text}
        </div>
      )}

      {access.data &&
        (canAuthor ? (
          !editor && (
            <div className="button-row">
              <button
                className="button button--primary"
                type="button"
                disabled={opening || versions.loading}
                onClick={() => void openEditor()}
              >
                <FilePlus2 aria-hidden="true" />
                {opening ? "Loading…" : "Submit new version"}
              </button>
            </div>
          )
        ) : (
          <div className="permission-note">
            <KeyRound aria-hidden="true" />
            <p>
              Viewing only. An Entra assignment for <code>Bower.Operator</code>,{" "}
              <code>Bower.Approver</code> or <code>Bower.Administrator</code> is required to
              submit a privacy profile version.
            </p>
          </div>
        ))}

      {editor && (
        <PrivacyProfileEditor
          initialContent={editor.content}
          basedOn={editor.basedOn}
          onCancel={() => setEditor(null)}
          onSubmitted={(detail) => {
            setEditor(null);
            changed(
              `Submitted ${detail.profileId}@${detail.version} for review. Another approver must approve it.`
            );
            select(detail.id);
          }}
        />
      )}

      <section className="section-gap" aria-labelledby="privacy-versions-title">
        <div className="subsection-heading">
          <div>
            <h2 id="privacy-versions-title">Privacy profile versions</h2>
            <p>Immutable submitted copies, newest first.</p>
          </div>
          <span>Latest 500</span>
        </div>
        <ResourceState loading={versions.loading} error={versions.error} data={versions.data}>
          {(records) =>
            records.length ? (
              <div className="version-groups">
                {groupByProfile(records).map(([profileId, items]) => (
                  <section className="sheet" key={profileId} aria-label={profileId}>
                    <div className="section-heading">
                      <h3 className="mono">{profileId}</h3>
                      <span>
                        {items.length} version{items.length === 1 ? "" : "s"}
                      </span>
                    </div>
                    <VersionTable items={items} selectedId={selectedId} onSelect={select} />
                  </section>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={<ShieldCheck aria-hidden="true" />}
                title="No privacy profile versions"
                detail="Collectors keep their local or built-in default privacy profile until an approved privacy profile version is assigned."
              />
            )
          }
        </ResourceState>
      </section>

      {selectedId && (
        <PrivacyProfileVersionPanel
          key={selectedId}
          id={selectedId}
          access={access.data}
          collectors={collectors.data}
          refresh={refresh}
          onChanged={changed}
        />
      )}

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Collector sync status</h2>
          <span>Reported in heartbeats</span>
        </div>
        <ResourceState
          loading={collectors.loading}
          error={collectors.error}
          data={collectors.data}
        >
          {(records) =>
            records.length ? (
              <div className="responsive-table">
                <table>
                  <thead>
                    <tr>
                      <th>Collector</th>
                      <th>Status</th>
                      <th>Privacy profile</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((collector) => (
                      <tr key={collector.id}>
                        <td data-label="Collector">
                          <strong>{collector.machineName}</strong>
                          <small>{collector.id}</small>
                        </td>
                        <td data-label="Status">
                          <StatusBadge status={collector.status} />
                        </td>
                        <td data-label="Privacy profile">
                          <PrivacyProfileLabel collector={collector} />
                        </td>
                        <td data-label="Last seen">{formatDate(collector.lastSeenAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="No collectors enrolled"
                detail="Assigned privacy profile versions and their sync status appear here once collectors register."
              />
            )
          }
        </ResourceState>
      </section>

      <section className="sheet section-gap">
        <div className="section-heading">
          <h2>Assignment history</h2>
          <span>Latest 250</span>
        </div>
        <ResourceState
          loading={assignments.loading}
          error={assignments.error}
          data={assignments.data}
        >
          {(records) =>
            records.length ? (
              <HistoryTable
                headings={["When", "Collector", "Action", "Privacy profile version", "Actor", "Reason"]}
                rows={records.map((item) => [
                  formatDate(item.occurredAt),
                  item.collectorId,
                  item.action === "assigned" ? "Assigned" : "Cleared",
                  item.profileId && item.version ? `${item.profileId}@${item.version}` : "—",
                  item.actorName ?? "—",
                  item.reason
                ])}
              />
            ) : (
              <EmptyState
                title="No assignments recorded"
                detail="Assigning or clearing a privacy profile version on a collector is recorded here with actor and reason."
              />
            )
          }
        </ResourceState>
      </section>
    </Page>
  );
}

function VersionTable({
  items,
  selectedId,
  onSelect
}: {
  items: PrivacyProfileVersionSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="responsive-table">
      <table>
        <thead>
          <tr>
            <th>Version</th>
            <th>Status</th>
            <th>Author</th>
            <th>Created</th>
            <th>Reviewer</th>
            <th>Assigned collectors</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className={item.id === selectedId ? "row--selected" : undefined}>
              <td data-label="Version">
                <button
                  className="text-button mono"
                  type="button"
                  aria-current={item.id === selectedId ? "true" : undefined}
                  onClick={() => onSelect(item.id)}
                >
                  {item.version}
                </button>
                <small title={item.changeSummary}>{item.changeSummary}</small>
              </td>
              <td data-label="Status">
                <VersionStatusBadge status={item.status} />
              </td>
              <td data-label="Author">{item.authorName ?? "—"}</td>
              <td data-label="Created">{formatDate(item.createdAt)}</td>
              <td data-label="Reviewer">
                {item.reviewerName ?? "—"}
                {item.reviewedAt && <small>{formatDate(item.reviewedAt)}</small>}
              </td>
              <td data-label="Assigned collectors">{item.assignedCollectors.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

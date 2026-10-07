import { ScrollText } from "lucide-react";
import {
  Page,
  HistoryTable,
  EmptyState,
  ResourceState
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDate } from "../lib/format";
import type { Audit } from "../types";

export function AuditPage() {
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

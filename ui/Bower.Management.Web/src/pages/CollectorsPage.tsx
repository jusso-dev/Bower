import { Boxes } from "lucide-react";
import {
  Page,
  CollectorTable,
  EmptyState,
  ResourceState
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import type { Collector } from "../types";

export function CollectorsPage() {
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

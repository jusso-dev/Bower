import { GitBranch } from "lucide-react";
import { Page, EmptyState, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import type { PipelineTemplate } from "../types";
import { CustomLogWorkbench } from "./CustomLogWorkbench";

export function PipelinesPage() {
  const { data, loading, error } = useResource<PipelineTemplate[]>(
    "/api/pipelines/templates"
  );
  return (
    <Page
      title="Pipeline builder"
      description="Infer custom log parsers, validate transformed fields and use reusable pipeline templates."
    >
      <CustomLogWorkbench />
      <ResourceState loading={loading} error={error} data={data}>
        {(templates) =>
          templates.length ? (
            <section className="section-gap">
              <div className="subsection-heading">
                <h2>Pipeline templates</h2>
                <span>{templates.length} available</span>
              </div>
              <div className="workbench-grid">
                {templates.map((template) => (
                  <section className="sheet" key={template.id}>
                    <div className="section-heading">
                      <h2>{template.name}</h2>
                      <span className="mono">{template.version}</span>
                    </div>
                    <div className="sheet-body">
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
                    </div>
                  </section>
                ))}
              </div>
            </section>
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

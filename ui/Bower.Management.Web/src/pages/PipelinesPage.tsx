import { GitBranch } from "lucide-react";
import { Page, EmptyState, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import type { Access, PipelineTemplate } from "../types";
import { CustomLogWorkbench } from "./CustomLogWorkbench";

export function PipelinesPage() {
  const access = useResource<Access>("/api/access/me");
  const canEdit = access.data?.roles.some(role => ["Bower.Operator", "Bower.Approver", "Bower.Administrator"].includes(role)) ?? false;
  const { data, loading, error } = useResource<PipelineTemplate[]>(
    "/api/pipelines/templates"
  );
  return (
    <Page
      title="Pipeline builder"
      description="Infer custom log parsers, validate transformed fields and use reusable pipeline templates."
    >
      {canEdit ? <CustomLogWorkbench /> : <p className="permission-note">
        Viewing only. An operator can generate and preview parser configuration. You can read the available templates below.
      </p>}
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
              detail="Ask an administrator to check that pipeline templates are available in the management service. To connect a supported source, start in Sources."
              action={{ to: "/sources", label: "Set up a source" }}
            />
          )
        }
      </ResourceState>
    </Page>
  );
}

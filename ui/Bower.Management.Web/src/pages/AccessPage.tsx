import { Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import type { Access } from "../types";

export function AccessPage() {
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

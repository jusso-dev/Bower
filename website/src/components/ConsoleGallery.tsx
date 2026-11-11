import { useState, type KeyboardEvent } from "react";
import useBaseUrl from "@docusaurus/useBaseUrl";
import { useColorMode } from "@docusaurus/theme-common";
import styles from "./ConsoleGallery.module.css";

// Screenshots come from e2e/docs-gallery.spec.ts in the console project, on its synthetic
// preview dataset. Each view ships in light and dark; the gallery follows the site's theme.
export type View = { id: string; label: string; caption: string; guide: string };

export const VIEWS: View[] = [
  { id: "home", label: "Home", caption: "What needs attention, what was protected this week, and collector groups, in plain language.", guide: "/operations/console-home/" },
  { id: "overview", label: "Fleet posture", caption: "Exceptions first: approval, collection, queue, delivery and privacy profile conditions that need action.", guide: "/operations/console-fleet/" },
  { id: "setup", label: "Setup", caption: "A seven-step wizard from sign-in to a verified canary. Progress is saved on the server.", guide: "/operations/console-onboarding/" },
  { id: "sources", label: "Sources", caption: "Guided setup for each kind of source. Bower writes the settings, someone else approves them.", guide: "/operations/console-sources/" },
  { id: "privacy", label: "Privacy", caption: "Edit a privacy profile with forms, preview the protected example, and submit a version for approval.", guide: "/operations/console-privacy-editor/" },
  { id: "collector", label: "Collector", caption: "One collector: queue, delivery, policy drift, dead letters and the suggested fix.", guide: "/operations/console-fleet/" },
  { id: "approvals", label: "Approvals", caption: "Approve a collector's identity, a source request or a privacy profile. The requester cannot approve their own.", guide: "/security/management-identity-and-rbac/" },
  { id: "reports", label: "Reports", caption: "Canary results and evidence bundles. Only a Sentinel query that finds the exact event is proof.", guide: "/operations/evidence-bundles/" }
];

export default function ConsoleGallery({ views = VIEWS }: { views?: View[] }) {
  const [active, setActive] = useState(0);
  const { colorMode } = useColorMode();
  const base = useBaseUrl("/img/console/");
  const view = views[active];

  function onKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = views.length - 1;
    const next = event.key === "ArrowRight" ? (index === last ? 0 : index + 1)
      : event.key === "ArrowLeft" ? (index === 0 ? last : index - 1)
      : event.key === "Home" ? 0 : event.key === "End" ? last : null;
    if (next === null) return;
    event.preventDefault();
    setActive(next);
    document.getElementById(`gallery-tab-${views[next].id}`)?.focus();
  }

  return (
    <div className={styles.gallery}>
      <div role="tablist" aria-label="Console views" className={styles.tabs}>
        {views.map((item, index) => (
          <button
            key={item.id}
            id={`gallery-tab-${item.id}`}
            role="tab"
            type="button"
            aria-selected={index === active}
            aria-controls={`gallery-panel-${item.id}`}
            tabIndex={index === active ? 0 : -1}
            className={index === active ? styles.tabActive : styles.tab}
            onClick={() => setActive(index)}
            onKeyDown={(event) => onKey(event, index)}
          >
            {item.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`gallery-panel-${view.id}`} aria-labelledby={`gallery-tab-${view.id}`} className={styles.panel}>
        <div className={styles.frame}>
          <div className={styles.chrome} aria-hidden="true"><span /><span /><span /><em>bower-management / {view.label.toLowerCase()}</em></div>
          <img
            src={`${base}${view.id}-${colorMode}.png`}
            alt={`Bower management console, ${view.label} page, ${colorMode} mode, with synthetic preview data`}
            width={1440}
            height={900}
            loading="lazy"
          />
        </div>
        <div className={styles.caption}>
          <p>{view.caption}</p>
          <a href={useBaseUrl(view.guide)}>Read the {view.label} guide →</a>
        </div>
      </div>
      <p className={styles.note}>Synthetic preview data. The banner shows the local development sign-in used to capture these; production uses Microsoft Entra ID.</p>
    </div>
  );
}

import {
  Activity,
  Boxes,
  CircleHelp,
  ClipboardCheck,
  FileLock,
  GitBranch,
  House,
  KeyRound,
  ListChecks,
  Menu,
  Plug,
  Moon,
  ScrollText,
  Sun,
  Ticket,
  Timer,
  Bell,
  FileChartColumn,
  SlidersHorizontal,
  X
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { Brand } from "./components/ui";
import { HomePage } from "./pages/HomePage";
import { HelpPage } from "./pages/HelpPage";
import { OverviewPage } from "./pages/OverviewPage";
import { CollectorsPage, CollectorDetailPage } from "./pages/CollectorsPage";
import { PipelinesPage } from "./pages/PipelinesPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { AccessPage } from "./pages/AccessPage";
import { AuditPage } from "./pages/AuditPage";
import { JobsPage } from "./pages/JobsPage";
import { PrivacyProfilesPage } from "./pages/PrivacyProfilesPage";
import { SetupPage } from "./pages/SetupPage";
import { EnrolmentPage } from "./pages/EnrolmentPage";
import { SourcesPage } from "./pages/SourcesPage";
import { useConsoleView } from "./hooks/useConsoleView";

const navItems = [
  { to: "/", label: "Home", icon: House },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/reports", label: "Reports", icon: FileChartColumn },
  { to: "/overview", label: "Overview", icon: Activity },
  { to: "/setup", label: "Setup", icon: ListChecks },
  { to: "/collectors", label: "Collectors", icon: Boxes },
  { to: "/sources", label: "Sources", icon: Plug },
  { to: "/pipelines", label: "Pipelines", icon: GitBranch },
  { to: "/approvals", label: "Approvals", icon: ClipboardCheck },
  { to: "/enrolment", label: "Enrolment", icon: Ticket },
  { to: "/privacy-profiles", label: "Privacy profiles", icon: FileLock },
  { to: "/jobs", label: "Jobs", icon: Timer },
  { to: "/access", label: "Access", icon: KeyRound },
  { to: "/audit", label: "Audit", icon: ScrollText },
  { to: "/help", label: "Help", icon: CircleHelp }
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
  const view = useConsoleView(authenticated);
  const location = useLocation();
  const simplePaths = ["/", "/alerts", "/reports", "/help"];
  const technical = !simplePaths.includes(location.pathname.replace(/\/+$/, "") || "/");

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
          {navItems.filter(item => view.detailed || simplePaths.includes(item.to)).map(({ to, label, icon: Icon }) => (
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
          {view.access && <button className="rail-action" type="button" aria-pressed={view.detailed} onClick={view.toggle}>
            <SlidersHorizontal aria-hidden="true" />
            <span>{view.detailed ? "Use simple view" : "Show technical pages"}</span>
          </button>}
          <button
            className="rail-action"
            type="button"
            onClick={() => setDark((value) => !value)}
          >
            {dark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
            <span>{dark ? "Light mode" : "Dark mode"}</span>
          </button>
          <div className="identity-block">
            <span className="identity-name">{view.access?.displayName || accountName || "Not signed in"}</span>
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
        {view.error && <div className="alert alert--danger" role="alert">
          Your access could not be checked. Technical pages are unavailable.
          <button className="button button--secondary" type="button" onClick={view.retry}>Retry access check</button>
        </div>}
        {view.loading && technical ? <p role="status" aria-label="Loading">Checking your access…</p> : !view.detailed && technical ? (
          <section className="sheet section-gap sheet-body" aria-labelledby="technical-pages-title">
            <h1 id="technical-pages-title">Technical details are hidden</h1>
            <p>Simple view shows Home, Alerts and Reports. You can show the technical pages to read more detail. Your permissions stay the same.</p>
            <button className="button button--primary" type="button" disabled={!view.access} onClick={view.toggle}>Show this technical page</button>
          </section>
        ) : (
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/alerts" element={<HomePage view="alerts" />} />
          <Route path="/reports" element={<HomePage view="reports" />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/collectors" element={<CollectorsPage />} />
          <Route path="/collectors/:id" element={<CollectorDetailPage />} />
          <Route path="/sources" element={<SourcesPage />} />
          <Route path="/pipelines" element={<PipelinesPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
          <Route path="/enrolment" element={<EnrolmentPage />} />
          <Route path="/privacy-profiles" element={<PrivacyProfilesPage />} />
          <Route path="/jobs" element={<JobsPage />} />
          <Route path="/access" element={<AccessPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/help" element={<HelpPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        )}
      </main>
    </div>
  );
}

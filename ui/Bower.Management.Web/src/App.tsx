import {
  Activity,
  Boxes,
  ClipboardCheck,
  GitBranch,
  KeyRound,
  Menu,
  Moon,
  ScrollText,
  Sun,
  Timer,
  X
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Brand } from "./components/ui";
import { OverviewPage } from "./pages/OverviewPage";
import { CollectorsPage } from "./pages/CollectorsPage";
import { PipelinesPage } from "./pages/PipelinesPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { AccessPage } from "./pages/AccessPage";
import { AuditPage } from "./pages/AuditPage";
import { JobsPage } from "./pages/JobsPage";

const navItems = [
  { to: "/", label: "Overview", icon: Activity },
  { to: "/collectors", label: "Collectors", icon: Boxes },
  { to: "/pipelines", label: "Pipelines", icon: GitBranch },
  { to: "/approvals", label: "Approvals", icon: ClipboardCheck },
  { to: "/jobs", label: "Jobs", icon: Timer },
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
          <Route path="/jobs" element={<JobsPage />} />
          <Route path="/access" element={<AccessPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

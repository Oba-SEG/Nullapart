import { useQuery } from "@tanstack/react-query";
import { Outlet, Link, useRouterState } from "@tanstack/react-router";
import { useEffect, useRef } from "react";
import {
  Bot,
  Building2,
  BrainCircuit,
  Cable,
  LayoutDashboard,
  LogOut,
  Mail,
  Radar,
  ScrollText,
  Send,
  Server,
  Settings,
  ShieldCheck,
  ShieldAlert,
  SlidersHorizontal,
  Users,
} from "lucide-react";
import { hasPermission, isSystemAdmin, loadSession, logout } from "../auth/session";
import { getSessionPresentation } from "../lib/session-presentation";
import { ImpersonationBanner } from "./ImpersonationBanner";
import { ThemeToggle } from "./ThemeToggle";
import { Toasts } from "./Toasts";
import "./Layout.css";

export function Layout() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const isLogin = pathname === "/login";
  const navRef = useRef<HTMLElement>(null);

  // Keep the active destination visible: the sidebar nav scrolls
  // horizontally below 900px and vertically on short screens, so without
  // this the lime "you are here" pill can sit outside the viewport.
  useEffect(() => {
    const nav = navRef.current;
    if (!nav) return;
    const sync = () => {
      const overflow = nav.scrollWidth > nav.clientWidth + 4;
      const atEnd = overflow && nav.scrollLeft + nav.clientWidth >= nav.scrollWidth - 4;
      nav.classList.toggle("nav-overflow", overflow);
      nav.classList.toggle("nav-at-end", atEnd);
    };
    nav
      .querySelector<HTMLElement>(".nav-link.active")
      ?.scrollIntoView({ block: "nearest", inline: "center" });
    sync();
    nav.addEventListener("scroll", sync, { passive: true });
    const observer = new ResizeObserver(sync);
    observer.observe(nav);
    return () => {
      nav.removeEventListener("scroll", sync);
      observer.disconnect();
    };
  }, [pathname]);

  const session = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });

  if (isLogin) {
    return (
      <main className="main auth-main">
        <Outlet />
      </main>
    );
  }

  const current = session.data ?? null;
  const sessionPresentation = getSessionPresentation(current, session.isError);
  const can = (permission: string) => hasPermission(current, permission);
  const systemAdmin = isSystemAdmin(current);

  return (
    <div className="layout">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar">
        <Link to="/" className="sidebar-brand" aria-label="Nullapart home">
          <img
            src="/brand/logos/horizontal-logo-dark.png"
            alt="Nullapart"
            className="sidebar-logo"
          />
        </Link>

        <div className="sidebar-boundary" aria-label="Operator session context">
          <img src={sessionPresentation.asset} alt="" className="sidebar-boundary-mark" />
          <span>
            <strong>{systemAdmin ? "Platform authority" : "Operator boundary"}</strong>
            <small>{sessionPresentation.boundaryLabel}</small>
          </span>
        </div>

        <nav ref={navRef} className="sidebar-nav" aria-label="Primary">
          <p className="nav-section-label">{systemAdmin ? "System command" : "Security desk"}</p>
          <Link
            to="/"
            className="nav-link"
            activeOptions={{ exact: true }}
            activeProps={{ className: "nav-link active" }}
          >
            <LayoutDashboard size={17} aria-hidden="true" />
            <span>{systemAdmin ? "Command center" : "Security desk"}</span>
          </Link>
          {can("operations:view") ? (
            <Link
              to="/operations"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Server size={17} aria-hidden="true" />
              <span>Runtime control</span>
            </Link>
          ) : null}
          {can("scanner:operations:view") ? (
            <Link
              to="/scanner-operations"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Radar size={17} aria-hidden="true" />
              <span>Scanner fabric</span>
            </Link>
          ) : null}
          {can("domain-security:view") ? (
            <Link
              to="/domain-security"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <ShieldCheck size={17} aria-hidden="true" />
              <span>Domain posture</span>
            </Link>
          ) : null}
          {can("outbound-intelligence:view") ? (
            <Link
              to="/outbound-intelligence"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Send size={17} aria-hidden="true" />
              <span>Outbound protection</span>
            </Link>
          ) : null}

          <p className="nav-section-label">Tenant security</p>
          {can("trace:view") ? (
            <Link
              to="/messages"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Mail size={17} aria-hidden="true" />
              <span>Messages</span>
            </Link>
          ) : null}
          {can("quarantine:view") ? (
            <Link
              to="/quarantine"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <ShieldAlert size={17} aria-hidden="true" />
              <span>Quarantine</span>
            </Link>
          ) : null}
          {can("admin:customers:view") ? (
            <Link
              to="/customers"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Building2 size={17} aria-hidden="true" />
              <span>Customer estate</span>
            </Link>
          ) : null}

          <p className="nav-section-label">Governance</p>
          {can("deep-ai:view") ? (
            <Link to="/deep-ai" className="nav-link" activeProps={{ className: "nav-link active" }}>
              <Bot size={17} aria-hidden="true" />
              <span>Deep AI</span>
            </Link>
          ) : null}
          {can("connectors:view") ? (
            <Link
              to="/connectors-remediation"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Cable size={17} aria-hidden="true" />
              <span>Connectors</span>
            </Link>
          ) : null}
          {can("audit:view") ? (
            <Link
              to="/audit-log"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <ScrollText size={17} aria-hidden="true" />
              <span>Audit log</span>
            </Link>
          ) : null}
          {can("policies:view") ? (
            <Link
              to="/policies"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <SlidersHorizontal size={17} aria-hidden="true" />
              <span>Policies</span>
            </Link>
          ) : null}
          {can("models:view") ? (
            <Link to="/models" className="nav-link" activeProps={{ className: "nav-link active" }}>
              <BrainCircuit size={17} aria-hidden="true" />
              <span>Models</span>
            </Link>
          ) : null}

          {systemAdmin ? <p className="nav-section-label">Platform access</p> : null}
          {can("admin:users:manage") || can("admin:impersonate") ? (
            <Link
              to="/admin-users"
              className="nav-link"
              activeProps={{ className: "nav-link active" }}
            >
              <Users size={17} aria-hidden="true" />
              <span>Admin users</span>
            </Link>
          ) : null}
          <Link to="/settings" className="nav-link" activeProps={{ className: "nav-link active" }}>
            <Settings size={17} aria-hidden="true" />
            <span>{systemAdmin ? "Platform settings" : "Workspace settings"}</span>
          </Link>
        </nav>

        <div className="sidebar-foot">
          <div className="sidebar-foot-row">
            <ThemeToggle />
            <span className="user-name" title={current?.email ?? "Authenticated session"}>
              {current?.email ?? "Authenticated session"}
            </span>
          </div>
          <button
            type="button"
            className="nav-link sidebar-logout"
            onClick={() => void logout()}
            aria-label="Sign out"
          >
            <LogOut size={16} aria-hidden="true" />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      <div className="content">
        <Toasts />
        <ImpersonationBanner session={current} />
        <header className="command-context" aria-label="Current operator context">
          <div className="command-context-product">
            <img src="/brand/logos/logo-mark@2x.png" alt="" />
            <span>{systemAdmin ? "Nullapart System Control" : "Nullapart Security Desk"}</span>
            <span className="command-context-state">{sessionPresentation.stateLabel}</span>
          </div>
          <div className="command-context-scope">
            <ShieldCheck size={15} aria-hidden="true" />
            <span>{sessionPresentation.scopeLabel}</span>
            <span className="command-context-divider" aria-hidden="true" />
            <span className="command-context-email">{current?.email ?? "Loading session…"}</span>
          </div>
        </header>
        <main className="main" id="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}

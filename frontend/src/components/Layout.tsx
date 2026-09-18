import { Outlet, Link, useRouterState } from "@tanstack/react-router";
import "./Layout.css";

export function Layout() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const isLogin = pathname === "/login";

  if (isLogin) {
    return (
      <main className="main auth-main">
        <Outlet />
      </main>
    );
  }

  return (
    <div className="layout">
      <header className="header">
        <div className="header-brand">
          <Link to="/" className="brand-link" aria-label="Nullapart home">
            <span className="brand-name">NULLAPART</span>
          </Link>
        </div>

        <nav className="header-nav" aria-label="Primary">
          <Link to="/" className="nav-link">
            Dashboard
          </Link>
          <Link to="/messages" className="nav-link">
            Messages
          </Link>
          <Link to="/quarantine" className="nav-link">
            Quarantine
          </Link>
          <Link to="/settings" className="nav-link">
            Settings
          </Link>
        </nav>

        <div className="header-actions">
          <div className="user-menu" aria-label="Current session">
            <span className="user-name">Authenticated session</span>
          </div>
        </div>
      </header>

      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

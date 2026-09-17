import { Outlet, Link } from "@tanstack/react-router";
import { useState } from "react";
import "./Layout.css";

export function Layout() {
  const [tenant, setTenant] = useState<string | null>(null);

  return (
    <div className="layout">
      <header className="header">
        <div className="header-brand">
          <Link to="/" className="brand-link">
            <svg className="brand-icon" viewBox="0 0 32 32" fill="currentColor">
              <path d="M16 2C8.268 2 2 8.268 2 16s6.268 14 14 14 14-6.268 14-14S23.732 2 16 2zm0 4c2.21 0 4 1.79 4 4s-1.79 4-4 4-4-1.79-4-4 1.79-4 4-4zm0 20c-5.52 0-10-3.58-10-8v-2c0-1.1.9-2 2-2h16c1.1 0 2 .9 2 2v2c0 4.42-4.48 8-10 8z" />
            </svg>
            <span className="brand-name">Nullapart</span>
          </Link>
        </div>

        <nav className="header-nav">
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
          {tenant && (
            <select
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
              className="tenant-select"
            >
              <option value="tenant-1">Customer A</option>
              <option value="tenant-2">Customer B</option>
            </select>
          )}
          <div className="user-menu">
            <span className="user-name">Admin</span>
          </div>
        </div>
      </header>

      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

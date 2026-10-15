import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, LogOut, Moon, Sun } from "lucide-react";
import { api } from "../api/client";
import { hasPermission, loadSession, logout } from "../auth/session";
import { readStoredTheme, setTheme, subscribeTheme, type Theme } from "../lib/theme";
import { useSyncExternalStore } from "react";
import { Button } from "../components/primitives/Button";
import { ControlRail } from "../components/ControlRail";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide } from "../components/WorkflowGuide";
import "./Settings.css";

interface RuntimeSnapshot {
  deployment_id: string;
  config: { db_revision: number | null };
  outbox: { unpublished_count: number; oldest_unpublished_age_seconds: number | null };
  dead_letters: { count: number };
  scanner: { total: number; active: number; draining: number; offline: number };
}

export function Settings() {
  const theme = useSyncExternalStore(subscribeTheme, readStoredTheme, readStoredTheme);

  const sessionQuery = useQuery({
    queryKey: ["session"],
    queryFn: ({ signal }) => loadSession(signal),
    staleTime: 60_000,
    retry: false,
  });
  const session = sessionQuery.data ?? null;
  const canSeeRuntime = hasPermission(session, "operations:view");

  const runtime = useQuery({
    queryKey: ["operations-runtime"],
    queryFn: ({ signal }) => api.get<RuntimeSnapshot>("/operations/runtime", signal),
    staleTime: 15_000,
    enabled: canSeeRuntime,
  });

  const options: { value: Theme; label: string; Icon: typeof Sun }[] = [
    { value: "dark", label: "Midnight", Icon: Moon },
    { value: "light", label: "Light", Icon: Sun },
  ];

  return (
    <div className="settings-page">
      <WorkspaceHeader
        eyebrow="Console preferences"
        title="Settings"
        description="Control local display preferences and review the authenticated session that is operating this console. Browser preferences never affect server-side access."
        scope="Local browser preferences"
      />

      <ControlRail
        title="Session and local preference state"
        summary="Only the display mode is stored in this browser. Identity, permissions and runtime status are supplied by the authenticated server session."
        signals={[
          { label: "Theme", value: theme, detail: "Current browser-local console preference." },
          {
            label: "Permissions",
            value: session?.permissions?.length ?? "—",
            detail: "Permissions reported by the active session.",
          },
          {
            label: "Runtime",
            value: canSeeRuntime ? "permitted" : "restricted",
            detail: "Runtime detail follows the current server-authorized role.",
            tone: canSeeRuntime ? "healthy" : "neutral",
          },
        ]}
      />

      <WorkflowGuide
        title="Separate console preference from authority"
        description="This page makes it explicit which settings live in the browser and which runtime information is read from the authenticated server session."
        steps={[
          {
            label: "Set appearance",
            detail: "Choose the local display mode for this browser profile.",
          },
          {
            label: "Confirm session",
            detail: "Review the active identity and any customer-entry context.",
          },
          {
            label: "Inspect runtime",
            detail: "Use live runtime detail only when your role permits it.",
          },
        ]}
      />

      <div className="settings-grid">
        <section className="card settings-card" aria-labelledby="settings-appearance-heading">
          <h2 id="settings-appearance-heading" className="section-title">
            Appearance
          </h2>
          <p className="settings-hint">
            The console ships Midnight (dark) as the default. The choice is stored in this browser
            profile only and never affects server-side access.
          </p>
          <div className="settings-segmented" role="group" aria-label="Theme">
            {options.map(({ value, label, Icon }) => (
              <button
                key={value}
                type="button"
                className={`settings-segment${theme === value ? " selected" : ""}`}
                aria-pressed={theme === value}
                onClick={() => setTheme(value)}
              >
                <Icon size={16} aria-hidden="true" />
                {label}
              </button>
            ))}
          </div>
        </section>

        <section className="card settings-card" aria-labelledby="settings-session-heading">
          <h2 id="settings-session-heading" className="section-title">
            Session
          </h2>
          {session ? (
            <>
              <dl className="settings-facts">
                <dt>Signed in as</dt>
                <dd>{session.email}</dd>
                <dt>Roles</dt>
                <dd className="settings-chips">
                  {session.roles.map((role) => (
                    <span className="settings-chip" key={role}>
                      {role}
                    </span>
                  ))}
                </dd>
                <dt>Customer scope</dt>
                <dd>{session.customerId ?? "System scope"}</dd>
                <dt>Permissions</dt>
                <dd>{session.permissions?.length ?? 0} granted</dd>
                <dt>Session expires</dt>
                <dd>{new Date(session.expiresAt).toLocaleString()}</dd>
                <dt>Step-up re-auth</dt>
                <dd>{session.stepUpActive ? "Active" : "Not active"}</dd>
              </dl>
              <Button variant="ghost" onClick={() => void logout()}>
                <LogOut size={14} aria-hidden="true" />
                Sign out
              </Button>
            </>
          ) : sessionQuery.isPending ? (
            <p className="settings-hint" role="status">
              Loading session details…
            </p>
          ) : (
            <p className="settings-hint" role="alert">
              Session details are unavailable. Reload the page or sign in again.
            </p>
          )}
        </section>

        {canSeeRuntime ? (
          <section className="card settings-card" aria-labelledby="settings-deployment-heading">
            <h2 id="settings-deployment-heading" className="section-title">
              Deployment
            </h2>
            {runtime.data ? (
              <>
                <dl className="settings-facts">
                  <dt>Deployment</dt>
                  <dd>{runtime.data.deployment_id}</dd>
                  <dt>Config revision</dt>
                  <dd>{runtime.data.config.db_revision ?? "Unknown"}</dd>
                  <dt>Outbox backlog</dt>
                  <dd>{runtime.data.outbox.unpublished_count} unpublished</dd>
                  <dt>Dead letters</dt>
                  <dd>{runtime.data.dead_letters.count} pending</dd>
                  <dt>Scanner nodes</dt>
                  <dd>
                    {runtime.data.scanner.active}/{runtime.data.scanner.total} active
                  </dd>
                </dl>
                <Link to="/operations" className="settings-link">
                  Open operations <ArrowRight size={14} aria-hidden="true" />
                </Link>
              </>
            ) : runtime.isError ? (
              <p className="settings-hint" role="alert">
                Runtime details are temporarily unavailable.
              </p>
            ) : (
              <p className="settings-hint" role="status">
                Loading runtime details…
              </p>
            )}
          </section>
        ) : null}
      </div>
    </div>
  );
}

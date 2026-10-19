import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, LogOut, Moon, Sun } from "lucide-react";
import { api } from "../api/client";
import { hasPermission, isTenantTier, loadSession, logout } from "../auth/session";
import { readStoredTheme, setTheme, subscribeTheme, type Theme } from "../lib/theme";
import { useSyncExternalStore } from "react";
import { Button } from "../components/primitives/Button";
import { ControlRail, type ControlSignal } from "../components/ControlRail";
import { Hint } from "../components/primitives/Hint";
import {
  HINTS,
  deploymentLifecycleLabel,
  identityProviderLabel,
  roleLevelLabel,
  sessionWindowLabel,
} from "../lib/labels";
import { WorkspaceHeader } from "../components/WorkspaceHeader";
import { WorkflowGuide, type WorkflowGuideStep } from "../components/WorkflowGuide";
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
  const tenant = isTenantTier(session);
  const canSeeRuntime = hasPermission(session, "operations:view");

  const runtime = useQuery({
    queryKey: ["operations-runtime"],
    queryFn: ({ signal }) => api.get<RuntimeSnapshot>("/operations/runtime", signal),
    staleTime: 15_000,
    enabled: canSeeRuntime,
  });

  const options: { value: Theme; label: string; Icon: typeof Sun }[] = [
    { value: "light", label: "Light", Icon: Sun },
    { value: "dark", label: "Dark", Icon: Moon },
  ];
  // The rail shows the word the picker uses, never the stored key.
  const themeLabel = options.find((option) => option.value === theme)?.label ?? theme;

  // The server decides who gets platform facts; the console only renders them,
  // and it never advertises a readout this session cannot open.
  const platform = session?.platform ?? null;

  const signals: ControlSignal[] = [
    { label: "Theme", value: themeLabel, detail: "The display mode for this browser." },
    {
      label: "Permissions",
      value: session?.permissions?.length ?? "—",
      detail: "Permissions on your current session.",
    },
    ...(platform
      ? [
          {
            label: "Platform facts",
            value: "Published",
            detail: "The installation, sign-in method and session policy you are using.",
            tone: "healthy" as const,
          },
        ]
      : []),
    ...(canSeeRuntime
      ? [
          {
            label: "Runtime",
            value: "Allowed",
            detail: "Live runtime detail from the operations service.",
            tone: "healthy" as const,
          },
        ]
      : []),
  ];

  const guideSteps: WorkflowGuideStep[] = [
    { label: "Set appearance", detail: "Pick the display mode for this browser." },
    {
      label: "Confirm session",
      detail: tenant
        ? "Check who you are signed in as and which customer you administer."
        : "Check who you are signed in as and whether you have entered a customer.",
    },
    ...(platform
      ? [
          {
            label: "Read the platform",
            detail:
              "Check which installation you are on, how you signed in, and how long it lasts.",
          },
        ]
      : []),
    ...(canSeeRuntime
      ? [
          {
            label: "Inspect runtime",
            detail: "Use live runtime detail only when your role allows it.",
          },
        ]
      : []),
  ];

  return (
    <div className="settings-page">
      <WorkspaceHeader
        eyebrow="Console preferences"
        title="Settings"
        description={
          platform
            ? "Set how the console looks on this device, check the session you are signed in with, and read what the running platform reports about itself."
            : "Set how the console looks on this device and check the session you are signed in with."
        }
        scope="Local browser preferences"
      />

      <ControlRail
        title="Session and local preference state"
        summary="Only the display mode is saved in this browser. Your identity, permissions and live status come from your sign-in."
        signals={signals}
      />

      <WorkflowGuide
        title="Separate console preference from access"
        description={
          platform
            ? "This page shows which settings live in your browser, which come from your sign-in, and which belong to the installation itself."
            : "This page shows which settings live in your browser and which come from your sign-in."
        }
        steps={guideSteps}
      />

      <div className="settings-grid">
        <section className="card settings-card" aria-labelledby="settings-appearance-heading">
          <h2 id="settings-appearance-heading" className="section-title">
            Appearance
          </h2>
          <p className="settings-hint">
            Light is the default. Dark is available for long sessions in low light. Your choice is
            saved in this browser only and does not change what you can access.
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
                      {roleLevelLabel(role)}
                    </span>
                  ))}
                </dd>
                <dt>Customer</dt>
                <dd>{session.customerId ?? "Platform"}</dd>
                <dt>Permissions</dt>
                <dd>{session.permissions?.length ?? 0} granted</dd>
                <dt>Session expires</dt>
                <dd>{new Date(session.expiresAt).toLocaleString()}</dd>
                <dt>
                  <Hint label="Re-authentication confirms it is you before a high-risk action. It stays valid for a short window.">
                    <span className="hint-term">Re-authentication</span>
                  </Hint>
                </dt>
                <dd>{session.stepUpActive ? "Verified" : "Not verified"}</dd>
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

        {platform ? (
          <section className="card settings-card" aria-labelledby="settings-platform-heading">
            <h2 id="settings-platform-heading" className="section-title">
              Platform
            </h2>
            <p className="settings-hint">
              <Hint label={HINTS.platformReadout}>
                <span className="hint-term">Read from the running platform</span>
              </Hint>{" "}
              rather than from this browser. Nothing here is editable: each value is set when the
              installation is built.
            </p>

            {platform.deploymentRecordAvailable ? (
              <dl className="settings-facts">
                <dt>
                  <Hint label={HINTS.deploymentRecord}>
                    <span className="hint-term">Installation</span>
                  </Hint>
                </dt>
                <dd>{platform.deploymentName ?? "Not named in the record"}</dd>
                <dt>Deployment reference</dt>
                <dd className="settings-mono">{platform.deploymentId}</dd>
                <dt>Region</dt>
                <dd>{platform.deploymentRegion}</dd>
                <dt>Serving status</dt>
                <dd>
                  {platform.deploymentLifecycle
                    ? deploymentLifecycleLabel(platform.deploymentLifecycle)
                    : "Not recorded"}
                </dd>
                <dt>Provisioned</dt>
                <dd>{new Date(platform.deploymentCreatedAt ?? 0).toLocaleDateString()}</dd>
              </dl>
            ) : (
              <>
                <p className="settings-hint" role="status">
                  The deployment record could not be read, so this installation has no name, status
                  or provisioned date to show. The reference below is what the running service
                  holds.
                </p>
                <dl className="settings-facts">
                  <dt>Deployment reference</dt>
                  <dd className="settings-mono">{platform.deploymentId}</dd>
                  <dt>Region</dt>
                  <dd>{platform.deploymentRegion}</dd>
                </dl>
              </>
            )}

            <dl className="settings-facts">
              <dt>
                <Hint label={HINTS.identityMode}>
                  <span className="hint-term">Sign-in method</span>
                </Hint>
              </dt>
              <dd>
                {identityProviderLabel(platform.identityProvider)}
                {platform.identityIssuer ? (
                  <span className="settings-secondary"> · {platform.identityIssuer}</span>
                ) : null}
              </dd>
              <dt>
                <Hint label={HINTS.sessionPolicy}>
                  <span className="hint-term">Idle window</span>
                </Hint>
              </dt>
              <dd>{sessionWindowLabel(platform.idleTtlSecs)} without activity</dd>
              <dt>Longest a sign-in lasts</dt>
              <dd>{sessionWindowLabel(platform.absoluteTtlSecs)} from sign-in</dd>
              <dt>Re-authentication lasts</dt>
              <dd>{sessionWindowLabel(platform.stepUpTtlSecs)}</dd>
            </dl>
          </section>
        ) : null}

        {canSeeRuntime ? (
          <section className="card settings-card" aria-labelledby="settings-runtime-heading">
            <h2 id="settings-runtime-heading" className="section-title">
              Runtime
            </h2>
            {runtime.data ? (
              <>
                <dl className="settings-facts">
                  <dt>Config version</dt>
                  <dd>{runtime.data.config.db_revision ?? "Unknown"}</dd>
                  <dt>Pending publication</dt>
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

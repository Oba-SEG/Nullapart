import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import "./WorkspaceHeader.css";

export type WorkspaceHeaderProps = {
  eyebrow: string;
  title: string;
  description: string;
  scope?: string;
  actions?: ReactNode;
  children?: ReactNode;
};

/**
 * The shared route header for the operator console. It describes the authority
 * boundary and gives the principal action a deliberate home instead of making
 * every administration screen look like a passive dashboard.
 */
export function WorkspaceHeader({
  eyebrow,
  title,
  description,
  scope = "Allowed for your role",
  actions,
  children,
}: WorkspaceHeaderProps) {
  return (
    <header className="workspace-header">
      <div className="workspace-header-copy">
        <p className="workspace-eyebrow">{eyebrow}</p>
        <h1 className="workspace-title">{title}</h1>
        <p className="workspace-description">{description}</p>
        {children ? <div className="workspace-header-detail">{children}</div> : null}
      </div>
      <div className="workspace-header-actions">
        <span className="workspace-scope">
          <ShieldCheck size={15} aria-hidden="true" />
          {scope}
        </span>
        {actions ? <div className="workspace-action-row">{actions}</div> : null}
      </div>
    </header>
  );
}

import { isSystemTier, sessionTier, type Session } from "../auth/session";

export type SessionPresentation = {
  asset:
    | "/brand/status/status-clean-256.png"
    | "/brand/status/status-processing.svg"
    | "/brand/status/status-review-256.png";
  boundaryLabel: string;
  scopeLabel: string;
  stateLabel: string;
  mode: "system" | "customer" | "customer-entry" | "unverified";
};

/**
 * Keep the shell's visual session claim conservative. Route loaders remain the
 * authorization boundary; this only prevents a pending or failed query from
 * looking like a verified operator session.
 */
export function getSessionPresentation(
  session: Session | null,
  queryFailed: boolean,
): SessionPresentation {
  if (session?.authenticated) {
    if (isSystemTier(session) && session.impersonation) {
      return {
        asset: "/brand/status/status-review-256.png",
        boundaryLabel: "Audited customer entry",
        scopeLabel: `Customer entry · ${session.impersonation.customerDisplayName}`,
        stateLabel: "Customer entry active",
        mode: "customer-entry",
      };
    }
    if (isSystemTier(session)) {
      return {
        asset: "/brand/status/status-clean-256.png",
        boundaryLabel: "System administrator",
        scopeLabel: "System-wide authority",
        stateLabel: "System control",
        mode: "system",
      };
    }
    // A resolved tenant tier administers one named customer; an unresolved or
    // Support session works the desk and is not shown a tenant claim it may
    // not have.
    if (sessionTier(session) === "customer" && session.customerId) {
      return {
        asset: "/brand/status/status-clean-256.png",
        boundaryLabel: "Customer administrator",
        scopeLabel: `Your customer · ${session.customerId}`,
        stateLabel: "Customer control",
        mode: "customer",
      };
    }
    return {
      asset: "/brand/status/status-clean-256.png",
      boundaryLabel: "Server-managed session",
      scopeLabel: session.customerId ? "Customer workspace" : "Platform workspace",
      stateLabel: "Operator session",
      mode: "customer",
    };
  }

  if (queryFailed) {
    return {
      asset: "/brand/status/status-review-256.png",
      boundaryLabel: "Session status unavailable",
      scopeLabel: "Authentication requires verification",
      stateLabel: "Attention required",
      mode: "unverified",
    };
  }

  return {
    asset: "/brand/status/status-processing.svg",
    boundaryLabel: "Verifying session",
    scopeLabel: "Authentication is being verified",
    stateLabel: "Verifying",
    mode: "unverified",
  };
}

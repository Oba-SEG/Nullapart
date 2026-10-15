import type { Session } from "../auth/session";

export type SessionPresentation = {
  asset:
    | "/brand/status/status-clean-256.png"
    | "/brand/status/status-processing.svg"
    | "/brand/status/status-review-256.png";
  boundaryLabel: string;
  scopeLabel: string;
  stateLabel: string;
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
    return {
      asset: "/brand/status/status-clean-256.png",
      boundaryLabel: "Server-managed session",
      scopeLabel: session.customerId ? "Customer scope" : "Platform scope",
      stateLabel: "Authenticated",
    };
  }

  if (queryFailed) {
    return {
      asset: "/brand/status/status-review-256.png",
      boundaryLabel: "Session status unavailable",
      scopeLabel: "Authentication requires verification",
      stateLabel: "Attention required",
    };
  }

  return {
    asset: "/brand/status/status-processing.svg",
    boundaryLabel: "Verifying session",
    scopeLabel: "Authentication is being verified",
    stateLabel: "Verifying",
  };
}

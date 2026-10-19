export type StatusTone = "clean" | "threat" | "review" | "processing" | "delivered" | "muted";

export function severityTone(severity: string): StatusTone {
  if (severity === "critical" || severity === "high") return "threat";
  if (severity === "medium") return "review";
  return "muted";
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  warning: "Warning",
  page: "Pages on-call",
  info: "Informational",
  unknown: "Not determined",
};

export function severityLabel(severity: string): string {
  return SEVERITY_LABELS[severity.toLowerCase()] ?? severity;
}

const DISPOSITION_LABELS: Record<string, string> = {
  allow: "Delivered",
  allowed: "Delivered",
  deliver: "Delivered",
  delivered: "Delivered",
  accept: "Delivered",
  accepted: "Delivered",
  quarantine: "Held for review",
  quarantined: "Held for review",
  hold: "Held for review",
  reject: "Rejected",
  rejected: "Rejected",
  block: "Rejected",
  defer: "Retrying delivery",
  deferred: "Retrying delivery",
};

export function dispositionLabel(disposition: string): string {
  return DISPOSITION_LABELS[disposition.toLowerCase()] ?? disposition;
}

const DIRECTION_LABELS: Record<string, string> = {
  inbound: "Inbound",
  outbound: "Outbound",
};

export function directionLabel(direction: string): string {
  return DIRECTION_LABELS[direction.toLowerCase()] ?? direction;
}

const NODE_STATUS_LABELS: Record<string, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  draining: "Draining",
  offline: "Offline",
};

export function nodeStatusLabel(status: string): string {
  return NODE_STATUS_LABELS[status.toLowerCase()] ?? status;
}

const SCANNER_STATUS_LABELS: Record<string, string> = {
  healthy: "Healthy",
  unavailable: "Unavailable",
  complete: "Completed",
  completed: "Completed",
  failed: "Failed",
};

export function scannerStatusLabel(status: string | undefined): string {
  if (status === undefined) return "Not reported";
  return SCANNER_STATUS_LABELS[status.toLowerCase()] ?? status;
}

/**
 * What a check concluded about this message, in the words a customer decides
 * with. The server's customer answer carries one of these keys and none of the
 * platform's own status token, which reads as `error` or `unknown` and describes
 * the machinery rather than the mail. An unanswered check matters: it is one
 * reason a hold is still open.
 */
const CHECK_OUTCOME_LABELS: Record<string, string> = {
  clear: "No issue found",
  threat_found: "Threat found",
  suspicious_found: "Something suspicious",
  no_answer: "No answer recorded",
  not_applicable: "Not applicable",
};

/**
 * An outcome the console cannot interpret is reported as no answer, never as a
 * clean result. That is the same fail-closed rule the scanner runs under, applied
 * to the wording: a tenant reading a held message must not be able to mistake an
 * unread check for a passed one.
 */
export function checkOutcomeLabel(outcome: string | undefined): string {
  if (outcome === undefined) return CHECK_OUTCOME_LABELS.no_answer;
  return CHECK_OUTCOME_LABELS[outcome.toLowerCase()] ?? CHECK_OUTCOME_LABELS.no_answer;
}

export function requirementLabel(requirement: string): string {
  return requirement.toLowerCase() === "optional" ? "Optional" : "Required";
}

const RESULT_LABELS: Record<string, string> = {
  success: "Success",
  ok: "Success",
  allowed: "Allowed",
  permitted: "Allowed",
  denied: "Denied",
  failed: "Failed",
  error: "Failed",
};

export function resultLabel(result: string): string {
  return RESULT_LABELS[result.toLowerCase()] ?? result;
}

const DELIVERY_STATUS_LABELS: Record<string, string> = {
  deferred: "Retrying",
  delivered: "Delivered",
  bounced: "Bounced",
  failed: "Failed",
  pending: "Pending",
  accepted: "Accepted",
  sent: "Sent",
};

export function deliveryStatusLabel(status: string): string {
  return DELIVERY_STATUS_LABELS[status.toLowerCase()] ?? status;
}

const REMEDIATION_LABELS: Record<string, string> = {
  none: "None",
  release: "Release",
  reject: "Reject",
  quarantine: "Quarantine",
  delete: "Delete",
  defer: "Retry",
};

export function remediationLabel(remediation: string): string {
  return REMEDIATION_LABELS[remediation.toLowerCase()] ?? remediation;
}

const CHECKPOINT_STATE_LABELS: Record<string, string> = {
  current: "Current",
  stale: "Stale",
  not_configured: "Not configured",
};

export function checkpointStatusLabel(state: string): string {
  return CHECKPOINT_STATE_LABELS[state.toLowerCase()] ?? state;
}

/**
 * Whether a held message has a reviewable quarantine case. Used to link trace
 * views to a held message so a flagged copy reaches its release decision in one
 * step. The check runs on the wire value, so callers keep passing the raw
 * disposition.
 */
export function isQuarantineLinked(disposition: string): boolean {
  const value = disposition.toLowerCase();
  return value.includes("quarantine") || value.includes("release") || value.includes("hold");
}

/**
 * Operator-facing labels for the enumerations the API returns.
 *
 * Rules from docs/engineering/UX-TERMINOLOGY.md: an enum never renders as its
 * raw wire value in a primary position, "tenant" is never shown to an operator,
 * and a mechanism is never named where an outcome would do. Raw identifiers
 * still appear, but only as secondary evidence next to the label, because audit
 * records and support threads name the key.
 */

import {
  decodeOverrideValue,
  type AuthResult,
  type ConditionScope,
  type Disposition,
  type FindingCategory,
  type FindingSeverity,
  type ManagementLevel,
  type NotifyTarget,
  type OverrideScope,
  type ScannerType,
} from "../api/policies";
import { humanizeToken } from "./text";

export const OVERRIDE_SCOPE_LABELS: Record<OverrideScope, string> = {
  system: "Platform-wide",
  deployment: "Deployment-wide",
  tenant: "This customer",
};

/** Scope label for an override row, which carries the customer it applies to. */
export function overrideScopeLabel(scope: OverrideScope, scopeId?: string): string {
  if (scope === "tenant") {
    return scopeId ? `This customer · ${scopeId}` : OVERRIDE_SCOPE_LABELS.tenant;
  }
  return OVERRIDE_SCOPE_LABELS[scope];
}

export const MANAGEMENT_LEVEL_LABELS: Record<ManagementLevel, string> = {
  customer: "Customer",
  support: "Support",
  system: "System",
};

/** Phrases the level inside a requirement sentence, lower-case and hyphenated. */
export function levelRequirement(level: ManagementLevel): string {
  return `${level} level`;
}

/**
 * What a rule matches on. "transaction" and "tenant" are the wire names; an
 * operator reads the scope of the decision instead.
 */
export const CONDITION_SCOPE_LABELS: Record<ConditionScope, string> = {
  transaction: "One message",
  tenant: "Everything for this customer",
  recipient: "One recipient",
};

/**
 * Actions in the rule builder. The message views in lib/status fold quarantine
 * and hold together because a reader there only cares that mail stopped; a
 * person writing a rule must not, so this map keeps them distinct.
 */
export const POLICY_DISPOSITION_LABELS: Record<Disposition, string> = {
  allow: "Deliver it",
  quarantine: "Hold it for review",
  reject: "Reject it",
  hold: "Hold it without a review queue",
  defer: "Defer it and retry delivery later",
};

/**
 * Rule-builder vocabularies. The wire value is what the engine stores; these
 * are the words a person picks the rule with.
 */
export const FINDING_SEVERITY_LABELS: Record<FindingSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

export const FINDING_CATEGORY_LABELS: Record<FindingCategory, string> = {
  malware: "Malware",
  phishing: "Phishing",
  spam: "Spam",
  spoofing: "Spoofing",
  business_email_compromise: "Business email compromise",
  credential_harvest: "Credential harvesting",
  malicious_url: "Malicious link",
  malicious_attachment: "Malicious attachment",
  suspicious_content: "Suspicious content",
  policy_violation: "Policy violation",
  auth_failure: "Authentication failure",
  reputation: "Sender reputation",
  unknown: "Unclassified",
};

export const SCANNER_LABELS: Record<ScannerType, string> = {
  clamav: "ClamAV antivirus",
  rspamd: "Rspamd spam filter",
  urlanalysis: "Link analysis",
  attachment: "Attachment analysis",
  dkim: "DKIM signing check",
  spf: "SPF sender check",
  dmarc: "DMARC policy check",
  arc: "ARC forwarding check",
  inlineml: "Inline machine learning",
  deepai: "Deep AI analysis",
  custom: "Custom scanner",
};

/** The SPF/DKIM/DMARC verdicts, in the words the RFC results actually mean. */
export const AUTH_RESULT_LABELS: Record<AuthResult, string> = {
  pass: "Passed",
  fail: "Failed",
  softfail: "Soft failed",
  neutral: "Neutral",
  none: "Not checked",
  permerror: "Permanent error",
  temperror: "Temporary error",
};

export const NOTIFY_TARGET_LABELS: Record<NotifyTarget, string> = {
  admin: "Mail admins",
  sender: "The sender",
  recipient: "The recipient",
};

/**
 * Outbound guardrail verdicts. The event feed and the campaign summary use
 * different wordings for the same decision, so both forms map to one label; an
 * unknown value degrades to its own words rather than an empty pill.
 */
const OUTBOUND_OUTCOME_LABELS: Record<string, string> = {
  allow: "Delivered",
  allowed: "Delivered",
  warn: "Warned",
  warned: "Warned",
  throttle: "Delivery slowed",
  throttled: "Delivery slowed",
  defer: "Retrying delivery",
  deferred: "Retrying delivery",
  hold: "Held",
  held: "Held",
  block_sender: "Sender blocked",
  blocked: "Sender blocked",
  suspend_outbound: "Outbound suspended",
};

export function outboundOutcomeLabel(outcome: string): string {
  return OUTBOUND_OUTCOME_LABELS[outcome] ?? tokenLabel(outcome);
}

/**
 * Outbound security event types. The store keeps the enum's wire name with
 * hyphens turned into underscores, so both spellings are accepted.
 */
const OUTBOUND_EVENT_LABELS: Record<string, string> = {
  unauthorized_bulk: "Unapproved bulk sending",
  compromised_sender: "Compromised sender",
  source_spoofing: "Spoofed sending source",
  malware_from_bulk_sender: "Malware from a bulk sender",
  campaign_outbreak: "Campaign outbreak",
  delivery_failure_spike: "Delivery failure spike",
};

export function outboundEventLabel(eventType: string): string {
  const key = eventType.replaceAll("-", "_");
  return OUTBOUND_EVENT_LABELS[key] ?? tokenLabel(key);
}

/**
 * Which fingerprinting rule produced a campaign fingerprint. There is exactly
 * one rule today; the version is still shown because two fingerprints computed
 * by different rules are not comparable.
 */
export function fingerprintVersionLabel(algorithm: string): string {
  return algorithm === "nullapart_v1"
    ? "Campaign rule v1"
    : `Campaign rule ${tokenLabel(algorithm)}`;
}

/**
 * Customer lifecycle. The wire values are state names; an operator reads what
 * each one does to mail.
 */
export const LIFECYCLE_LABELS: Record<"active" | "grace" | "suspended" | "terminated", string> = {
  active: "Active",
  grace: "In grace period",
  suspended: "Suspended",
  terminated: "Terminated",
};

/**
 * Lifecycle for a value the caller has not narrowed to the customer enum, such
 * as an administrator row. Anything unrecognised reads as words rather than a
 * wire token.
 */
export function lifecycleLabel(value: string): string {
  return LIFECYCLE_LABELS[value as keyof typeof LIFECYCLE_LABELS] ?? tokenLabel(value);
}

export const VERIFICATION_STATUS_LABELS: Record<"pending" | "verified" | "failed", string> = {
  pending: "Waiting for verification",
  verified: "Verified",
  failed: "Verification failed",
};

/** How a domain proves ownership. Falls back to the de-tokenised wire name. */
export function verificationMethodLabel(method: string): string {
  const names: Record<string, string> = { dns_txt: "DNS text record" };
  return names[method] ?? tokenLabel(method);
}

export const OVERRIDE_VALUE_KIND_LABELS = {
  inherit: "Follow the higher setting",
  enabled: "On",
  disabled: "Off",
  typed: "A specific value",
} as const;

/** Turns a stored wire value into the words an operator reads. */
export function describeOverrideValue(value: string): string {
  const decoded = decodeOverrideValue(value);
  if (decoded.kind === "typed") return decoded.typed || "no value set";
  return OVERRIDE_VALUE_KIND_LABELS[decoded.kind];
}

/**
 * Last resort for a wire token: `humanizeToken` turns it into sentence-case
 * words. Prefer a named map when the word alone does not tell an operator what
 * happens ("defer" is a retry decision, not a status).
 */
export function tokenLabel(value: string): string {
  return humanizeToken(value);
}

/** Where a sending source came from, as the classification table shows it. */
const SOURCE_CLASSIFICATION_LABELS = {
  authorized: "Authorized",
  expected_incomplete: "Partially set up",
  unknown: "Not classified yet",
  suspicious: "Suspicious",
  malicious: "Malicious",
  third_party: "Another party sends for you",
} as const;

/** Readiness of an operation on this page, not a generic status word. */
const OPERATION_READINESS_LABELS = {
  ready: "Ready",
  partial: "Partly working",
  defined: "Rules defined",
  not_ready: "Not ready",
  blocked: "Blocked",
  tested: "Tested",
  alerting_active: "Alerting is live",
} as const;

/** Where an integration delivers its result. */
const DESTINATION_LABELS = {
  clickup: "ClickUp",
  n8n: "n8n workflow",
  customer_notification: "Customer notification",
  reporting: "Reporting",
} as const;

/** Internal versus send-only sending, the two domain types an operator picks. */
const DOMAIN_TYPE_LABELS = {
  internal: "Internal",
  send_only: "Send only",
} as const;

/** Domain ownership verification; the wire states are three lowercase words. */
const VERIFICATION_STATE_LABELS = {
  pending: "Waiting for verification",
  verified: "Verified",
  failed: "Verification failed",
} as const;

/** Reads a named map, falling back to readable words for an unknown state. */
function fromLabels(labels: Record<string, string>, value: string): string {
  return labels[value] ?? tokenLabel(value);
}

export function sourceClassificationLabel(value: string): string {
  return fromLabels(SOURCE_CLASSIFICATION_LABELS, value);
}

export function operationReadinessLabel(value: string): string {
  return fromLabels(OPERATION_READINESS_LABELS, value);
}

/** Where an alert category is delivered. */
export function destinationLabel(value: string): string {
  return fromLabels(DESTINATION_LABELS, value);
}

export function domainTypeLabel(value: string): string {
  return fromLabels(DOMAIN_TYPE_LABELS, value);
}

export function verificationStatusLabel(value: string): string {
  return fromLabels(VERIFICATION_STATE_LABELS, value);
}

/**
 * Audit actions shown in a change history. The wire name is written by the
 * server, so an unmapped action falls back to readable words rather than
 * hiding the entry.
 */
const AUDIT_ACTION_LABELS: Record<string, string> = {
  outbound_bulk_sender_upserted: "Approved sender changed",
};

export function auditActionLabel(action: string): string {
  return fromLabels(AUDIT_ACTION_LABELS, action);
}

/**
 * Connector vocabularies. A connector card shows three of these at once (what
 * it does, whether it is usable, whether its credentials work), so each gets
 * its own map rather than one generic status word list.
 */
const CONNECTOR_CAPABILITY_LABELS = {
  directory_sync: "Directory sync",
  mailbox_search: "Mailbox search",
  retro_remediation: "Retro remediation",
} as const;

const CONNECTOR_STATUS_LABELS = {
  setup_required: "Setup required",
  active: "Active",
  degraded: "Degraded",
  disabled: "Disabled",
  revoked: "Revoked",
} as const;

const AUTH_STATE_LABELS = {
  not_configured: "No credentials stored",
  healthy: "Credentials valid",
  expiring: "Credentials expiring",
  expired: "Credentials expired",
  revoked: "Credentials revoked",
  provider_error: "Provider rejected the credentials",
} as const;

/**
 * Execution state of a mailbox search or remediation. The control plane only
 * records intent; the provider confirms the result, so "pending" is the normal
 * state rather than an error and the label says who still has work to do.
 */
const EXECUTION_STATE_LABELS = {
  pending: "Recorded, not yet run",
  queued: "Queued with the provider",
  running: "Running",
  in_progress: "Running",
  succeeded: "Succeeded",
  completed: "Completed",
  failed: "Failed",
  not_checked: "Not checked yet",
} as const;

/** Why an operator is searching a customer's mailbox. */
const SEARCH_PURPOSE_LABELS = {
  post_delivery_threat: "Post-delivery threat",
  customer_reported_phishing: "Customer-reported phishing",
  false_negative_review: "Missed-threat review",
  manual_security_case: "Manual security case",
} as const;

/** What a remediation action does to the message in the mailbox. */
const REMEDIATION_ACTION_LABELS = {
  move_to_quarantine: "Move to quarantine",
  move_to_junk: "Move to junk mail",
  delete: "Delete the message",
  manual_review: "Leave it for review",
} as const;

/** Model approval, shared by the inline model registry and Deep AI releases. */
const APPROVAL_STATE_LABELS = {
  pending: "Awaiting approval",
  approved: "Approved",
  rejected: "Rejected",
} as const;

/** Verdict recorded against a shadow evaluation. */
const SHADOW_RESULT_LABELS = {
  candidate_better: "Candidate performed better",
  candidate_worse: "Candidate performed worse",
  inconclusive: "Inconclusive",
  rollback_rehearsed: "Rollback rehearsed",
} as const;

/** What a Deep AI grant lets a model read. */
const GRANT_RESOURCE_LABELS = {
  quarantine_case: "One quarantine case",
  blocked_message: "One blocked message",
  reported_phishing: "One reported message",
  confirmed_threat: "One confirmed threat",
} as const;

/** SMTP node state, which the snapshot reports as recorded rows only. */
const COMMISSIONING_LABELS = {
  recorded: "Nodes recorded",
  not_configured: "Not configured here",
} as const;

export function connectorCapabilityLabel(value: string): string {
  return fromLabels(CONNECTOR_CAPABILITY_LABELS, value);
}

export function connectorStatusLabel(value: string): string {
  return fromLabels(CONNECTOR_STATUS_LABELS, value);
}

export function authStateLabel(value: string): string {
  return fromLabels(AUTH_STATE_LABELS, value);
}

export function executionStateLabel(value: string): string {
  return fromLabels(EXECUTION_STATE_LABELS, value);
}

export function searchPurposeLabel(value: string): string {
  return fromLabels(SEARCH_PURPOSE_LABELS, value);
}

export function remediationActionLabel(value: string): string {
  return fromLabels(REMEDIATION_ACTION_LABELS, value);
}

export function approvalStateLabel(value: string): string {
  return fromLabels(APPROVAL_STATE_LABELS, value);
}

export function shadowResultLabel(value: string): string {
  return fromLabels(SHADOW_RESULT_LABELS, value);
}

export function grantResourceLabel(value: string): string {
  return fromLabels(GRANT_RESOURCE_LABELS, value);
}

export function commissioningLabel(value: string): string {
  return fromLabels(COMMISSIONING_LABELS, value);
}

/**
 * Deep AI release and evidence states. Skills, model releases and analysis
 * results each carry one of these, so the words are shared across all three.
 */
const DEEP_AI_STATE_LABELS = {
  draft: "Draft",
  released: "Released",
  rolled_back: "Rolled back",
  deprecated: "Retired",
  valid: "Valid",
  invalid: "Invalid",
  expired: "Expired",
  error: "Errored",
  // Outcomes of the structured-output contract. Each one names what failed,
  // because an operator has to decide whether the finding or the run is wrong.
  schema_invalid: "Output did not match the contract",
  hallucinated_evidence: "Cited evidence does not exist",
  tool_denied: "Tool access was refused",
  model_unavailable: "Model could not run",
} as const;

/**
 * `attack_type` on a Deep AI finding. It is not the scanner category: `bec` and
 * `impersonation` are this contract's own vocabulary, so it keeps its own map.
 */
const ATTACK_TYPE_LABELS = {
  none: "No attack type",
  phishing: "Phishing",
  bec: "Business email compromise",
  impersonation: "Impersonation",
  malware: "Malware",
  spam: "Junk mail",
  scam: "Scam",
  unknown: "Unclassified",
} as const;

/**
 * What a Deep AI finding recommends doing with the message. Kept apart from the
 * policy dispositions because these are a suggestion to a person, not an engine
 * action that executes.
 */
const RECOMMENDED_ACTION_LABELS = {
  deliver: "Deliver it",
  hold: "Hold it without a review queue",
  quarantine: "Hold it for review",
  block: "Block it",
  escalate: "Send it to a security reviewer",
  release: "Release it from hold",
  unknown: "No recommendation",
} as const;

/**
 * Who asserted a Deep AI finding. The server derives this from the caller, so
 * the two values are the only origins a row can legitimately carry.
 */
const RESULT_ORIGIN_LABELS = {
  model_runtime: "Produced by the analysis runtime",
  administrator: "Entered by an administrator",
} as const;

/** The verdict a Deep AI analysis reached about the message. */
const ANALYSIS_VERDICT_LABELS = {
  clean: "Clean",
  suspicious: "Suspicious",
  malicious: "Malicious",
  unknown: "Could not classify",
  error: "Analysis failed",
} as const;

export function deepAiStateLabel(value: string): string {
  return fromLabels(DEEP_AI_STATE_LABELS, value);
}

export function analysisVerdictLabel(value: string): string {
  return fromLabels(ANALYSIS_VERDICT_LABELS, value);
}

export function attackTypeLabel(value: string): string {
  return fromLabels(ATTACK_TYPE_LABELS, value);
}

export function recommendedActionLabel(value: string): string {
  return fromLabels(RECOMMENDED_ACTION_LABELS, value);
}

/**
 * Origin of a finding. A missing origin means the row predates origin tracking;
 * it is never guessed at, and never rendered as a model-produced result.
 */
export function resultOriginLabel(value: string | null): string {
  if (value === null) return "Origin not recorded";
  return fromLabels(RESULT_ORIGIN_LABELS, value);
}

/** A threat category named by a scanner or a model, in operator words. */
export function findingCategoryLabel(value: string): string {
  return fromLabels(FINDING_CATEGORY_LABELS, value);
}

/**
 * Verdicts of the DNS and logo checks on the domain page. They share four
 * words with other surfaces but nothing else, so they keep their own map.
 */
const CHECK_VERDICT_LABELS = {
  ready: "Ready",
  not_ready: "Not ready",
  valid: "Valid",
  invalid: "Invalid",
  missing: "Missing",
  not_checked: "Not checked yet",
  not_required: "Not required",
  enforced: "Enforced",
  not_enforced: "Not enforced",
  published: "Published",
  unknown: "Unknown",
} as const;

/** The enforcement a published DMARC record asks receivers to apply. */
const DMARC_POLICY_LABELS = {
  reject: "Reject",
  quarantine: "Quarantine",
  none: "No policy",
  missing: "No record",
} as const;

/** State of a runtime node as the snapshot reports it. */
/**
 * Runtime node lifecycle. `nodes.status` records `active`, `draining` or
 * `offline`; the health-check words cover what the operations snapshot
 * reports about a node that is up but not taking work.
 */
const NODE_STATE_LABELS = {
  active: "Active",
  draining: "Draining: no new work",
  offline: "Offline",
  healthy: "Healthy",
  starting: "Starting",
  unhealthy: "Unhealthy",
} as const;

/**
 * `nodes.node_type` is a checked column: mail, control, scanner, worker.
 * `mx` appears in locally seeded rows.
 */
const NODE_TYPE_LABELS = {
  mail: "Mail node",
  control: "Control plane",
  scanner: "Scanner",
  worker: "Worker",
  mx: "MX node",
} as const;

/**
 * `nodes.role` is free text, so this covers the roles this deployment actually
 * records. Anything else falls back to sentence case rather than a guess.
 */
const NODE_ROLE_LABELS = {
  mx: "Receives inbound mail",
  mail: "Sends and receives mail",
  inbound: "Receives inbound mail",
  outbound: "Sends outbound mail",
  scanner: "Scores mail for threats",
  control: "Serves the console and APIs",
  worker: "Runs queued jobs",
  "mail-core": "Runs the mail core",
} as const;

/** Role level, including the placeholder for a role that is not listed. */
const ROLE_LEVEL_LABELS: Record<string, string> = {
  ...MANAGEMENT_LEVEL_LABELS,
  custom: "Custom",
};

export function checkVerdictLabel(value: string): string {
  return fromLabels(CHECK_VERDICT_LABELS, value);
}

export function dmarcPolicyLabel(value: string): string {
  return fromLabels(DMARC_POLICY_LABELS, value);
}

/**
 * State of a runtime node. Named apart from `lib/status.nodeStatusLabel`,
 * which reads scanner-node health rather than this lifecycle.
 */
export function runtimeNodeLabel(value: string): string {
  return fromLabels(NODE_STATE_LABELS, value);
}

export function nodeTypeLabel(value: string): string {
  return fromLabels(NODE_TYPE_LABELS, value);
}

export function nodeRoleLabel(value: string): string {
  return fromLabels(NODE_ROLE_LABELS, value);
}

export function roleLevelLabel(value: string): string {
  return fromLabels(ROLE_LEVEL_LABELS, value);
}

/**
 * Tooltips. One rule each, stated as what happens rather than how it is
 * implemented; the primitives/Hint component carries them to assistive tech.
 */
export const HINTS = {
  securityFloor:
    "A security floor stays in force while this setting changes. Nothing here can switch it off.",
  emergencyStop:
    "An emergency stop is a switch the platform can pull to halt this feature everywhere. It stays listed so you can see it.",
  internalIdentifier:
    "The internal name for this setting. Audit records and support references use it, so it stays visible.",
  callerTier:
    "The highest management level your current roles reach. It decides which settings you can change on this page.",
  winningScope:
    "Where the active value came from. A setting at this level is replaced by anything set closer to the customer.",
  inherit:
    "Stop overriding here and use the value from the next level up. Nothing is deleted; this level stops deciding.",
  readOnly:
    "Your roles cannot change this setting at any level it allows. Ask a system administrator if it needs to move.",
  stepUp: "Changing this signs you in again first, and every change is recorded with your reason.",
  lifecycle:
    "Active customers send and receive normally. Grace limits mail. Suspended stops new mail. Terminated ends the account.",
  domainType:
    "Internal can send and receive. Send only can send but never receives, and mail addressed to it is refused at the door.",
  providerState:
    "This console records what should happen. The provider confirms what actually did, and the result appears here once it reports back.",
  modelApproval:
    "An approved model is allowed to run. Only one approved model is active at a time, and it is the one that scores live mail.",
  shadowResult:
    "How the candidate scored against the active model on a fixed evaluation set. Nothing here changes what runs on live mail.",
  resultOrigin:
    "The server decides this from who is calling. A finding entered here stays labelled as entered by an administrator, so it can never be mistaken for model output.",
  citedEvidence:
    "A finding has to cite the authorization it read under. These references are taken from the grant you picked, so the finding traces back to one permitted view of one message.",
  modelReleaseChoice:
    "Only a release this deployment approved can be cited. A finding cannot claim a model that does not exist or one that was rejected.",
  grantRevocation:
    "Ends this access now instead of waiting for it to expire. No new finding can cite the grant afterwards, and your name and reason stay on the record. Changing this signs you in again first.",
} as const;

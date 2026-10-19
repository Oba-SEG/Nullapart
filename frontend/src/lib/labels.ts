/**
 * Operator-facing labels for the enumerations the API returns.
 *
 * Rules from docs/engineering/UX-TERMINOLOGY.md: an enum never renders as its
 * raw wire value in a primary position, "tenant" is never shown to an operator,
 * and a mechanism is never named where an outcome would do. A machine key (a
 * reason code, an engine name, a runbook path) never reaches a customer screen
 * at all: the customer read is built from outcome words, and the key stays
 * where the platform can use it, in the audit record and the API.
 */

import {
  decodeOverrideValue,
  type AuthResult,
  type ConditionFieldName,
  type ConditionScope,
  type Disposition,
  type EnforcementMode,
  type FindingCategory,
  type FindingSeverity,
  type ManagementLevel,
  type NotifyTarget,
  type OverrideScope,
  type RuleCondition,
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
 * A customer session does not administer the provider's ladder, so the two
 * levels above customer are one bucket in a tenant console: published by their
 * provider. Naming them separately would teach a customer a hierarchy they
 * cannot act inside.
 */
export type TenantLevelBucket = "yours" | "provider";

export function tenantLevelBucket(level: ManagementLevel): TenantLevelBucket {
  return level === "customer" ? "yours" : "provider";
}

export const TENANT_LEVEL_LABELS: Record<TenantLevelBucket, string> = {
  yours: "Yours to change",
  provider: "Needs your provider",
};

/** The level word for a role that sits above everything a tenant can grant. */
export const PROVIDER_ROLE_LEVEL_LABEL = "Provider";

/** The level word for the only role level a tenant console lists. */
export const TENANT_ROLE_LEVEL_LABEL = "Your organisation";

/** Builtin roles that sit above anything a tenant can hold or grant. */
const PLATFORM_ROLE_KEYS: string[] = ["system_admin", "support"];

/**
 * The role chip beside an audit actor. A tenant console does not name the
 * provider's ladder, so a builtin platform role reads as the one bucket above
 * the tenant's own. Other keys keep their humanised name: an audit row carries
 * role keys, not levels, so a custom platform role can only be named, not
 * classified, without reading the role directory a tenant console does not ask
 * for.
 */
export function actorRoleLabels(roleKeys: string[], tenant: boolean): string[] {
  if (!tenant) return roleKeys.map(roleLevelLabel);
  return Array.from(
    new Set(
      roleKeys.map((key) =>
        PLATFORM_ROLE_KEYS.includes(key) ? PROVIDER_ROLE_LEVEL_LABEL : roleLevelLabel(key),
      ),
    ),
  );
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

/** The condition fieldsets in the rule builder, named the way the form names them. */
export const CONDITION_FIELD_LABELS: Record<ConditionFieldName, string> = {
  sender: "Sender",
  recipient: "Recipient",
  auth: "Authentication",
  content: "Content",
  finding: "Scanner findings",
};

/**
 * What a stage does with this family's published revisions. The sentence an
 * operator reads next to it comes from the server, so the claim and the check
 * are the same code.
 */
export const ENFORCEMENT_MODE_LABELS: Record<EnforcementMode, string> = {
  ml_thresholds: "Sets classifier score bands",
  outbound_thresholds: "Sets outbound sending limits",
  not_enforced: "Stored, not enforced",
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

/**
 * Which check produced a finding, in product-capability words. The wire keys
 * name the engine behind the check; the console never repeats them, because a
 * customer chooses evidence by what was looked at, not by which daemon looked.
 */
export const SCANNER_LABELS: Record<ScannerType, string> = {
  clamav: "Malware analysis",
  rspamd: "Spam analysis",
  urlanalysis: "Link analysis",
  attachment: "Attachment analysis",
  dkim: "Message signature check",
  spf: "Sender authorisation check",
  dmarc: "Domain alignment check",
  arc: "Forwarding chain check",
  inlineml: "Automated threat analysis",
  deepai: "Advanced threat analysis",
  custom: "Custom check",
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
  release: "Message released",
};

export function auditActionLabel(action: string): string {
  return fromLabels(AUDIT_ACTION_LABELS, action);
}

/**
 * The policy families by the name the policy console gives them. A change
 * history row carries the storage key, not the name, so a customer reading
 * their own history needs the same words the policy list uses. The catalog is
 * versioned server-side; an unmapped key still reads as a name, never as a key.
 */
const POLICY_FAMILY_LABELS: Record<string, string> = {
  attachments: "Attachment handling",
  authentication: "Sender authentication",
  bulk_sending: "Bulk sending limits",
  connection_security: "Connection security",
  connectors_remediation: "Connector remediation",
  content_security: "Content filtering",
  dmarc_bimi: "DMARC and BIMI",
  geolocation: "Geolocation rules",
  greylisting: "Greylisting",
  impersonation: "Impersonation protection",
  inbound_routing: "Inbound routing",
  malware: "Malware scanning",
  ml_threat_classification: "Automatic threat review",
  notifications: "Notifications",
  outbound_abuse: "Outbound abuse detection",
  outbound_routing: "Outbound routing",
  outbound_senders: "Outbound sender approvals",
  quarantine: "Quarantine handling",
  recipient_controls: "Recipient controls",
  retention: "Retention windows",
  sender_reputation: "Sender reputation",
  spam_filtering: "Spam filtering",
  transport_security: "TLS transport security",
  url_security: "URL protection",
  vip_protection: "VIP protection",
};

export function policyFamilyLabel(familyKey: string): string {
  return fromLabels(POLICY_FAMILY_LABELS, familyKey);
}

/**
 * The family name for the seat reading it. A platform operator quotes the
 * catalog name their runbooks use; a customer reads what the family does for
 * their mail, so a catalog name that describes the engine rather than the
 * outcome is renamed for them and nowhere else.
 */
export function familyDisplayName(familyKey: string, catalogName: string, tenant: boolean): string {
  return tenant ? policyFamilyLabel(familyKey) : catalogName;
}

/**
 * What a family governs, for the seat reading the list. The catalog descriptions
 * are written for the platform's own runbook, and two of them describe the
 * machinery rather than the mail: a customer whose family is named "Automatic
 * threat review" above the line must not read "machine-learning classification"
 * in it. Every other catalog description already says what the family does and
 * passes through untouched.
 */
const TENANT_FAMILY_DESCRIPTIONS: Record<string, string> = {
  connectors_remediation: "How connected mailboxes are checked and repaired",
  ml_threat_classification: "Automatic threat review evidence",
};

export function familyDescription(
  familyKey: string,
  catalogDescription: string,
  tenant: boolean,
): string {
  if (!tenant) return catalogDescription;
  return TENANT_FAMILY_DESCRIPTIONS[familyKey] ?? catalogDescription;
}

/**
 * A stored reference a customer can use. A primary key is not one: it names a
 * row in the platform's database rather than anything in their mail, and every
 * row that carries one already says what happened beside it.
 */
const OPAQUE_IDENTIFIER =
  /^(?:\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?|urn:uuid:[0-9a-f-]{36}|[0-9a-f]{24,})$/i;

/**
 * The references that name the customer's own mail, so the key is theirs even
 * when it is shaped like a primary one. A quarantine case is read and routed by
 * its message id, and a transaction id is that same message seen from the trace
 * page; both are what a customer quotes in a support ticket. Every other type is
 * a row in the platform's database.
 */
const CUSTOMER_MAIL_HANDLES: string[] = ["transaction", "quarantine", "quarantine_case", "message"];

/**
 * A history row's reference in a customer seat's own words. The ledger stores a
 * machine reference for the thing a write touched: a family key, a composite
 * `address:source-kind:source-id`, the platform's own readout name. A customer
 * needs to know which policy or which sender changed, not how the row is keyed.
 * A reference they can act on (a sender address, their own customer id) passes
 * through untouched, and one that names platform machinery or a database row
 * becomes nothing rather than a leak.
 */
export function tenantResourceReference(
  resourceType: string,
  resourceId: string | null,
): string | null {
  if (resourceId === null || resourceId.trim().length === 0) return null;
  switch (resourceType) {
    case "policy_family":
      return resourceId === "families" ? "All your mail policies" : policyFamilyLabel(resourceId);
    case "approved_bulk_sender":
      return resourceId.split(":")[0] ?? resourceId;
    case "audit":
      // The ledger checkpoint is the installation's own seal. A tenant row about
      // it says which record was read, and they have the row either way.
      return resourceId === "checkpoint-status"
        ? null
        : referenceForTenant(resourceType, resourceId);
    case "session":
      // A session row is the platform's own bookkeeping: the login event says
      // who and when, the primary key says nothing a customer can act on.
      return null;
    default:
      return referenceForTenant(resourceType, resourceId);
  }
}

/**
 * A stored reference a customer can actually use. An opaque primary key is not
 * one: it names a row in the platform's database rather than anything in their
 * mail, so the row keeps its outcome and loses the key. A composite key is read
 * segment by segment, because `domain-uuid:source` is still keyed by a database
 * row even though neither half matches the shape on its own.
 */
function referenceForTenant(resourceType: string, resourceId: string): string | null {
  if (CUSTOMER_MAIL_HANDLES.includes(resourceType)) return resourceId;
  const opaque = resourceId.split(":").some((segment) => OPAQUE_IDENTIFIER.test(segment.trim()));
  return opaque ? null : resourceId;
}

/**
 * The name a customer reads for one field of an audit event's details. What the
 * ledger stores is the column the writer used; what the customer needs is the
 * fact in it. A key this map has never seen still reads as a label, never as a
 * snake_case column.
 */
const AUDIT_DETAIL_KEY_LABELS: Record<string, string> = {
  changed: "Changed",
  classification: "Source class",
  created: "Created",
  cidr_count: "Address ranges",
  domain: "Domain",
  domain_type: "Domain kind",
  expires_at: "Expires",
  family_key: "Mail policy",
  format: "File format",
  lifecycle: "Status",
  login: "Administrator",
  reason: "Reason",
  reason_code: "Recorded reason",
  release_reason: "Release note",
  revision: "Revision",
  revision_number: "Revision",
  role_key: "Role",
  role_level: "Role level",
  row_count: "Records",
  rules_count: "Rules",
  scope_level: "Applies to",
  source_key: "Sending range",
  status: "Result",
  truncated: "Cut short",
};

export function auditDetailFieldLabel(key: string): string {
  return fromLabels(AUDIT_DETAIL_KEY_LABELS, key);
}

/**
 * A detail field's value in the words the rest of the customer's console
 * already uses for the same thing. The audit row carries the key the writer
 * stored; the policy list, the role directory and the quarantine table all show
 * a name, so the ledger cannot be the one screen that shows the key.
 */
export function auditDetailValueLabel(key: string, value: string): string {
  switch (key) {
    case "family_key":
      return policyFamilyLabel(value);
    case "role_key":
    case "role_level":
      return roleLevelLabel(value);
    case "scope_level":
      return value === "customer" || value === "tenant"
        ? TENANT_ROLE_LEVEL_LABEL
        : PROVIDER_ROLE_LEVEL_LABEL;
    case "classification":
      return sourceClassificationLabel(value);
    case "domain_type":
      return domainTypeLabel(value);
    case "lifecycle":
      return lifecycleLabel(value);
    case "reason_code":
      return reasonCodeLabel(value);
    case "changed":
    case "created":
    case "truncated":
      if (value === "true") return "Yes";
      if (value === "false") return "No";
      return value;
    default:
      return value;
  }
}

/**
 * What each permission key lets someone do, in the words the person assigning
 * it cares about. A customer console shows these; a platform console shows the
 * key, because the key is what the API and the runbooks quote. Grants this map
 * has never seen still read as a capability, never as a colon-separated key.
 */
const PERMISSION_CAPABILITY_LABELS: Record<string, string> = {
  "admin:customers:manage": "Manage customer records",
  "admin:customers:view": "View customer records",
  "admin:domains:manage": "Manage your sending domains",
  "admin:impersonate": "Provider access only",
  "admin:users:manage": "Manage your administrators",
  "audit:cross_customer": "Read activity outside your organisation",
  "audit:export": "Export the activity log",
  "audit:view": "Read the activity log",
  "connectors:manage": "Change integrations",
  "connectors:view": "See integrations",
  "deep-ai:manage": "Change advanced analysis",
  "deep-ai:view": "See advanced analysis",
  "domain-security:manage": "Change domain security settings",
  "domain-security:view": "View domain security",
  "models:manage": "Change platform models",
  "models:view": "See platform models",
  "notifications:manage": "Change delivery alerts",
  "notifications:view": "View delivery alerts",
  "operations:manage": "Change platform operations",
  "operations:view": "See platform operations",
  "outbound-intelligence:manage": "Change outbound sender approvals",
  "outbound-intelligence:view": "View outbound sending activity",
  "policies:manage": "Change your mail policies",
  "policies:view": "View your mail policies",
  "quarantine:release": "Release held mail",
  "quarantine:view": "View held mail",
  "scanner:operations:view": "See scanner operations",
  "trace:content": "Read message contents",
  "trace:view": "Trace your messages",
};

export function permissionCapabilityLabel(permission: string): string {
  return fromLabels(PERMISSION_CAPABILITY_LABELS, permission);
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
 * What a decision did to the message. The wire value is a machine key written
 * by the policy engine, so every code the engine can emit is named here: a
 * customer needs the outcome ("the message was held because it looked like
 * phishing"), not `QUARANTINE_PHISHING`. A key that is not listed was typed by
 * an operator into a rule, so it is echoed back as readable words rather than
 * guessed at.
 */
const REASON_CODE_LABELS: Record<string, string> = {
  ALLOWED: "Delivered",
  QUARANTINE_MALWARE: "Held: malware",
  QUARANTINE_PHISHING: "Held: phishing",
  QUARANTINE_SPAM: "Held: spam",
  QUARANTINE_POLICY: "Held: matched your policy",
  QUARANTINE_ATTACHMENT: "Held: attachment not accepted",
  REJECT_SPF_FAIL: "Rejected: the sender domain did not authorise it",
  REJECT_DKIM_FAIL: "Rejected: the message signature did not verify",
  REJECT_DMARC_FAIL: "Rejected: failed the sender domain's alignment rule",
  REJECT_SPOOFING: "Rejected: the sender looked spoofed",
  REJECT_POLICY: "Rejected: refused by your policy",
  DEFER_RATE_LIMIT: "Deferred: sending rate limit reached",
  DEFER_TEMPORARY: "Deferred: delivery will be retried",
  HOLD_PENDING: "Held: waiting for a decision",
  OUTBOUND_POLICY: "Restricted by an outbound limit",
  OUTBOUND_UNAUTHORIZED_BULK: "Bulk send from an unapproved sender",
  OUTBOUND_SOURCE_COMPROMISE: "A sending source looks compromised",
  OUTBOUND_XOORG_SPOOFING: "A sender is impersonating one of your other domains",
  OUTBOUND_QUEUE_PRESSURE: "The sending queue is under pressure",
  OUTBOUND_BULK_ANOMALY: "Bulk volume is outside the usual range",
  OUTBOUND_ROTATING_RECIPIENTS: "Recipients rotate between sends",
  OUTBOUND_CAMPAIGN_CLUSTER: "Sends look like one campaign",
  OUTBOUND_FAILURE_SPIKE: "Delivery failures spiked",
};

/** What a policy or intelligence decision did, in outcome words. */
export function reasonCodeLabel(value: string): string {
  return fromLabels(REASON_CODE_LABELS, value);
}

/**
 * One-line summary of what a rule matches, in the words the rule builder uses.
 * Every value the engine stores is read through a label map here, so the
 * summary never repeats a scanner key, a verdict token or a severity name the
 * way the database spells them.
 */
export function summarizeRuleCondition(condition: RuleCondition): string {
  const parts: string[] = [];
  const sender = condition.sender;
  if (sender) {
    if (sender.domain?.length) parts.push(`sender domain ${sender.domain.join(", ")}`);
    if (sender.address?.length) parts.push(`sender ${sender.address.join(", ")}`);
    if (sender.internal !== undefined) {
      parts.push(sender.internal ? "internal senders" : "external senders");
    }
    if (sender.authenticated !== undefined) {
      parts.push(sender.authenticated ? "authenticated senders" : "unauthenticated senders");
    }
  }
  const recipient = condition.recipient;
  if (recipient) {
    if (recipient.domain?.length) parts.push(`recipient domain ${recipient.domain.join(", ")}`);
    if (recipient.address?.length) parts.push(`recipient ${recipient.address.join(", ")}`);
    if (recipient.internal !== undefined) {
      parts.push(recipient.internal ? "internal recipients" : "external recipients");
    }
  }
  const auth = condition.auth;
  if (auth) {
    if (auth.spf?.length) {
      parts.push(`sender authorisation ${auth.spf.map((v) => AUTH_RESULT_LABELS[v]).join(", ")}`);
    }
    if (auth.dkim?.length) {
      parts.push(`message signature ${auth.dkim.map((v) => AUTH_RESULT_LABELS[v]).join(", ")}`);
    }
    if (auth.dmarc?.length) {
      parts.push(`domain alignment ${auth.dmarc.map((v) => AUTH_RESULT_LABELS[v]).join(", ")}`);
    }
  }
  const content = condition.content;
  if (content) {
    if (content.has_attachment !== undefined) {
      parts.push(content.has_attachment ? "has an attachment" : "has no attachment");
    }
    if (content.attachment_types?.length) {
      parts.push(`attachment types ${content.attachment_types.join(", ")}`);
    }
    if (content.size_gt !== undefined) parts.push(`larger than ${content.size_gt} bytes`);
    if (content.has_url !== undefined) parts.push(content.has_url ? "contains a link" : "no link");
  }
  const finding = condition.finding;
  if (finding) {
    if (finding.scanner?.length) {
      parts.push(`from ${finding.scanner.map((scanner) => SCANNER_LABELS[scanner]).join(", ")}`);
    }
    if (finding.severity?.length) {
      parts.push(`severity ${finding.severity.map((s) => FINDING_SEVERITY_LABELS[s]).join(", ")}`);
    }
    if (finding.category?.length) {
      parts.push(`category ${finding.category.map((c) => FINDING_CATEGORY_LABELS[c]).join(", ")}`);
    }
    if (finding.false_positive !== undefined) {
      parts.push(finding.false_positive ? "marked as a mistake" : "not marked as a mistake");
    }
  }
  const scope = CONDITION_SCOPE_LABELS[condition.scope];
  return parts.length === 0 ? `${scope} · every message` : `${scope} · ${parts.join(" · ")}`;
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
 * How this installation proves who an administrator is before the console
 * loads. The console cannot change it, so the words name where the identity
 * comes from instead of naming a protocol.
 */
const IDENTITY_PROVIDER_LABELS = {
  "proxy-header": "This installation's sign-in boundary",
  oidc: "External identity provider",
} as const;

export function identityProviderLabel(value: string): string {
  return fromLabels(IDENTITY_PROVIDER_LABELS, value);
}

/**
 * The state of the deployment record itself. Distinct from a customer
 * lifecycle: this says whether the installation is in service.
 */
const DEPLOYMENT_LIFECYCLE_LABELS = {
  active: "In service",
  suspended: "Suspended",
  decommissioned: "Decommissioned",
} as const;

export function deploymentLifecycleLabel(value: string): string {
  return fromLabels(DEPLOYMENT_LIFECYCLE_LABELS, value);
}

/**
 * A session window in words. The server publishes seconds because that is what
 * it enforces; nobody reads a policy as 28800.
 */
export function sessionWindowLabel(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "Not published";
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  }
  const hours = minutes / 60;
  const rounded = Number.isInteger(hours) ? String(hours) : hours.toFixed(1);
  return `${rounded} hour${hours === 1 ? "" : "s"}`;
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
    "The internal name for this setting. Audit records and support references name this key rather than the label.",
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
  platformReadout:
    "The running platform reports these facts about itself. They are published to system administrators only and nothing on this page changes them.",
  identityMode:
    "How this installation proves who you are before the console loads. Support needs this when a sign-in problem belongs to the provider rather than to your account.",
  sessionPolicy:
    "How long this sign-in lasts. The idle window restarts when you use the console; the absolute window does not. Re-authentication is the short window a high-risk change needs.",
  deploymentRecord:
    "The installation this console is connected to. Changing it is a deployment task, not a console setting, so it is shown here rather than edited.",
  configPublisher:
    "The person who published this configuration version. Hovering the name shows the identifier the audit record uses.",
} as const;

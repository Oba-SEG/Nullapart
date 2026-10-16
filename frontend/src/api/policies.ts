/**
 * Nullapart policy + feature administration contract.
 *
 * Mirrors `nullapart_mail_contracts::policy::PolicyRule` and the `/policies`
 * and `/features` control-plane endpoints. The builders are pure so the admin
 * UI can assemble rules from structured fields and omit empty condition parts
 * instead of ever offering a raw JSON editor.
 */

import { randomUuid } from "../lib/ids";
export type ManagementLevel = "customer" | "support" | "system";
export type RevisionScope = "system" | "tenant";
export type OverrideScope = "system" | "deployment" | "tenant";
export type ConditionScope = "transaction" | "tenant" | "recipient";
export type Disposition = "allow" | "quarantine" | "reject" | "hold" | "defer";
export type NotifyTarget = "admin" | "sender" | "recipient";
export type AuthResult =
  "pass" | "fail" | "softfail" | "neutral" | "none" | "permerror" | "temperror";
export type ScannerType =
  | "clamav"
  | "rspamd"
  | "urlanalysis"
  | "attachment"
  | "dkim"
  | "spf"
  | "dmarc"
  | "arc"
  | "inlineml"
  | "deepai"
  | "custom";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingCategory =
  | "malware"
  | "phishing"
  | "spam"
  | "spoofing"
  | "business_email_compromise"
  | "credential_harvest"
  | "malicious_url"
  | "malicious_attachment"
  | "suspicious_content"
  | "policy_violation"
  | "auth_failure"
  | "reputation"
  | "unknown";

export const MANAGEMENT_LEVELS: ManagementLevel[] = ["customer", "support", "system"];
export const CONDITION_SCOPES: ConditionScope[] = ["transaction", "tenant", "recipient"];
export const DISPOSITIONS: Disposition[] = ["allow", "quarantine", "reject", "hold", "defer"];
export const NOTIFY_TARGETS: NotifyTarget[] = ["admin", "sender", "recipient"];
export const AUTH_RESULTS: AuthResult[] = [
  "pass",
  "fail",
  "softfail",
  "neutral",
  "none",
  "permerror",
  "temperror",
];
export const SCANNER_TYPES: ScannerType[] = [
  "clamav",
  "rspamd",
  "urlanalysis",
  "attachment",
  "dkim",
  "spf",
  "dmarc",
  "arc",
  "inlineml",
  "deepai",
  "custom",
];
export const FINDING_SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
export const FINDING_CATEGORIES: FindingCategory[] = [
  "malware",
  "phishing",
  "spam",
  "spoofing",
  "business_email_compromise",
  "credential_harvest",
  "malicious_url",
  "malicious_attachment",
  "suspicious_content",
  "policy_violation",
  "auth_failure",
  "reputation",
  "unknown",
];

export const MAX_RULES = 200;
export const MIN_RULE_PRIORITY = -1000;
export const MAX_RULE_PRIORITY = 1000;
export const MIN_OVERRIDE_REASON_LENGTH = 10;
export const MAX_OVERRIDE_REASON_LENGTH = 500;
export const OVERRIDE_VALUE_PREFIX = "typed:";

export interface RevisionSummary {
  revision_number: number;
  published_by: string;
  published_at: string;
  scope_level: RevisionScope;
}

export interface PolicyFamily {
  family_key: string;
  /** Catalog label seeded by migration 039; the key stays for audit evidence. */
  display_name: string;
  description: string;
  management_level: ManagementLevel;
  security_floor: boolean;
  revision_count: number;
  active_revision: RevisionSummary | null;
}

export interface PolicyRevision extends RevisionSummary {
  activated_at?: string | null;
  deactivated_at?: string | null;
  rules_count?: number;
  rules: Rule[] | null;
}

export interface PolicyDetail {
  family: PolicyFamily;
  revisions: PolicyRevision[];
  /** Resolved server-side from this session's roles; null when it carries none. */
  caller_tier: ManagementLevel | null;
}

export interface PolicyList {
  families: PolicyFamily[];
  /** Resolved server-side from this session's roles; null when it carries none. */
  caller_tier: ManagementLevel | null;
}

export interface PublishResult {
  family_key: string;
  revision_number: number;
  published_at: string;
  rules_count: number;
}

export interface RefreshResult {
  family_key: string;
  refresh_requested_at: string;
}

export interface FeatureOverride {
  id: string;
  scope: OverrideScope;
  scope_id: string;
  value: string;
  owner: string;
  reason: string;
  revision: number;
  created_at: string;
  expires_at: string | null;
}

export interface Feature {
  feature_id: string;
  /** Catalog label written for operators; the id is what audit records name. */
  display_name: string;
  description: string;
  default_value: string;
  mandatory: boolean;
  kill_switch: boolean;
  allowed_scopes: OverrideScope[];
  effective_value: string;
  winning_scope: OverrideScope;
  overrides: FeatureOverride[];
}

export interface FeatureList {
  features: Feature[];
  /**
   * Override scopes the server will accept from this session, resolved by the
   * same tier ladder the write path enforces.
   */
  allowed_override_scopes: OverrideScope[];
}

export interface OverrideWriteResult extends FeatureOverride {
  effective_value: string;
  winning_scope: OverrideScope;
}

// ---------------------------------------------------------------------------
// Rule contract
// ---------------------------------------------------------------------------

export interface SenderCondition {
  domain?: string[];
  address?: string[];
  internal?: boolean;
  authenticated?: boolean;
}

export interface RecipientCondition {
  domain?: string[];
  address?: string[];
  internal?: boolean;
}

export interface AuthCondition {
  spf?: AuthResult[];
  dkim?: AuthResult[];
  dmarc?: AuthResult[];
}

export interface ContentCondition {
  has_attachment?: boolean;
  attachment_types?: string[];
  size_gt?: number;
  has_url?: boolean;
}

export interface FindingCondition {
  scanner?: ScannerType[];
  severity?: FindingSeverity[];
  category?: FindingCategory[];
  false_positive?: boolean;
}

export interface RuleCondition {
  sender?: SenderCondition;
  recipient?: RecipientCondition;
  auth?: AuthCondition;
  content?: ContentCondition;
  finding?: FindingCondition;
  scope: ConditionScope;
}

export interface RuleAction {
  disposition: Disposition;
  reason_code: string;
  notify?: NotifyTarget[];
  metadata?: Record<string, unknown>;
}

export interface Rule {
  id: string;
  name: string;
  priority: number;
  enabled: boolean;
  condition: RuleCondition;
  action: RuleAction;
}

export interface PolicyPublishBody {
  rules: Rule[];
}

/** Tri-state editor value: unset, explicitly true, explicitly false. */
export type TriState = boolean | null;

/** Flat structured editor state; `toCondition` converts it to the wire shape. */
export interface RuleDraft {
  id: string;
  name: string;
  priority: number;
  enabled: boolean;
  scope: ConditionScope;
  senderDomains: string;
  senderAddresses: string;
  senderInternal: TriState;
  senderAuthenticated: TriState;
  recipientDomains: string;
  recipientAddresses: string;
  recipientInternal: TriState;
  authSpf: AuthResult[];
  authDkim: AuthResult[];
  authDmarc: AuthResult[];
  hasAttachment: TriState;
  attachmentTypes: string;
  sizeGt: string;
  hasUrl: TriState;
  scanners: ScannerType[];
  severities: FindingSeverity[];
  categories: FindingCategory[];
  falsePositive: TriState;
  disposition: Disposition;
  reasonCode: string;
  notify: NotifyTarget[];
  actionMetadata?: Record<string, unknown>;
}

const REASON_CODE_PATTERN = /^[A-Z0-9_]{1,64}$/;

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((char) => {
    const code = char.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
}

/** Splits a comma/newline separated field into trimmed, non-empty entries. */
export function parseList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function hasEntries(value: object): boolean {
  return Object.keys(value).length > 0;
}

/**
 * Builds the wire `RuleCondition` from structured editor state.
 * Empty CSV fields and unset tri-states are omitted entirely, never `[]`.
 */
export function toCondition(draft: RuleDraft): RuleCondition {
  const condition: RuleCondition = { scope: draft.scope };

  const sender: SenderCondition = {};
  const senderDomains = parseList(draft.senderDomains);
  const senderAddresses = parseList(draft.senderAddresses);
  if (senderDomains.length > 0) sender.domain = senderDomains;
  if (senderAddresses.length > 0) sender.address = senderAddresses;
  if (draft.senderInternal !== null) sender.internal = draft.senderInternal;
  if (draft.senderAuthenticated !== null) sender.authenticated = draft.senderAuthenticated;
  if (hasEntries(sender)) condition.sender = sender;

  const recipient: RecipientCondition = {};
  const recipientDomains = parseList(draft.recipientDomains);
  const recipientAddresses = parseList(draft.recipientAddresses);
  if (recipientDomains.length > 0) recipient.domain = recipientDomains;
  if (recipientAddresses.length > 0) recipient.address = recipientAddresses;
  if (draft.recipientInternal !== null) recipient.internal = draft.recipientInternal;
  if (hasEntries(recipient)) condition.recipient = recipient;

  const auth: AuthCondition = {};
  if (draft.authSpf.length > 0) auth.spf = draft.authSpf;
  if (draft.authDkim.length > 0) auth.dkim = draft.authDkim;
  if (draft.authDmarc.length > 0) auth.dmarc = draft.authDmarc;
  if (hasEntries(auth)) condition.auth = auth;

  const content: ContentCondition = {};
  const sizeGt = Number(draft.sizeGt);
  const attachmentTypes = parseList(draft.attachmentTypes);
  if (draft.hasAttachment !== null) content.has_attachment = draft.hasAttachment;
  if (attachmentTypes.length > 0) content.attachment_types = attachmentTypes;
  if (draft.sizeGt.trim().length > 0 && Number.isFinite(sizeGt) && sizeGt >= 0) {
    content.size_gt = sizeGt;
  }
  if (draft.hasUrl !== null) content.has_url = draft.hasUrl;
  if (hasEntries(content)) condition.content = content;

  const finding: FindingCondition = {};
  if (draft.scanners.length > 0) finding.scanner = draft.scanners;
  if (draft.severities.length > 0) finding.severity = draft.severities;
  if (draft.categories.length > 0) finding.category = draft.categories;
  if (draft.falsePositive !== null) finding.false_positive = draft.falsePositive;
  if (hasEntries(finding)) condition.finding = finding;

  return condition;
}

function toAction(draft: RuleDraft): RuleAction {
  const action: RuleAction = {
    disposition: draft.disposition,
    reason_code: draft.reasonCode,
  };
  if (draft.notify.length > 0) action.notify = draft.notify;
  if (draft.actionMetadata && hasEntries(draft.actionMetadata)) {
    action.metadata = structuredClone(draft.actionMetadata);
  }
  return action;
}

/** Builds the wire `Rule` from structured editor state. */
export function ruleFromDraft(draft: RuleDraft): Rule {
  return {
    id: draft.id,
    name: draft.name.trim(),
    priority: draft.priority,
    enabled: draft.enabled,
    condition: toCondition(draft),
    action: toAction(draft),
  };
}

function joinList(value: string[] | undefined): string {
  return (value ?? []).join(", ");
}

function triState(value: boolean | undefined): TriState {
  return value === undefined ? null : value;
}

/** Converts a stored rule back into structured editor state. */
export function draftFromRule(rule: Rule): RuleDraft {
  const condition = rule.condition;
  return {
    id: rule.id,
    name: rule.name,
    priority: rule.priority,
    enabled: rule.enabled,
    scope: condition.scope,
    senderDomains: joinList(condition.sender?.domain),
    senderAddresses: joinList(condition.sender?.address),
    senderInternal: triState(condition.sender?.internal),
    senderAuthenticated: triState(condition.sender?.authenticated),
    recipientDomains: joinList(condition.recipient?.domain),
    recipientAddresses: joinList(condition.recipient?.address),
    recipientInternal: triState(condition.recipient?.internal),
    authSpf: condition.auth?.spf ?? [],
    authDkim: condition.auth?.dkim ?? [],
    authDmarc: condition.auth?.dmarc ?? [],
    hasAttachment: triState(condition.content?.has_attachment),
    attachmentTypes: joinList(condition.content?.attachment_types),
    sizeGt: condition.content?.size_gt === undefined ? "" : String(condition.content.size_gt),
    hasUrl: triState(condition.content?.has_url),
    scanners: condition.finding?.scanner ?? [],
    severities: condition.finding?.severity ?? [],
    categories: condition.finding?.category ?? [],
    falsePositive: triState(condition.finding?.false_positive),
    disposition: rule.action.disposition,
    reasonCode: rule.action.reason_code,
    notify: rule.action.notify ?? [],
    actionMetadata: rule.action.metadata ? structuredClone(rule.action.metadata) : undefined,
  };
}

export function newRuleDraft(): RuleDraft {
  return {
    id: randomUuid(),
    name: "",
    priority: 0,
    enabled: true,
    scope: "transaction",
    senderDomains: "",
    senderAddresses: "",
    senderInternal: null,
    senderAuthenticated: null,
    recipientDomains: "",
    recipientAddresses: "",
    recipientInternal: null,
    authSpf: [],
    authDkim: [],
    authDmarc: [],
    hasAttachment: null,
    attachmentTypes: "",
    sizeGt: "",
    hasUrl: null,
    scanners: [],
    severities: [],
    categories: [],
    falsePositive: null,
    disposition: "quarantine",
    reasonCode: "",
    notify: [],
    actionMetadata: undefined,
  };
}

// ---------------------------------------------------------------------------
// Validation (client-side convenience; the server stays authoritative)
// ---------------------------------------------------------------------------

export function ruleNameError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return "Enter a rule name between 1 and 128 characters.";
  }
  if (hasControlCharacters(trimmed)) {
    return "Control characters are not allowed in a rule name.";
  }
  return undefined;
}

export function priorityError(value: number): string | undefined {
  if (!Number.isInteger(value) || value < MIN_RULE_PRIORITY || value > MAX_RULE_PRIORITY) {
    return `Priority must be a whole number between ${MIN_RULE_PRIORITY} and ${MAX_RULE_PRIORITY}.`;
  }
  return undefined;
}

export function reasonCodeError(value: string): string | undefined {
  if (!REASON_CODE_PATTERN.test(value)) {
    return "Use 1-64 characters: uppercase letters, digits and underscores only.";
  }
  return undefined;
}

export function draftErrors(draft: RuleDraft): {
  name?: string;
  priority?: string;
  reasonCode?: string;
} {
  const errors: { name?: string; priority?: string; reasonCode?: string } = {};
  const name = ruleNameError(draft.name);
  const priority = priorityError(draft.priority);
  const reasonCode = reasonCodeError(draft.reasonCode);
  if (name !== undefined) errors.name = name;
  if (priority !== undefined) errors.priority = priority;
  if (reasonCode !== undefined) errors.reasonCode = reasonCode;
  return errors;
}

export function isDraftValid(draft: RuleDraft): boolean {
  return Object.keys(draftErrors(draft)).length === 0;
}

/** Evaluation order: higher priority is evaluated first. */
export function sortByEvaluationOrder(rules: Rule[]): Rule[] {
  return [...rules].sort((left, right) => right.priority - left.priority);
}

/** Assigns positional priorities so array order is the evaluation order. */
export function resequenceRules(rules: Rule[]): Rule[] {
  return rules.map((rule, index) => ({ ...rule, priority: rules.length - index }));
}

export function cloneRulesForEditing(rules: Rule[]): Rule[] {
  return sortByEvaluationOrder(structuredClone(rules));
}

/** Short human-readable condition summary for the rules table. */
export function summarizeCondition(condition: RuleCondition): string {
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
    if (auth.spf?.length) parts.push(`spf ${auth.spf.join(", ")}`);
    if (auth.dkim?.length) parts.push(`dkim ${auth.dkim.join(", ")}`);
    if (auth.dmarc?.length) parts.push(`dmarc ${auth.dmarc.join(", ")}`);
  }
  const content = condition.content;
  if (content) {
    if (content.has_attachment !== undefined) {
      parts.push(content.has_attachment ? "has attachment" : "no attachment");
    }
    if (content.attachment_types?.length) {
      parts.push(`attachment types ${content.attachment_types.join(", ")}`);
    }
    if (content.size_gt !== undefined) parts.push(`larger than ${content.size_gt} bytes`);
    if (content.has_url !== undefined) parts.push(content.has_url ? "has url" : "no url");
  }
  const finding = condition.finding;
  if (finding) {
    if (finding.scanner?.length) parts.push(`scanner ${finding.scanner.join(", ")}`);
    if (finding.severity?.length) parts.push(`severity ${finding.severity.join(", ")}`);
    if (finding.category?.length) parts.push(`category ${finding.category.join(", ")}`);
    if (finding.false_positive !== undefined) {
      parts.push(finding.false_positive ? "marked false positive" : "not a false positive");
    }
  }
  const scope = `scope ${condition.scope}`;
  return parts.length === 0 ? `${scope} · every message` : `${scope} · ${parts.join(" · ")}`;
}

// ---------------------------------------------------------------------------
// Authorization affordances (server-side authorization stays authoritative)
// ---------------------------------------------------------------------------

/**
 * The server resolves which management tier a session carries from the roles it
 * issued, including deployment-defined roles, and publishes that tier alongside
 * the data. The console reads it instead of re-deriving a tier from builtin
 * role keys, which silently locked out custom roles the server authorizes.
 */
export const TIER_RANK: Record<ManagementLevel, number> = {
  customer: 0,
  support: 1,
  system: 2,
};

export function tierAllows(caller: ManagementLevel | null, required: ManagementLevel): boolean {
  if (caller === null) return false;
  return TIER_RANK[caller] >= TIER_RANK[required];
}

/**
 * Scopes this session may write for a feature: the scopes the feature allows,
 * kept only where the server also placed them in the session's own list. An
 * empty result is a real lock, so the caller states the reason rather than
 * hiding the control.
 */
export function writableScopes(
  allowed: OverrideScope[],
  sessionScopes: OverrideScope[],
): OverrideScope[] {
  return allowed.filter((scope) => sessionScopes.includes(scope));
}

// ---------------------------------------------------------------------------
// Feature override values
// ---------------------------------------------------------------------------

export type OverrideValueKind = "inherit" | "enabled" | "disabled" | "typed";

export const OVERRIDE_VALUE_KINDS: OverrideValueKind[] = [
  "inherit",
  "enabled",
  "disabled",
  "typed",
];

export function decodeOverrideValue(value: string): { kind: OverrideValueKind; typed: string } {
  if (value.startsWith(OVERRIDE_VALUE_PREFIX)) {
    return { kind: "typed", typed: value.slice(OVERRIDE_VALUE_PREFIX.length) };
  }
  if (value === "inherit" || value === "enabled" || value === "disabled") {
    return { kind: value, typed: "" };
  }
  return { kind: "typed", typed: value };
}

export function encodeOverrideValue(kind: OverrideValueKind, typed: string): string {
  return kind === "typed" ? `${OVERRIDE_VALUE_PREFIX}${typed}` : kind;
}

export function overrideReasonError(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length < MIN_OVERRIDE_REASON_LENGTH) {
    return `Enter a reason of at least ${MIN_OVERRIDE_REASON_LENGTH} characters.`;
  }
  if (trimmed.length > MAX_OVERRIDE_REASON_LENGTH) {
    return `Enter a reason of at most ${MAX_OVERRIDE_REASON_LENGTH} characters.`;
  }
  if (hasControlCharacters(trimmed)) {
    return "Control characters are not allowed in a reason.";
  }
  return undefined;
}

/** Converts a `datetime-local` value to RFC3339, rejecting past instants. */
export function expiryError(localValue: string): string | undefined {
  if (localValue.trim().length === 0) return undefined;
  const parsed = new Date(localValue);
  if (Number.isNaN(parsed.getTime())) return "Enter a valid expiry date and time.";
  if (parsed.getTime() <= Date.now()) return "Expiry must be in the future.";
  return undefined;
}

export function expiryToRfc3339(localValue: string): string | null {
  if (localValue.trim().length === 0) return null;
  return new Date(localValue).toISOString();
}

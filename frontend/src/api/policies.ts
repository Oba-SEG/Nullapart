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
  /** The publisher's name for the seat reading the history. A customer read
   * resolves a publisher outside their own organisation to the provider. A
   * service that predates the field leaves it out, and the row key it stores is
   * never printed. */
  published_by_name?: string | null;
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
  /** What this family's published rules actually do. The editor renders its
   * condition and threshold sections from this instead of showing every family
   * the same fields. */
  profile: RuleProfile;
}

// ---------------------------------------------------------------------------
// Per-family rule profile (published by `nullapart_mail_core::policy_profile`)
// ---------------------------------------------------------------------------

export type EnforcementMode = "ml_thresholds" | "outbound_thresholds" | "not_enforced";
export type ConditionFieldName = "sender" | "recipient" | "auth" | "content" | "finding";
export type MetadataFieldKind = "count" | "minutes" | "ratio" | "class_bands";

export interface EnforcementProfile {
  mode: EnforcementMode;
  summary: string;
}

export interface ConditionFieldProfile {
  field: ConditionFieldName;
  /** False means the delivery path never evaluates this predicate here. */
  honoured: boolean;
  note: string;
}

export interface MetadataFieldProfile {
  key: string;
  label: string;
  kind: MetadataFieldKind;
  min: number | null;
  max: number | null;
  /** The built-in operating point used when the key is absent. */
  default: number | null;
  /** Accepted class keys, present only for `class_bands`. */
  classes?: string[];
  hint: string;
}

export interface MetadataProfile {
  read: boolean;
  /** When metadata is present it must carry exactly the listed keys. */
  exact_keys: boolean;
  metadata_optional: boolean;
  merge: string;
  fields: MetadataFieldProfile[];
}

export interface RuleProfile {
  enforcement: EnforcementProfile;
  conditions: ConditionFieldProfile[];
  metadata: MetadataProfile;
}

/** The single `action.metadata` key the inline classifier reads. */
export const ML_THRESHOLDS_KEY = "thresholds";
export const ML_THRESHOLDS_PAYLOAD_VERSION = 1;

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
  /** The stored actor reference: an administrator identity id. Kept because
   * audit records and support tickets name overrides by it. */
  owner: string;
  /** Whose decision this is, in the words an operator reads. The server falls
   * back to `owner` when no display name exists, so it is never empty. */
  owner_display_name: string;
  reason: string;
  revision: number;
  created_at: string;
  expires_at: string | null;
}

/**
 * What `GET /features` answers the operator console. The same read answered to a
 * customer-tier session is projected: the platform's security floors, kill
 * switches and scope ladder are absent rather than blanked, features no Customer
 * scope may reach are not listed, and only that customer's own override rows
 * come back alongside a `governed_by` outcome word. This console is never that
 * reader, so the fields it renders stay required here.
 */
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
  /** Text value per scalar `action.metadata` key the family profile declares. */
  metadataValues: Record<string, string>;
  /** Per-class operating points for a `class_bands` profile, set classes only. */
  classBands: Record<string, ClassBandEntry>;
}

export interface ClassBandEntry {
  low: string;
  medium: string;
  high: string;
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

// ---------------------------------------------------------------------------
// Profile-driven action metadata
// ---------------------------------------------------------------------------

function numericText(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? String(value) : "";
}

function scalarFields(profile: RuleProfile): MetadataFieldProfile[] {
  return profile.metadata.fields.filter((field) => field.kind !== "class_bands");
}

function bandField(profile: RuleProfile): MetadataFieldProfile | undefined {
  return profile.metadata.fields.find((field) => field.kind === "class_bands");
}

/** Reads the scalar threshold values a stored rule carries for this family. */
export function scalarsFromMetadata(
  profile: RuleProfile,
  metadata: Record<string, unknown> | undefined,
): Record<string, string> {
  const values: Record<string, string> = {};
  for (const field of scalarFields(profile)) {
    values[field.key] = numericText(metadata?.[field.key]);
  }
  return values;
}

/**
 * Reads the per-class bands from a stored `thresholds` payload. A payload the
 * server would reject reads back as unset rather than half-populated, so the
 * operator sees the fields they must fill instead of an editor showing numbers
 * that cannot publish.
 */
export function classBandsFromMetadata(
  profile: RuleProfile,
  metadata: Record<string, unknown> | undefined,
): Record<string, ClassBandEntry> {
  const field = bandField(profile);
  const result: Record<string, ClassBandEntry> = {};
  if (field === undefined) return result;
  const payload = metadata?.[field.key];
  if (typeof payload !== "object" || payload === null) return result;
  const classes = (payload as Record<string, unknown>).classes;
  if (typeof classes !== "object" || classes === null) return result;
  for (const classKey of field.classes ?? []) {
    const entry = (classes as Record<string, unknown>)[classKey];
    if (typeof entry !== "object" || entry === null) continue;
    const record = entry as Record<string, unknown>;
    const low = numericText(record.low);
    const medium = numericText(record.medium);
    const high = numericText(record.high);
    if (low.length === 0 || medium.length === 0 || high.length === 0) continue;
    if (classBandError(low, medium, high) !== undefined) continue;
    result[classKey] = { low, medium, high };
  }
  return result;
}

/** Mirrors `valid_class_threshold` in the classifier's threshold parser. */
function classBandError(low: string, medium: string, high: string): string | undefined {
  const values = [low, medium, high].map(Number);
  if (values.some((value) => !Number.isFinite(value))) {
    return "Enter a score between 0 and 1.";
  }
  const [lowValue, mediumValue, highValue] = values;
  if (!(lowValue > 0)) return "The operating point must be above 0.";
  if (!(lowValue <= mediumValue && mediumValue <= highValue)) {
    return "Bands must rise: low at or below medium, medium at or below high.";
  }
  if (highValue > 1) return "Bands cannot exceed 1.";
  return undefined;
}

function scalarFieldError(field: MetadataFieldProfile, raw: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return `${field.label} is required when any threshold is set.`;
  const value = Number(trimmed);
  if (!Number.isFinite(value)) return `${field.label} must be a number.`;
  if (field.kind === "ratio") {
    if (!(value > 0)) return `${field.label} must be above 0.`;
    if (field.max !== null && value > field.max)
      return `${field.label} cannot exceed ${field.max}.`;
    return undefined;
  }
  if (!Number.isInteger(value)) return `${field.label} must be a whole number.`;
  if (field.min !== null && value < field.min)
    return `${field.label} must be at least ${field.min}.`;
  if (field.max !== null && value > field.max) return `${field.label} cannot exceed ${field.max}.`;
  return undefined;
}

/**
 * Builds the `action.metadata` object this family accepts, plus the per-key
 * errors that stop it. A profile with `exact_keys` cannot be published half
 * filled, so any value set makes every declared key required; leaving them all
 * blank publishes no metadata, which keeps the built-in defaults.
 * Error keys are the metadata key, or `<key>:<class>` for one band row.
 */
export function metadataFromDraft(
  profile: RuleProfile,
  draft: RuleDraft,
): { metadata?: Record<string, unknown>; errors: Record<string, string> } {
  const errors: Record<string, string> = {};
  const fields = profile.metadata.fields;
  if (!profile.metadata.read || fields.length === 0) {
    // Nothing reads this family's metadata, so a stored payload is kept exactly
    // as it is rather than discarded by an editor that cannot interpret it.
    return draft.actionMetadata && hasEntries(draft.actionMetadata)
      ? { metadata: structuredClone(draft.actionMetadata), errors }
      : { errors };
  }

  const scalars = scalarFields(profile);
  const setScalars = scalars.filter((field) => draft.metadataValues[field.key]?.trim().length > 0);
  const metadata: Record<string, unknown> = {};

  if (setScalars.length > 0) {
    const scalarErrors: [string, string][] = [];
    const values: Record<string, number> = {};
    for (const field of scalars) {
      const error = scalarFieldError(field, draft.metadataValues[field.key] ?? "");
      if (error !== undefined) scalarErrors.push([field.key, error]);
      else values[field.key] = Number(draft.metadataValues[field.key].trim());
    }
    // `exact_keys` means a partial object is a rejected publish, not a rule that
    // keeps the defaults for the keys left out. Refusing the whole set here is
    // what stops Save from writing a rule the server cannot accept.
    if (scalarErrors.length === 0) Object.assign(metadata, values);
    else for (const [key, error] of scalarErrors) errors[key] = error;
  }

  const bands = bandField(profile);
  if (bands !== undefined) {
    const entries = Object.entries(draft.classBands);
    if (entries.length > 0) {
      const classes: Record<string, { low: number; medium: number; high: number }> = {};
      for (const [classKey, entry] of entries) {
        const error = classBandError(entry.low, entry.medium, entry.high);
        if (error !== undefined) errors[`${bands.key}:${classKey}`] = error;
        else
          classes[classKey] = {
            low: Number(entry.low),
            medium: Number(entry.medium),
            high: Number(entry.high),
          };
      }
      const bandErrors = Object.keys(errors).some((key) => key.startsWith(`${bands.key}:`));
      if (!bandErrors && Object.keys(classes).length > 0) {
        metadata[bands.key] = { version: ML_THRESHOLDS_PAYLOAD_VERSION, classes };
      }
    }
  }

  return Object.keys(metadata).length > 0 ? { metadata, errors } : { errors };
}

function toAction(draft: RuleDraft, metadata: Record<string, unknown> | undefined): RuleAction {
  const action: RuleAction = {
    disposition: draft.disposition,
    reason_code: draft.reasonCode,
  };
  if (draft.notify.length > 0) action.notify = draft.notify;
  if (metadata && hasEntries(metadata)) {
    action.metadata = structuredClone(metadata);
  }
  return action;
}

/** Builds the wire `Rule` from structured editor state. */
export function ruleFromDraft(draft: RuleDraft, profile?: RuleProfile): Rule {
  // With a profile the metadata is rebuilt from the family's own form, so
  // clearing every threshold really does drop the key instead of leaving a
  // stale payload from the revision that was loaded.
  const metadata =
    profile === undefined ? draft.actionMetadata : metadataFromDraft(profile, draft).metadata;
  return {
    id: draft.id,
    name: draft.name.trim(),
    priority: draft.priority,
    enabled: draft.enabled,
    condition: toCondition(draft),
    action: toAction(draft, metadata),
  };
}

function joinList(value: string[] | undefined): string {
  return (value ?? []).join(", ");
}

function triState(value: boolean | undefined): TriState {
  return value === undefined ? null : value;
}

/** Converts a stored rule back into structured editor state. */
export function draftFromRule(rule: Rule, profile?: RuleProfile): RuleDraft {
  const condition = rule.condition;
  const metadata = rule.action.metadata;
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
    actionMetadata: metadata ? structuredClone(metadata) : undefined,
    metadataValues: profile === undefined ? {} : scalarsFromMetadata(profile, metadata),
    classBands: profile === undefined ? {} : classBandsFromMetadata(profile, metadata),
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
    metadataValues: {},
    classBands: {},
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

/**
 * Editor validation problems. The three rule-identity fields are named because
 * the form always shows them; every other key is a profile-driven one: a
 * metadata key, or `<key>:<class>` for one classifier band row.
 */
export interface DraftErrors {
  name?: string;
  priority?: string;
  reasonCode?: string;
  [key: string]: string | undefined;
}

export function draftErrors(draft: RuleDraft, profile?: RuleProfile): DraftErrors {
  const errors: DraftErrors = {};
  const name = ruleNameError(draft.name);
  const priority = priorityError(draft.priority);
  const reasonCode = reasonCodeError(draft.reasonCode);
  if (name !== undefined) errors.name = name;
  if (priority !== undefined) errors.priority = priority;
  if (reasonCode !== undefined) errors.reasonCode = reasonCode;
  if (profile !== undefined) Object.assign(errors, metadataFromDraft(profile, draft).errors);
  return errors;
}

export function isDraftValid(draft: RuleDraft, profile?: RuleProfile): boolean {
  return Object.keys(draftErrors(draft, profile)).length === 0;
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

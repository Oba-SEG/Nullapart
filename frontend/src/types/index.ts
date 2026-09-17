// Core types mirroring Rust contracts

export type MailDirection = "inbound" | "outbound";

export type Disposition = "allow" | "quarantine" | "reject" | "hold" | "defer";

export type DeliveryStatus =
  "pending" | "in_progress" | "success" | "transient_failure" | "permanent_failure" | "bounced";

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

export type AuthResultType =
  "pass" | "fail" | "softfail" | "neutral" | "none" | "permerror" | "temperror";

export type ActorType = "user" | "system" | "api_key" | "service_account";

// API Types
export interface ApiError {
  error: string;
  message: string;
  code: string;
  details?: Record<string, unknown>;
  trace_id?: string;
  timestamp: string;
}

// Transaction types
export interface Transaction {
  id: string;
  direction: MailDirection;
  deployment_id: string;
  connection_id: string;
  envelope_sender: string;
  recipients: Recipient[];
  message_id?: string;
  spf_result?: AuthResult;
  dkim_result?: AuthResult;
  dmarc_result?: AuthResult;
  mime_artifact_id: string;
  content_hash: string;
  shared_findings: Finding[];
  received_at: string;
  postfix_queue_ids: string[];
  trace_id: string;
}

export interface TenantMessage {
  id: string;
  transaction_id: string;
  customer_id: string;
  recipients: Recipient[];
  policy_revision: string;
  findings: Finding[];
  disposition: Disposition;
  quarantine_state?: QuarantineState;
  delivery_attempts: DeliveryAttempt[];
  remediation_state?: RemediationState;
}

export interface Recipient {
  address: string;
  orcpt?: string;
  notify?: string[];
}

export interface AuthResult {
  result: AuthResultType;
  detail?: string;
  identity?: string;
  selector?: string;
  domain?: string;
}

export interface Finding {
  id: string;
  scope: "transaction" | "content" | "tenant" | "recipient";
  scanner: string;
  scanner_status: string;
  severity: FindingSeverity;
  confidence: "high" | "medium" | "low";
  category: FindingCategory;
  description: string;
  details?: Record<string, unknown>;
  indicators: Indicator[];
  created_at: string;
  false_positive: boolean;
  transaction_id?: string;
  tenant_message_id?: string;
}

export interface Indicator {
  indicator_type: string;
  value: string;
  context?: string;
}

export interface QuarantineState {
  quarantined_at: string;
  reason: string;
  released_at?: string;
  released_by?: string;
}

export interface RemediationState {
  state: string;
  created_at: string;
  completed_at?: string;
  action?: string;
}

export interface DeliveryAttempt {
  id: string;
  attempt_number: number;
  scheduled_at: string;
  started_at?: string;
  completed_at?: string;
  result: DeliveryResult;
  downstream_smtp_response?: string;
  next_retry_at?: string;
}

export interface DeliveryResult {
  status: DeliveryStatus;
  code?: number;
  enhanced_code?: string;
  message?: string;
}

// User/Auth types
export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  customer_id?: string;
  deployment_id: string;
}

export type UserRole = "system_admin" | "support" | "customer_admin";

export interface Tenant {
  id: string;
  name: string;
  customer_id: string;
  status: "active" | "suspended" | "terminated";
  domains: string[];
}

// Feature flags
export interface Feature {
  id: string;
  name: string;
  description: string;
  default_value: boolean;
  scope: "system" | "deployment" | "tenant";
  scope_id?: string;
  effective_value: boolean;
}

// Policy
export interface Policy {
  id: string;
  version: number;
  created_at: string;
  is_default: boolean;
}

// Queue metrics
export interface QueueMetrics {
  queue_depth: number;
  oldest_queue_age_seconds: number;
  smtp_rate_per_minute: number;
  delivery_latency_p50_ms: number;
  delivery_latency_p99_ms: number;
  rejects_today: number;
  defers_today: number;
}

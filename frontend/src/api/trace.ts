/**
 * Nullapart mail trace contract.
 *
 * Typed client for the `/mail-trace` control-plane endpoints: transaction
 * search, transaction detail and the permission-gated full-message content
 * projection. Responses arrive through the shared `{data}`/`{error}` envelope
 * handled by `api/client`; server-side authorization stays authoritative.
 */

import { api } from "./client";

export interface TraceSearchInstance {
  tenant_message_id: string;
  disposition: string;
}

export interface TraceSearchResult {
  transaction_id: string;
  direction: string;
  envelope_sender: string | null;
  message_id: string | null;
  received_at: string;
  recipients: string[];
  instances: TraceSearchInstance[];
}

export interface TraceSearchResults {
  results: TraceSearchResult[];
  total_count: number;
  has_more: boolean;
}

export interface TraceSearchBody {
  q: string;
  limit?: number;
}

export interface TraceRecipient {
  address: string;
  orcpt: string | null;
  notify: string | null;
}

export interface TraceAuthResults {
  spf_result: unknown | null;
  dkim_result: unknown | null;
  dmarc_result: unknown | null;
  arc_result: unknown | null;
}

export interface TraceInstance {
  tenant_message_id: string;
  disposition: string;
  remediation_type: string | null;
  created_at: string;
  updated_at: string;
}

export interface TraceDeliveryAttempt {
  attempt_number: number;
  status: string;
  smtp_code: string | null;
  enhanced_code: string | null;
  smtp_message: string | null;
  scheduled_at: string | null;
  completed_at: string | null;
  next_retry_at: string | null;
  /** MTA queue identifier. The customer answer omits the key. */
  postfix_queue_id?: string | null;
}

export interface TraceFinding {
  id: string;
  severity: string;
  category: string;
  description: string;
  /** Which analysis recorded the finding, in the customer's naming. The platform answer omits the key. */
  check?: string;
  /** The same source under the platform's field name. The customer answer omits the key. */
  scanner_type?: string;
  false_positive: boolean;
  created_at: string;
}

export interface TraceFlowStage {
  stage: string;
  at: string;
}

export interface TraceTransaction {
  transaction_id: string;
  /** Platform log correlation id. The customer answer omits the key. */
  trace_id?: string;
  direction: string;
  /** Which node accepted the mail. The customer answer omits the key. */
  deployment_id?: string;
  envelope_sender: string | null;
  message_id: string | null;
  /** Content dedup hash. The customer answer omits the key. */
  content_hash?: string;
  received_at: string;
  recipients: TraceRecipient[];
  auth: TraceAuthResults;
  /** MTA queue identifiers. The customer answer omits the key. */
  postfix_queue_ids?: string[];
  instances: TraceInstance[];
  delivery_attempts: TraceDeliveryAttempt[];
  findings: TraceFinding[];
  flow_stages: TraceFlowStage[];
}

export interface MessageHeader {
  name: string;
  value: string;
}

export interface MessageAttachment {
  filename: string | null;
  content_type: string | null;
  size_bytes: number | null;
}

export interface MessageContentData {
  transaction_id: string;
  subject: string | null;
  from: string | null;
  to: string[];
  date: string | null;
  headers: MessageHeader[];
  plain_text: string | null;
  html: string | null;
  truncated: boolean;
  attachments: MessageAttachment[];
}

/**
 * POST /mail-trace/search — `q` needs at least 3 characters (server 400
 * VALIDATION otherwise); the query is echoed by the page before the call.
 */
export function traceSearch(
  body: TraceSearchBody,
  signal?: AbortSignal,
): Promise<TraceSearchResults> {
  return api.post<TraceSearchResults>("/mail-trace/search", body, { signal });
}

/** GET /mail-trace/transaction/:id — 404 when the transaction is not visible. */
export function getTraceTransaction(
  transactionId: string,
  signal?: AbortSignal,
): Promise<TraceTransaction> {
  return api.get<TraceTransaction>(
    `/mail-trace/transaction/${encodeURIComponent(transactionId)}`,
    signal,
  );
}

/** GET /mail-trace/transaction/:id/content — requires `trace:content` (403). */
export function getMessageContent(
  transactionId: string,
  signal?: AbortSignal,
): Promise<MessageContentData> {
  return api.get<MessageContentData>(
    `/mail-trace/transaction/${encodeURIComponent(transactionId)}/content`,
    signal,
  );
}

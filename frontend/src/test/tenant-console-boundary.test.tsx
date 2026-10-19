/**
 * Tenant console boundary guard.
 *
 * The customer-tier console is a product for one organisation's administrator,
 * not a read-only view of the platform. Every surface below renders inside the
 * real shell with the permission set the server publishes for `customer_admin`,
 * so platform vocabulary, a platform readout or a platform-only action that
 * appears in a tenant render fails this file instead of reaching an operator.
 * It is a copy and placement tripwire, not the authorization boundary: the API
 * still re-authorizes every request.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { FC } from "react";

import { Layout } from "../components/Layout";
import { AdminUsers } from "../pages/AdminUsers";
import { AuditLog } from "../pages/AuditLog";
import { Customers } from "../pages/Customers";
import { Dashboard } from "../pages/Dashboard";
import { DomainSecurity } from "../pages/DomainSecurity";
import { FeatureOverrides } from "../pages/FeatureOverrides";
import { Messages } from "../pages/Messages";
import { MessageDetail } from "../pages/MessageDetail";
import { OutboundIntelligence } from "../pages/OutboundIntelligence";
import { Policies } from "../pages/Policies";
import { PolicyFamilyDetail } from "../pages/PolicyFamilyDetail";
import { Quarantine } from "../pages/Quarantine";
import { QuarantineDetail } from "../pages/QuarantineDetail";
import { Roles } from "../pages/Roles";
import { Settings } from "../pages/Settings";
import type { Session } from "../auth/session";

/** Mirrors the `customer_admin` builtin grant set in `admin_rbac.rs`. */
const TENANT_PERMISSIONS = [
  "admin:users:manage",
  "audit:view",
  "audit:export",
  "quarantine:view",
  "quarantine:release",
  "admin:customers:view",
  "admin:domains:manage",
  "domain-security:view",
  "domain-security:manage",
  "outbound-intelligence:view",
  "outbound-intelligence:manage",
  "notifications:view",
  "notifications:manage",
  "policies:view",
  "policies:manage",
  "trace:view",
  "trace:content",
];

const tenantSession: Session = {
  authenticated: true,
  userId: "actor-tenant",
  email: "tenant-admin@example.test",
  roles: ["customer_admin"],
  tier: "customer",
  permissions: TENANT_PERMISSIONS,
  customerId: "CZA-1",
  expiresAt: "2099-01-01T00:00:00Z",
  csrfToken: "csrf-token",
  impersonation: null,
  // The server refuses role definition for any identity but the built-in
  // System Administrator, so a tenant console never sees an open gate.
  capabilities: {
    defineRoles: {
      allowed: false,
      blocker: "role",
    },
  },
};

/**
 * Words that describe the running platform rather than the tenant's own
 * sending. A customer administrator who reads them learns about a system they
 * do not operate.
 */
const PLATFORM_LANGUAGE: Array<{ term: string; pattern: RegExp }> = [
  { term: "platform", pattern: /\bplatform\b/i },
  { term: "deployment", pattern: /\bdeployment\b/i },
  { term: "installation", pattern: /\binstallation\b/i },
  { term: "system administrator", pattern: /\bsystem admin(istrator)?\b/i },
  { term: "system level", pattern: /\bsystem[- ]level\b/i },
  { term: "support level", pattern: /\bsupport[- ]level\b/i },
  { term: "needs a higher level", pattern: /\bNeeds (System|Support)\b/ },
  { term: "system_admin key", pattern: /system_admin/i },
  { term: "support role key", pattern: /support[-_](agent|viewer)/i },
  { term: "model registry", pattern: /\bmodel registry\b/i },
  { term: "deep ai", pattern: /\bdeep ai\b/i },
  // Which engine answers a check is a fact about the running platform. A
  // customer is told what the check found, never that a model, a classifier or
  // a named weights file produced it — this is the class the whole sweep exists
  // for, so it gets its own tripwire rather than relying on the projection.
  { term: "model word", pattern: /\bmodels?\b/i },
  {
    term: "engine or artifact name",
    pattern:
      /\b(?:qwen|llama|mistral|bert|yolo|onnx|safetensors|pytorch|torch|transformers|rspamd|milter|dovecot|amavis)\b/i,
  },
  {
    term: "inference machinery",
    pattern: /\b(?:classifier|classification model|inference|embedding|tokenizer|neural)\b/i,
  },
  { term: "parameter count", pattern: /\b\d+(?:\.\d+)?b\b/i },
  // The platform's own name for an administrator entering a customer. The
  // `impersonation` policy family is about inbound sender impersonation, which
  // is a tenant's own protection, so the bare word is not a leak.
  {
    term: "customer entry",
    pattern: /\b(customer entry|entered customer|impersonation session)\b/i,
  },
  { term: "cross-customer", pattern: /\bcross-customer\b/i },
  { term: "outbox", pattern: /\boutbox\b/i },
  { term: "dead letters", pattern: /\bdead letters?\b/i },
  // The component the platform runs the checks with. A customer reads what the
  // checks found, never that a scanner node, an engine or a scanner result is
  // what produced it.
  { term: "scanner", pattern: /\bscanner\b/i },
  { term: "fleet", pattern: /\bfleet\b/i },
  { term: "emergency stop", pattern: /\bemergency stop\b/i },
  // The mail server's own bookkeeping. These name the platform's machinery, not
  // the tenant's message, and the customer projection leaves them out.
  { term: "MTA name", pattern: /\bpostfix\b/i },
  { term: "MTA queue identifier", pattern: /\bqueue (id|reference)\b/i },
  { term: "content dedup hash", pattern: /\bcontent hash\b/i },
  { term: "log correlation id", pattern: /\btrace[_ -]id\b/i },
  // Authorization keys. The customer's own roles are described by what they
  // allow, never by the row in the platform's permission table.
  {
    term: "permission key",
    pattern:
      /\b(admin|audit|trace|policies|quarantine|notifications|domain-security|outbound-intelligence|operations|models|connectors|deep-ai|scanner):[a-z_-]+/i,
  },
  // The installation's own bookkeeping for where it filed a customer.
  { term: "surrogate row key", pattern: /\binternal key\b/i },
  // Machine identifiers. A snake_case token is how a platform table keys a row;
  // a tenant reads a human label for the same thing, so any hit here is a value
  // that reached the console without a naming layer over it. No word anchors:
  // `textContent` welds adjacent elements together, so a key rendered straight
  // after a heading has no boundary to match.
  { term: "machine key", pattern: /[a-z][a-z0-9]*(?:_[a-z0-9]+)+/ },
  // A primary key. The ledger's `resource_id` column holds one for rows about
  // the platform's own records (a session, another audit event), and a tenant
  // console that prints it is showing them a database row. The bare-hash branch
  // has no trailing anchor for the same reason the machine key above has none:
  // `textContent` welds `<strong>a3f19c…</strong><span>Campaign…</span>` together,
  // so a hash printed straight before a word has no boundary to end on.
  {
    term: "opaque row key",
    pattern:
      /\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?|urn:uuid:[0-9a-f-]{36}|[0-9a-f]{24,}/i,
  },
  // A value that never arrived. A console that prints the word is rendering a
  // field the service did not publish, which is what happened when the UI was
  // rebuilt ahead of the API that names a revision's publisher.
  { term: "missing value", pattern: /\b(?:undefined|NaN)\b/ },
  // A render that fell over. The sweep below only compares words on the page, so
  // an error boundary would scan as clean text and a surface that crashes on the
  // tenant's own answer could hide inside a green guard.
  { term: "crashed render", pattern: /\b(?:Something went wrong|Cannot read propert)/ },
];

/** The tenant's own organisation record, with no domains or groups set yet.
 *  Operational placement is not in the answer at all: the server publishes it
 *  only to a platform seat, and a customer read does not even show the slot.
 *  The tenant reads their derived customer ID instead. */
const customerRecord = {
  id: "CZA-1",
  display_name: "Acme Freight",
  lifecycle: "active",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  domain_count: 0,
  domains: [],
  source_ip_groups: [],
  capabilities: {
    create_customer: { allowed: false, blocker: null },
    change_lifecycle: { allowed: true, blocker: null },
    add_send_only_domain: { allowed: true, blocker: null },
  },
};

/**
 * The directory a tenant can actually reach: their own administrator plus an
 * account that still carries provider-level grants. Those grants are the rows
 * that used to print "System Administrator" and "Support Agent" inside a
 * customer console.
 */
const adminDirectory = [
  {
    id: "00000000-0000-0000-0000-0000000000a1",
    login: "tenant-admin@example.test",
    displayName: "Tenant Admin",
    customerId: "CZA-1",
    lifecycle: "active",
    roles: ["customer_admin"],
  },
  {
    id: "00000000-0000-0000-0000-0000000000a2",
    login: "legacy@example.test",
    displayName: "Legacy Operator",
    customerId: "CZA-1",
    lifecycle: "suspended",
    roles: ["customer_admin", "support_agent", "system_admin"],
  },
];

/**
 * Every level a platform console publishes. The server no longer answers a
 * customer seat with the higher levels, and this fixture deliberately keeps
 * answering: wording that only leaks once data arrives is still a leak, and a
 * guard that renders only the narrowed answer cannot tell whether the console
 * would stay clean if that narrowing regressed.
 */
const roleDirectory = [
  {
    roleKey: "system_admin",
    displayName: "System Administrator",
    description: "Full platform authority.",
    roleLevel: "system",
    builtin: true,
    permissions: ["admin:users:manage", "admin:impersonate", "models:view", "operations:view"],
    userCount: 1,
  },
  {
    roleKey: "support_agent",
    displayName: "Support Agent",
    description: "Cross-customer support work.",
    roleLevel: "support",
    builtin: true,
    permissions: ["admin:customers:view", "audit:cross-customer", "quarantine:view"],
    userCount: 2,
  },
  {
    roleKey: "customer_admin",
    displayName: "Customer Administrator",
    description: "Administers one customer.",
    roleLevel: "customer",
    builtin: true,
    permissions: TENANT_PERMISSIONS,
    userCount: 1,
  },
  {
    roleKey: "mailroom_triage",
    displayName: "Mailroom triage",
    description: "Releases quarantine for this organisation.",
    roleLevel: "customer",
    builtin: false,
    permissions: ["quarantine:view", "quarantine:release"],
    userCount: 1,
  },
];

const policyFamilies = [
  {
    family_key: "quarantine",
    display_name: "Quarantine handling",
    description: "What lands in quarantine and how it is released.",
    management_level: "customer",
    security_floor: false,
    revision_count: 1,
    active_revision: {
      revision_number: 3,
      // What the column stores is the publisher's row key; what a customer read
      // is handed is the name the server resolved for that seat.
      published_by: "8f14e45f-ea41-4334-b632-f1bc9c9c9e21",
      published_by_name: "Tenant Admin",
      published_at: "2026-09-30T08:00:00Z",
      scope_level: "customer",
    },
  },
  {
    family_key: "bulk_sending",
    display_name: "Bulk sending",
    description: "Rate limits for high-volume senders.",
    management_level: "support",
    security_floor: false,
    revision_count: 0,
    active_revision: null,
  },
  {
    family_key: "authentication",
    display_name: "Sender authentication",
    description: "SPF, DKIM and DMARC enforcement floors.",
    management_level: "system",
    security_floor: true,
    revision_count: 2,
    active_revision: {
      revision_number: 7,
      // A provider operator published this revision. The customer read names the
      // side they can ask, not an operator the console has no reason to show.
      published_by: "32e35eba-a628-484f-858e-03e4cce584f7",
      published_by_name: "Your provider",
      published_at: "2026-10-01T08:00:00Z",
      scope_level: "system",
    },
  },
];

/**
 * What the trace detail endpoint answers a customer seat with: the tenant's own
 * message facts, and none of the platform's machinery. The correlation id, the
 * node that accepted the mail, the content dedup hash and the mail server's
 * queue identifiers are absent rather than blanked.
 */
const tenantTrace = {
  transaction_id: "0f9d0a6b-1111-2222-3333-444455556666",
  direction: "inbound",
  envelope_sender: "newsletter@partner.example",
  message_id: "<20260106-0949@partner.example>",
  received_at: "2026-01-06T09:49:55Z",
  recipients: [{ address: "ops@acmefreight.example", orcpt: null, notify: null }],
  auth: { spf_result: "pass", dkim_result: "pass", dmarc_result: "pass", arc_result: null },
  postfix_queue_ids: [],
  instances: [
    {
      tenant_message_id: "7d2c4e6a-1111-2222-3333-444455556666",
      disposition: "delivered",
      remediation_type: null,
      created_at: "2026-01-06T09:49:58Z",
      updated_at: "2026-01-06T09:50:02Z",
    },
  ],
  delivery_attempts: [
    {
      attempt_number: 1,
      status: "delivered",
      smtp_code: "250",
      enhanced_code: "2.0.0",
      smtp_message: "250 2.0.0 accepted for delivery",
      scheduled_at: "2026-01-06T09:50:00Z",
      completed_at: "2026-01-06T09:50:02Z",
      next_retry_at: null,
      postfix_queue_id: null,
    },
  ],
  findings: [
    {
      id: "finding-1",
      severity: "high",
      category: "malware",
      description: "high malware evidence was recorded for this message.",
      check: "malware_analysis",
      false_positive: false,
      created_at: "2026-01-06T09:49:57Z",
    },
    {
      id: "finding-2",
      severity: "medium",
      category: "phishing",
      description: "medium phishing evidence was recorded for this message.",
      // A platform answer read by a tenant seat: the field name and the stored
      // scanner key both stay on purpose, so a projection regression fails here
      // instead of printing a machine key to an operator.
      scanner_type: "inline_ml",
      false_positive: false,
      created_at: "2026-01-06T09:49:58Z",
    },
  ],
  flow_stages: [
    { stage: "received", at: "2026-01-06T09:49:55Z" },
    { stage: "delivered", at: "2026-01-06T09:50:02Z" },
  ],
};

/**
 * Identifiers a tenant console is entitled to print, because they name the
 * customer's own mail rather than a row in the platform's database: a
 * transaction id is what the trace search box takes back, a message id is what
 * opens a quarantine case, and an audit event id is what an operator quotes when
 * they dispute a recorded action. They are the only opaque-shaped values the scan
 * lets through, and each one is a single constant shared with the fixtures that
 * serve it, so a payload cannot quietly disagree with the allowlist and stop
 * being tested.
 */
const tenantEventId = "6b1f9d2e-4c3a-4f57-9a11-2b3c4d5e6f70";

const CUSTOMER_MAIL_HANDLES = [
  tenantTrace.transaction_id,
  ...tenantTrace.instances.map((instance) => instance.tenant_message_id),
  tenantEventId,
];

function withoutCustomerHandles(text: string): string {
  return CUSTOMER_MAIL_HANDLES.reduce((seen, handle) => seen.split(handle).join(" "), text);
}

/**
 * What the held-message detail answers a customer seat with. The check names are
 * the ones the server's capability label publishes ("Malware analysis", not the
 * engine behind it), and the engine's own bookkeeping — whether a check was
 * mandatory and how long the node took — is a platform health read. The page
 * must not render either.
 */
const tenantHeldMessage = {
  tenant_message_id: "7d2c4e6a-1111-2222-3333-444455556666",
  transaction_id: "0f9d0a6b-1111-2222-3333-444455556666",
  reason_code: "QUARANTINE_PHISHING",
  sender: "billing@partner.example",
  recipient_count: 2,
  findings: [
    {
      id: "1",
      category: "credential_harvest",
      severity: "high",
      description: "A link asks for credentials on a domain this organisation does not own",
      created_at: "2026-01-06T09:49:57Z",
    },
  ],
  quarantined_at: "2026-01-06T09:49:58Z",
  released_at: null,
  release_allowed: true,
  released_by: null,
  release_reason: null,
  retention: {
    retention_class: "standard",
    artifact_created_at: "2026-01-06T09:49:56Z",
    quarantined_at: "2026-01-06T09:49:58Z",
    released_at: null,
  },
  scanner_results: [
    {
      capability: "Malware analysis",
      // A platform answer read by a tenant seat: the status token, the
      // requirement and the wall clock all stay here on purpose, and there is no
      // outcome key, so a projection regression shows up as a machine word on the
      // page rather than a passing render.
      status: "healthy",
      required: true,
      duration_ms: 41,
      completed_at: "2026-01-06T09:49:57Z",
    },
    {
      capability: "URL reputation",
      outcome: "suspicious_found",
      completed_at: "2026-01-06T09:49:57Z",
    },
  ],
  audit: [
    {
      action: "quarantine_hold_reviewed",
      actor_login: "tenant-admin@example.test",
      result: "success",
      created_at: "2026-01-06T10:15:00Z",
    },
  ],
};

/**
 * What `GET /features` answers on a customer seat. It is a real read now, not a
 * platform read: the API authorizes a tenant session to write its own
 * Customer-scope overrides, so the console lists them. This fixture is the
 * projection, not the operator one — no description, no security floor or
 * emergency stop flags, no scope above the tenant's own, no override rows
 * written by anyone else, and a `governed_by` outcome word where the ladder
 * position is withheld. It still carries the raw `feature_id`, because that is
 * what the write path is addressed by; the guard below proves the console never
 * prints it.
 */
const customerFeatureList = {
  features: [
    {
      feature_id: "outbound_bulk_guard",
      display_name: "Bulk sending limits",
      default_value: "enabled",
      allowed_scopes: ["tenant"],
      effective_value: "typed:rate_limit=10",
      governed_by: "you",
      overrides: [
        {
          id: 118,
          scope: "tenant",
          scope_id: "CZA-1",
          value: "typed:rate_limit=10",
          owner: "00000000-0000-0000-0000-0000000000a1",
          owner_display_name: "Tenant Admin",
          reason: "Weekend campaign lift",
          revision: 3,
          created_at: "2026-01-05T09:00:00Z",
          expires_at: "2026-02-01T00:00:00Z",
        },
      ],
    },
    {
      feature_id: "deep_ai_analysis",
      display_name: "Message content review",
      default_value: "enabled",
      allowed_scopes: ["tenant"],
      effective_value: "enabled",
      governed_by: "provider",
      overrides: [],
    },
  ],
  allowed_override_scopes: ["tenant"],
};

/**
 * Payloads are the smallest valid answer each page can render, and they carry
 * real rows wherever platform vocabulary exists anywhere in the installation:
 * the role directory includes system and support roles even though the server
 * now stops a customer's answer at the levels that seat may grant, an
 * administrator still holds them, and the policy queue mixes all three
 * management levels. Wording that only leaks once data arrives is still a leak.
 * The permission catalog is the one read stubbed empty, because the console must
 * never ask for it at all and a `PLATFORM_READS` assertion below proves it does
 * not; a payload there would only ever be answered by a page that should not
 * exist.
 */
const PAYLOADS: Array<[string, unknown]> = [
  ["/auth/session", tenantSession],
  // Ordering matters: the stub answers the first needle the URL contains, and a
  // case detail URL also contains the list URL.
  ["/quarantine/7d2c4e6a-1111-2222-3333-444455556666", tenantHeldMessage],
  ["/quarantine", []],
  ["/admin/users", adminDirectory],
  ["/admin/roles", roleDirectory],
  ["/admin/permissions", []],
  [
    `/audit/events/${tenantEventId}`,
    {
      id: tenantEventId,
      created_at: "2026-01-06T09:57:00Z",
      actor_login: "tenant-admin@example.test",
      actor_roles: ["customer_admin"],
      impersonated_subject: null,
      impersonated_customer: null,
      customer_id: "CZA-1",
      action: "policy_published",
      resource_type: "policy_family",
      resource_id: "bulk_sending",
      result: "success",
      reason: null,
      source_ip: "192.168.8.232",
      trace_id: null,
      session_id: null,
      // What a customer's audit read is actually handed: the projection has
      // already dropped the platform's own fields (filters, identity, scope) and
      // the structures it cannot render. What is left still stores machine keys
      // and machine values, because that is what the ledger holds.
      details: [
        { key: "family_key", value: "ml_threat_classification" },
        { key: "reason_code", value: "QUARANTINE_MALWARE" },
        { key: "row_count", value: "50" },
        { key: "scope_level", value: "tenant" },
      ],
    },
  ],
  [
    "/audit/events",
    {
      events: [
        {
          id: "4a71b2c8-9d15-42e6-b7f0-1c3d5e7f9a11",
          created_at: "2026-01-06T09:58:00Z",
          actor_login: "ob1",
          actor_roles: ["system_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "policy_detail",
          resource_type: "policy_family",
          resource_id: "bulk_sending",
          result: "denied",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
        {
          // The row the detail test opens, so its key is both the handle the
          // dialog prints and the needle the stub answers that read with.
          id: tenantEventId,
          created_at: "2026-01-06T09:57:00Z",
          actor_login: "tenant-admin@example.test",
          actor_roles: ["customer_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "session_login",
          resource_type: "session",
          // What the column actually holds: the primary key of the platform's
          // own session row. The tenant reads the login, not the key.
          resource_id: "86538d62-3b7d-4003-a7e6-740341e252f1",
          result: "success",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
        {
          id: "9c1e7b40-5a2d-4f08-b6c3-8d47e2f1a906",
          created_at: "2026-01-06T09:56:00Z",
          actor_login: "tenant-admin@example.test",
          actor_roles: ["customer_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "outbound_bulk_sender_upserted",
          resource_type: "approved_bulk_sender",
          resource_id: "news@acmefreight.example:smtp_mta:office-vpn",
          result: "success",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
        {
          id: "d38b5c02-71e4-4a9f-8b0d-6f2c51a7e944",
          created_at: "2026-01-06T09:55:00Z",
          actor_login: "tenant-admin@example.test",
          actor_roles: ["customer_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "audit_access_detail",
          // The ledger checkpoint is the installation's own seal; a row that
          // names it must not print the reference to the tenant.
          resource_type: "audit",
          resource_id: "checkpoint-status",
          result: "success",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
        {
          id: "70f2a9c6-4b18-4d63-95e0-2a1c8d6b3f57",
          created_at: "2026-01-06T09:54:00Z",
          actor_login: "tenant-admin@example.test",
          actor_roles: ["customer_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "audit_access_detail",
          // Reading one event records the key of the event read. The tenant has
          // that row in their own list; the primary key says nothing more.
          resource_type: "audit",
          resource_id: "17b90409-291d-4333-962f-4b199e3a437f",
          result: "success",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
      ],
      next_cursor: null,
    },
  ],
  // The stub matches the first needle contained in the URL, so the more
  // specific read has to precede the record it is filed under.
  // The stub matches the first needle contained in the URL, so the more
  // specific read has to precede the record it is filed under.
  ["/admin/customers/CZA-1/source-ip-groups", { groups: [] }],
  ["/admin/customers/CZA-1", customerRecord],
  ["/admin/customers", { customers: [] }],
  [
    "/domain-security",
    {
      generated_at: "2026-01-06T10:00:00Z",
      summary: {
        domains_total: 1,
        verified_domains: 1,
        messages_30d: 0,
        dmarc_aligned_messages_30d: 0,
        unknown_sources: 0,
        report_authorization_broken: 0,
        bimi_not_ready: 0,
        open_notifications: 0,
      },
      domains: [
        {
          id: "3c2c4e6a-1111-2222-3333-444455556666",
          domain: "acmefreight.example",
          domain_type: "sending",
          verification_status: "verified",
          dmarc: {
            latest_policy: "none",
            reports_30d: 4,
            messages_30d: 120,
            aligned_messages_30d: 118,
            rejected_or_quarantined_messages_30d: 0,
          },
          report_authorization: null,
          bimi: null,
          observations: [],
          sources: [],
          next_actions: [],
        },
      ],
      notifications: [],
      recent_acknowledgments: [],
    },
  ],
  [
    "/notifications/settings",
    {
      generated_at: "2026-01-06T10:00:00Z",
      settings: {
        enabled: true,
        severity_floor: "warning",
        recipient_emails: ["postmaster@acmefreight.example"],
        digest_window_minutes: 60,
        updated_by: "ob2-customer-admin",
        updated_at: "2026-01-06T09:00:00Z",
      },
      effective: {
        enabled: true,
        severity_floor: "warning",
        recipient_count: 1,
        digest_window_minutes: 60,
        deliverable: true,
      },
      verified_domains: ["acmefreight.example"],
      deliveries: [
        {
          notification_id: "notice-1",
          status: "sent",
          recipient_count: 1,
          attempts: 1,
          reason: null,
          // The mail server's queue reference is a platform key: the customer
          // answer carries no such field at all.
          created_at: "2026-01-06T09:00:00Z",
          updated_at: "2026-01-06T09:01:00Z",
        },
      ],
      capabilities: {
        update_settings: { allowed: true, blocker: null },
      },
    },
  ],
  [
    "/outbound-intelligence",
    {
      generated_at: "2026-01-06T10:00:00Z",
      summary: {
        messages_1h: 0,
        recipients_1h: 0,
        unique_recipients_1h: 0,
        active_senders_1h: 0,
        campaigns_observed: 0,
        approved_bulk_senders: 0,
        open_security_events: 0,
        critical_security_events: 0,
      },
      approved_senders: [
        {
          id: "7d2c4e6a-1111-2222-3333-444455556666",
          sender_address: "news@acmefreight.example",
          sending_domain: "acmefreight.example",
          source_kind: "ip_group",
          source_id: "Office VPN",
          source_ip: null,
          max_messages_per_minute: 100,
          max_messages_per_hour: 2000,
          max_recipients_per_message: 500,
          max_unique_recipients_per_hour: 20000,
          active: true,
          reason: "Approved newsletter volume",
          approved_by: "ob1",
          updated_at: "2026-01-06T09:00:00Z",
          expires_at: null,
        },
      ],
      sender_behaviour: [],
      campaigns: [
        {
          // The platform's own answer: a content hash plus the matcher that
          // grouped it. Both name machinery, and the customer projection leaves
          // both keys off the wire entirely.
          fingerprint: "a3f19c0d2b7e48c1f6d0a5b2c9e4f1a3",
          algorithm: "rspamd_fuzzy",
          message_count: 12,
          recipient_count: 340,
          disposition: "throttled",
          first_seen_at: "2026-01-06T08:50:00Z",
          last_seen_at: "2026-01-06T09:30:00Z",
        },
      ],
      security_events: [
        {
          id: "9c2c4e6a-1111-2222-3333-444455556666",
          event_type: "bulk_volume_spike",
          severity: "warning",
          outcome: "throttled",
          reason_code: "bulk_rate_exceeded",
          sender_address: "news@acmefreight.example",
          source_id: "Office VPN",
          campaign_fingerprint: "a3f19c0d2b7e48c1f6d0a5b2c9e4f1a3",
          status: "open",
          message_count: 12,
          first_seen_at: "2026-01-06T09:00:00Z",
          last_seen_at: "2026-01-06T09:30:00Z",
          cooldown_until: null,
          // The provider's own runbook reference and remediation prose: the
          // customer projection withholds both.
          remediation_runbook: null,
          remediation_summary: null,
          credential_rotation_recommended: false,
        },
      ],
      policy_history: [
        {
          id: "history-sender-approval",
          action: "outbound_bulk_sender_upserted",
          actor_login: "tenant-admin@example.test",
          // The audit row keys an approved sender as a composite machine
          // reference. The tenant reads the sender, not the key.
          resource_id: "news@acmefreight.example:smtp_mta:office-vpn",
          result: "success",
          created_at: "2026-01-06T09:40:00Z",
        },
      ],
    },
  ],
  [
    "/policies/outbound_senders",
    {
      family: {
        family_key: "outbound_senders",
        display_name: "Outbound sender approvals",
        description: "Which sources may send as this customer.",
        management_level: "customer",
        security_floor: false,
        revision_count: 0,
        active_revision: null,
      },
      revisions: [],
      caller_tier: "customer",
      profile: {
        enforcement: { mode: "none", summary: "No rule is published for this family yet." },
        conditions: [],
        metadata: {
          read: false,
          exact_keys: false,
          metadata_optional: true,
          merge: "none",
          fields: [],
        },
      },
    },
  ],
  ["/mail-trace/transaction", tenantTrace],
  ["/features", customerFeatureList],
  ["/policies", { families: policyFamilies, caller_tier: "customer" }],
];

/**
 * One string each term is supposed to catch. The list is keyed by `term`, so a
 * term added without a sample — or a sample whose term has been renamed — fails
 * the completeness test below, and a term whose pattern no longer matches its
 * own sample fails with it. This exists because a guard term whose shape is
 * wrong is indistinguishable from a clean console: the audit fixtures used to be
 * keyed `event-tenant`, which no opaque-identifier pattern can ever match.
 */
const TERM_SAMPLES: Array<[string, string]> = [
  ["platform", "The platform keeps the archive signing key."],
  ["deployment", "This deployment runs the milter on one node."],
  ["installation", "The installation seal is current."],
  ["system administrator", "Only a system administrator may publish this."],
  ["system level", "Managed at the system level."],
  ["support level", "A support level edit is required."],
  ["needs a higher level", "Needs System to change."],
  ["system_admin key", "Granted to system_admin only."],
  ["support role key", "Held by support_agent seats."],
  ["model registry", "Approve it in the model registry first."],
  ["deep ai", "Deep AI analysis produced this finding."],
  ["customer entry", "Reached through customer entry."],
  ["cross-customer", "A cross-customer read is refused."],
  ["outbox", "12 rows are waiting in the outbox."],
  ["dead letters", "Moved to dead letters after nine tries."],
  ["scanner", "The scanner node did not answer."],
  ["fleet", "Fleet health is nominal."],
  ["emergency stop", "Emergency stop is engaged for this family."],
  ["MTA name", "Postfix accepted the envelope."],
  ["MTA queue identifier", "Held with queue id 4A2F1B8C3D."],
  ["content dedup hash", "Matched by content hash."],
  ["log correlation id", "Quote trace_id when you contact us."],
  ["permission key", "This needs quarantine:release."],
  ["surrogate row key", "Filed under internal key 118."],
  ["machine key", "Family ml_threat_classification."],
  [
    "opaque row key",
    "seen a3f19c0d2b7e48c1f6d0a5b2c9e4f1a3Campaign rule 9c4279a2-0d8e-455a-94c4-7c496786df12.",
  ],
  ["missing value", "Published by undefined on Tuesday."],
  ["crashed render", "Something went wrong while this screen was drawn."],
  ["model word", "The model flagged the link."],
  ["engine or artifact name", "Weighted by qwen, matched by Rspamd, served from an ONNX file."],
  ["inference machinery", "A classifier scored the body text."],
  ["parameter count", "The 27B weights were loaded at boot."],
];

function stubTenantFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    for (const [needle, payload] of PAYLOADS) {
      if (url.includes(needle)) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({ data: payload }) };
      }
    }
    return {
      ok: false,
      status: 501,
      statusText: "Not Implemented",
      json: async () => ({ error: { code: "NOT_IMPLEMENTED", message: "Not a tenant read." } }),
    };
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

/**
 * Reads that belong to the running platform. None of them has a tenant answer,
 * so a customer session must not issue them at all. The permission catalog is
 * here because it lists every permission the installation publishes, including
 * ones no tenant role can hold; only the role-definition dialog reads it, and a
 * customer console cannot open that dialog.
 *
 * `/features` used to be on this list. It is not: a customer session may write
 * its own Customer-scope overrides, so the read is a tenant read and the payload
 * above is what the server actually hands that seat.
 */
const PLATFORM_READS = [
  "/operations/runtime",
  "/scanner-operations",
  "/deep-ai",
  "/connectors",
  "/models",
  "/audit/checkpoint-status",
  "/admin/permissions",
];

interface Surface {
  name: string;
  /** Route pattern declared in the test tree. */
  path: string;
  /** URL the guard renders at. */
  entry: string;
  component: FC;
  /**
   * A label that only exists once this surface's own read has painted. The scan
   * below takes `document.body.textContent`, and the session chip settles before
   * a page's tables do, so without this a surface could scan green purely because
   * its rows had not rendered yet.
   */
  ready?: string;
}

const SURFACES: Surface[] = [
  { name: "Overview", path: "/", entry: "/", component: Dashboard },
  {
    name: "Domain security",
    path: "/domain-security",
    entry: "/domain-security",
    component: DomainSecurity,
  },
  {
    name: "Outbound",
    path: "/outbound-intelligence",
    entry: "/outbound-intelligence",
    component: OutboundIntelligence,
    ready: "news@acmefreight.example",
  },
  { name: "Quarantine", path: "/quarantine", entry: "/quarantine", component: Quarantine },
  {
    name: "Held message",
    path: "/quarantine/$tenant_message_id",
    entry: "/quarantine/7d2c4e6a-1111-2222-3333-444455556666",
    component: QuarantineDetail,
    ready: "Something suspicious",
  },
  { name: "Messages", path: "/messages", entry: "/messages", component: Messages },
  {
    name: "Message trace",
    path: "/messages/$messageId",
    entry: "/messages/0f9d0a6b-1111-2222-3333-444455556666",
    component: MessageDetail,
    ready: "high malware evidence was recorded for this message.",
  },
  { name: "Audit log", path: "/audit-log", entry: "/audit-log", component: AuditLog },
  {
    name: "Administrators",
    path: "/admin-users",
    entry: "/admin-users",
    component: AdminUsers,
  },
  { name: "Roles", path: "/roles", entry: "/roles", component: Roles },
  { name: "Policies", path: "/policies", entry: "/policies", component: Policies },
  {
    name: "Policy family",
    path: "/policies/$familyKey",
    entry: "/policies/outbound_senders",
    component: PolicyFamilyDetail,
  },
  {
    name: "Feature settings",
    path: "/policies/features",
    entry: "/policies/features",
    component: FeatureOverrides,
  },
  { name: "Settings", path: "/settings", entry: "/settings", component: Settings },
  {
    name: "Your organisation",
    path: "/customers",
    entry: "/customers",
    component: Customers,
  },
];

/** Every path the shell links to, so its nav renders without dangling links. */
const SHELL_PATHS = [
  "/operations",
  "/scanner-operations",
  "/deep-ai",
  "/connectors-remediation",
  "/models",
];

function surfaceNamed(name: string): Surface {
  const surface = SURFACES.find((item) => item.name === name);
  if (surface === undefined) throw new Error(`No surface named ${name}`);
  return surface;
}

function renderSurface(surface: Surface) {
  const rootRoute = createRootRoute({ component: Layout });
  const Blank = () => <div />;
  const routeTree = rootRoute.addChildren([
    ...SURFACES.map((item) =>
      createRoute({
        getParentRoute: () => rootRoute,
        path: item.path,
        component: item.component,
      }),
    ),
    ...SHELL_PATHS.map((path) =>
      createRoute({ getParentRoute: () => rootRoute, path, component: Blank }),
    ),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [surface.entry] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("tenant console boundary", () => {
  beforeAll(() => {
    // The shell keeps the active nav row in view; jsdom does not implement it.
    Element.prototype.scrollIntoView = () => {};
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
    vi.stubGlobal("matchMedia", (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));
  });

  beforeEach(() => {
    // The shell watches the nav for overflow; jsdom implements neither.
    class Observer {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    vi.stubGlobal("ResizeObserver", Observer);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each(SURFACES.map((surface) => [surface.name, surface] as const))(
    "%s renders no platform language for a customer session",
    async (_name, surface) => {
      const fetchMock = stubTenantFetch();
      renderSurface(surface);
      // The shell's session chip is the settle point: it only reads "Your
      // customer" once the session has resolved, so the scan below runs on the
      // tier-aware render rather than on the pending one.
      await screen.findByText("Your customer · CZA-1");
      if (surface.ready !== undefined) {
        // The session chip settles first. Wait for something only the surface's
        // own read paints, or the scan runs against a loading state.
        await screen.findAllByText(surface.ready);
      }

      const text = withoutCustomerHandles(document.body.textContent ?? "");
      const leaks: string[] = [];
      for (const { term, pattern } of PLATFORM_LANGUAGE) {
        // Every match, not the first: a page with three machine keys left on it
        // is three findings, and the count tells the next reader how deep the
        // leak runs.
        const global = new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`);
        for (const hit of text.matchAll(global)) {
          const from = Math.max(0, hit.index - 60);
          leaks.push(`"${term}" in: …${text.slice(from, hit.index + 60)}…`);
        }
      }
      expect(leaks, `${surface.entry} renders platform language`).toEqual([]);

      // Fleet health, the runtime, the model registry, connector remediation and
      // the audit checkpoint are platform reads. A console that shows none of
      // them must not ask for any of them either.
      const requested = fetchMock.mock.calls.map(([input]) => String(input));
      for (const forbidden of PLATFORM_READS) {
        expect(
          requested.filter((url) => url.includes(forbidden)),
          `${surface.entry} makes a platform read: ${forbidden}`,
        ).toEqual([]);
      }
    },
  );

  /**
   * A term that cannot match anything is indistinguishable from a clean console,
   * which is how the opaque-key blind spot survived a green suite. Each term has
   * to name a leak it actually catches, and no term may join the list without
   * one.
   */
  it("has a sample and a working pattern for every platform term", () => {
    const sampleFor = new Map(TERM_SAMPLES);
    const terms = new Set(PLATFORM_LANGUAGE.map(({ term }) => term));

    expect([...terms].filter((term) => !sampleFor.has(term))).toEqual([]);
    expect([...sampleFor.keys()].filter((term) => !terms.has(term))).toEqual([]);

    const dead = PLATFORM_LANGUAGE.filter(
      ({ term, pattern }) => !pattern.test(sampleFor.get(term)!),
    ).map(({ term }) => term);
    expect(dead, "these terms do not match the leak they name").toEqual([]);
  });

  /**
   * The scans above only mean something if the server rows actually reached the
   * render. These three assertions fail if a page errors instead of painting, or
   * if the directory stops arriving, so a future stub cannot make the guard
   * vacuously green.
   */
  it("reaches the render with the provider rows the role directory carries", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Roles"));
    await screen.findByText("Your customer · CZA-1");

    expect(await screen.findByText("Customer Administrator")).toBeInTheDocument();
    expect(screen.getByText("Mailroom triage")).toBeInTheDocument();
    expect(screen.queryByText("System Administrator")).not.toBeInTheDocument();
    expect(screen.queryByText("Support Agent")).not.toBeInTheDocument();
  });

  /**
   * The customer's own feature switches are a real tenant surface now, so the
   * same blind-spot check applies: the rows have to reach the render, and the
   * handle the write path is addressed by must stay off the page.
   */
  it("reaches the render with the customer's own feature rows", async () => {
    const fetchMock = stubTenantFetch();
    renderSurface(surfaceNamed("Feature settings"));
    await screen.findByText("Your customer · CZA-1");

    expect(await screen.findByText("Bulk sending limits")).toBeInTheDocument();
    expect(screen.getByText("Message content review")).toBeInTheDocument();
    expect(screen.getByText("On for your sending")).toBeInTheDocument();
    expect(screen.getByText("Your setting")).toBeInTheDocument();
    // The typed value shows once as the value in force and once on the row that
    // produced it.
    expect(screen.getAllByText(/rate_limit=10/)).toHaveLength(2);
    expect(screen.queryByText("outbound_bulk_guard")).not.toBeInTheDocument();
    expect(screen.queryByText("deep_ai_analysis")).not.toBeInTheDocument();
    // The read is a tenant read, and it happened.
    expect(
      fetchMock.mock.calls.filter(([input]) => String(input).includes("/features")),
    ).toHaveLength(1);
  });

  it("reaches the render with the provider rows the policy queue carries", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Policies"));
    await screen.findByText("Your customer · CZA-1");

    expect(await screen.findByText("Sender authentication")).toBeInTheDocument();
    expect(screen.getByText("Bulk sending limits")).toBeInTheDocument();
    // The bucket word is both a filter chip and the per-row answer, so each one
    // appears more than once; only its absence would be a problem.
    expect(screen.getAllByText("Needs your provider").length).toBeGreaterThan(1);
    expect(screen.getAllByText("Yours to change").length).toBeGreaterThan(1);
  });

  it("renames a provider-level grant instead of echoing its role key", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Administrators"));
    await screen.findByText("Your customer · CZA-1");

    const row = await screen.findByText("legacy@example.test");
    expect(row.closest("tr")?.textContent).toContain("Provider-level role");
    expect(row.closest("tr")?.textContent).not.toMatch(/system_admin|System Administrator/);
  });

  /**
   * The organisation record is the one tenant surface that used to carry the
   * platform's placement numbers. The server answer now omits those keys, and
   * the console has to treat an absent number as "not published" rather than as
   * a slot to fill in with a word.
   */
  it("shows the tenant's own record without the platform's placement", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Your organisation"));
    await screen.findByText("Your customer · CZA-1");

    const record = await screen.findByText("Acme Freight");
    expect(record.textContent).toBeTruthy();
    expect(screen.getByText("CZA-1")).toBeInTheDocument();
    expect(screen.queryByText("Internal key")).not.toBeInTheDocument();
    expect(screen.queryByText("Not placed")).not.toBeInTheDocument();
    expect(screen.queryByText("Not assigned")).not.toBeInTheDocument();
  });

  it("names a provider actor in the audit log as the provider", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Audit log"));
    await screen.findByText("Your customer · CZA-1");

    // The actor stays visible: a tenant is entitled to know that someone from
    // outside their organisation touched their record. Only the ladder is renamed.
    const provider = (await screen.findByText("ob1")).closest("tr");
    expect(provider?.textContent).toContain("Provider");
    expect(provider?.textContent).not.toMatch(/system_admin|System admin/);

    const own = screen.getAllByText("Customer admin")[0].closest("tr");
    expect(own?.textContent).toContain("tenant-admin@example.test");
  });

  it("lists a provider family without offering a link that refuses", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Policies"));
    await screen.findByText("Your customer · CZA-1");

    expect((await screen.findByText("Quarantine handling")).closest("a")).not.toBeNull();
    // Opening one of these 403s and writes a Denied row into the tenant's own
    // audit log, so the name is a fact about the account, not a dead-end link.
    // A tenant family reads in the console's own words, so a catalog name that
    // describes the engine ("ML threat classification") is not what they see.
    for (const name of ["Bulk sending limits", "Sender authentication"]) {
      expect(screen.getByText(name).closest("a")).toBeNull();
    }
    expect(screen.queryByText("Bulk sending")).toBeNull();
  });

  /**
   * The event detail is the one place the ledger's own vocabulary arrives in the
   * console, and it arrives as stored: a column name and the value written into
   * it. The server has already removed the fields that describe its machinery;
   * what is left is named here, in the words the rest of the tenant's console
   * uses for the same thing.
   */
  it("names an audit event's stored fields instead of printing its columns", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Audit log"));
    await screen.findByText("Your customer · CZA-1");

    fireEvent.click(await screen.findByText("1/6/2026, 11:57:00 AM"));
    expect(await screen.findByText("Mail policy")).toBeInTheDocument();

    const text = document.body.textContent ?? "";
    expect(text).toContain("Automatic threat review");
    expect(text).toContain("Your organisation");
    expect(text).not.toMatch(/[a-z][a-z0-9]*(?:_[a-z0-9]+)+/);
    expect(text).not.toMatch(/\{|"/);
  });

  /**
   * A revision history has to say who published the revision. The stored
   * reference is a row key in the platform's user table, so the customer read
   * takes the name the server resolved for their seat: their own administrator,
   * or the side of the house they can actually ask.
   */
  it("names a revision's publisher instead of its user row key", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Policies"));
    await screen.findByText("Your customer · CZA-1");

    expect(await screen.findByText(/#3 · by Tenant Admin/)).toBeInTheDocument();
    expect(screen.getByText(/#7 · by Your provider/)).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toMatch(
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
    );
  });

  /**
   * Rows about the platform's own records key the record they touched. The
   * tenant's log says a login happened and which policy was read; the primary
   * key underneath it is theirs to act on nowhere.
   */
  it("withholds a database row key from a tenant's evidence reference", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Audit log"));
    await screen.findByText("Your customer · CZA-1");

    await screen.findByText("Session login");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    // Anti-vacuous: the rows are rendered, they simply carry no reference. A
    // sender the customer approved keeps its address.
    expect(text).toContain("news@acmefreight.example");
  });

  /**
   * A held message is decided by what the checks found. Which component ran
   * them, whether that component was mandatory and how long its node took are
   * health readings of the platform, so a tenant's case detail shows the
   * capability the server named and the outcome, nothing else.
   */
  it("describes a held message's checks as outcomes, not as the platform's machinery", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Held message"));
    await screen.findByText("Your customer · CZA-1");

    expect(await screen.findByText("Security checks")).toBeInTheDocument();
    expect(screen.getByText("Malware analysis")).toBeInTheDocument();
    expect(screen.getByText("High: Credential harvesting")).toBeInTheDocument();
    expect(screen.queryByText("Requirement")).toBeNull();
    expect(screen.queryByText("Duration")).toBeNull();
    expect(screen.queryByText(/required/i)).toBeNull();

    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/\d+\s*ms/);
    expect(text).not.toMatch(/scanner/i);
  });
});

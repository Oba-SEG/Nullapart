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
import { render, screen } from "@testing-library/react";
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
  { term: "scanner node", pattern: /\bscanner node/i },
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
];

/** The tenant's own organisation record, with no domains or groups set yet.
 *  Operational placement is null because the server publishes it only to a
 *  platform seat; the tenant reads its derived customer ID instead. */
const customerRecord = {
  id: "CZA-1",
  display_name: "Acme Freight",
  internal_key: null,
  region_code: null,
  sequence_no: null,
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

/** Every level the server publishes, so a filter or badge cannot hide behind an empty list. */
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
      published_by: "tenant-admin@example.test",
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
      published_by: "ob1",
      published_at: "2026-10-01T08:00:00Z",
      scope_level: "system",
    },
  },
];

/**
 * Payloads are the smallest valid answer each page can render, and they carry
 * real rows wherever the server would publish platform vocabulary: the role
 * directory includes system and support roles, an administrator still holds
 * them, and the policy queue mixes all three management levels. Wording that
 * only leaks once data arrives is still a leak.
 */
/**
 * What the trace detail endpoint answers a customer seat with: the tenant's own
 * message facts, and none of the platform's machinery. The correlation id, the
 * node that accepted the mail, the content dedup hash and the mail server's
 * queue identifiers are absent rather than blanked.
 */
const tenantTrace = {
  transaction_id: "0f9d0a6b-1111-2222-3333-444455556666",
  trace_id: null,
  direction: "inbound",
  deployment_id: null,
  envelope_sender: "newsletter@partner.example",
  message_id: "<20260106-0949@partner.example>",
  content_hash: null,
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
  findings: [],
  flow_stages: [
    { stage: "received", at: "2026-01-06T09:49:55Z" },
    { stage: "delivered", at: "2026-01-06T09:50:02Z" },
  ],
};

const PAYLOADS: Array<[string, unknown]> = [
  ["/auth/session", tenantSession],
  ["/quarantine", []],
  ["/admin/users", adminDirectory],
  ["/admin/roles", roleDirectory],
  ["/admin/permissions", []],
  [
    "/audit/events",
    {
      events: [
        {
          id: "event-provider",
          created_at: "2026-01-06T09:58:00Z",
          actor_login: "ob1",
          actor_roles: ["system_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "policy_detail",
          resource_type: "policy_family",
          resource_id: "malware",
          result: "denied",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
        {
          id: "event-tenant",
          created_at: "2026-01-06T09:57:00Z",
          actor_login: "tenant-admin@example.test",
          actor_roles: ["customer_admin"],
          impersonated_subject: null,
          impersonated_customer: null,
          customer_id: "CZA-1",
          action: "session_login",
          resource_type: "session",
          resource_id: "session-tenant",
          result: "success",
          reason: null,
          source_ip: "192.168.8.232",
          trace_id: null,
        },
      ],
      next_cursor: null,
    },
  ],
  ["/admin/customers/CZA-1", customerRecord],
  ["/admin/customers", { customers: [] }],
  [
    "/domain-security",
    {
      deployment_id: null,
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
      deployment_id: null,
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
          // The mail server's queue reference: platform seats only.
          outbound_transaction_id: null,
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
      deployment_id: null,
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
      campaigns: [],
      security_events: [
        {
          id: "9c2c4e6a-1111-2222-3333-444455556666",
          event_type: "bulk_volume_spike",
          severity: "warning",
          outcome: "throttled",
          reason_code: "bulk_rate_exceeded",
          sender_address: "news@acmefreight.example",
          source_id: "Office VPN",
          campaign_fingerprint: null,
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
      policy_history: [],
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
  ["/policies", { families: policyFamilies, caller_tier: "customer" }],
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
 */
const PLATFORM_READS = [
  "/operations/runtime",
  "/scanner-operations",
  "/deep-ai",
  "/connectors",
  "/models",
  "/features",
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
  },
  { name: "Quarantine", path: "/quarantine", entry: "/quarantine", component: Quarantine },
  { name: "Messages", path: "/messages", entry: "/messages", component: Messages },
  {
    name: "Message trace",
    path: "/messages/$messageId",
    entry: "/messages/0f9d0a6b-1111-2222-3333-444455556666",
    component: MessageDetail,
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
    name: "Feature overrides",
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

      const text = document.body.textContent ?? "";
      const leaks: string[] = [];
      for (const { term, pattern } of PLATFORM_LANGUAGE) {
        const hit = text.match(pattern);
        if (hit === null) continue;
        const from = Math.max(0, (hit.index ?? 0) - 60);
        leaks.push(`"${term}" in: …${text.slice(from, (hit.index ?? 0) + 60)}…`);
      }
      expect(leaks, `${surface.entry} renders platform language`).toEqual([]);

      // Fleet health, the runtime, the model registry, connector remediation,
      // the rollout catalog and the audit checkpoint are platform reads. A
      // console that shows none of them must not ask for any of them either.
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

  it("reaches the render with the provider rows the policy queue carries", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Policies"));
    await screen.findByText("Your customer · CZA-1");

    expect(await screen.findByText("Sender authentication")).toBeInTheDocument();
    expect(screen.getByText("Bulk sending")).toBeInTheDocument();
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

  it("names a provider actor in the audit log as the provider", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Audit log"));
    await screen.findByText("Your customer · CZA-1");

    // The actor stays visible: a tenant is entitled to know that someone from
    // outside their organisation touched their record. Only the ladder is renamed.
    const provider = (await screen.findByText("ob1")).closest("tr");
    expect(provider?.textContent).toContain("Provider");
    expect(provider?.textContent).not.toMatch(/system_admin|System admin/);

    const own = screen.getByText("Customer admin").closest("tr");
    expect(own?.textContent).toContain("tenant-admin@example.test");
  });

  it("lists a provider family without offering a link that refuses", async () => {
    stubTenantFetch();
    renderSurface(surfaceNamed("Policies"));
    await screen.findByText("Your customer · CZA-1");

    expect((await screen.findByText("Quarantine handling")).closest("a")).not.toBeNull();
    // Opening one of these 403s and writes a Denied row into the tenant's own
    // audit log, so the name is a fact about the account, not a dead-end link.
    for (const name of ["Bulk sending", "Sender authentication"]) {
      expect(screen.getByText(name).closest("a")).toBeNull();
    }
  });
});

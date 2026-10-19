import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { newRuleDraft, toCondition } from "../api/policies";
import { FeatureOverrides } from "./FeatureOverrides";
import { Policies } from "./Policies";
import { PolicyFamilyDetail } from "./PolicyFamilyDetail";

function buildSession(roles: string[], permissions: string[]) {
  return {
    authenticated: true,
    userId: "actor-1",
    email: "admin@example.test",
    roles,
    permissions,
    customerId: null,
    expiresAt: "2099-01-01T00:00:00Z",
    csrfToken: "csrf-token",
    impersonation: null,
  };
}

const adminSession = buildSession(["system_admin"], ["policies:view", "policies:manage"]);
const customerAdminSession = buildSession(["customer_admin"], ["policies:view", "policies:manage"]);
const viewerSession = buildSession(["support"], ["policies:view"]);
const supportAdminSession = buildSession(["support"], ["policies:view", "policies:manage"]);

const customerFamily = {
  family_key: "attachments",
  display_name: "Attachment handling",
  description: "Attachment handling and file-type restrictions",
  management_level: "customer",
  security_floor: false,
  revision_count: 3,
  active_revision: {
    revision_number: 3,
    published_by: "admin@example.test",
    published_by_name: "admin@example.test",
    published_at: "2026-01-05T10:00:00Z",
    scope_level: "tenant",
  },
};

const systemFamily = {
  family_key: "malware",
  display_name: "Malware scanning",
  description: "Malware scanning and disposition",
  management_level: "system",
  security_floor: true,
  revision_count: 1,
  active_revision: {
    revision_number: 1,
    published_by: "ops@example.test",
    published_by_name: "ops@example.test",
    published_at: "2026-01-04T10:00:00Z",
    scope_level: "system",
  },
};

const unpublishedFamily = {
  family_key: "greylisting",
  display_name: "Greylisting",
  description: "Greylisting timing and retest behaviour",
  management_level: "support",
  security_floor: false,
  revision_count: 0,
  active_revision: null,
};

const storedRule = {
  id: "rule-1",
  name: "Quarantine external attachments",
  priority: 100,
  enabled: true,
  condition: {
    scope: "transaction",
    sender: { internal: false },
    content: { has_attachment: true },
  },
  action: { disposition: "quarantine", reason_code: "QUARANTINE_ATTACHMENT" },
};

const customerDetail = {
  family: customerFamily,
  revisions: [
    {
      revision_number: 3,
      scope_level: "tenant",
      published_by: "admin@example.test",
      published_by_name: "admin@example.test",
      published_at: "2026-01-05T10:00:00Z",
      activated_at: "2026-01-05T10:00:00Z",
      deactivated_at: null,
      rules_count: 1,
      rules: [storedRule],
    },
    {
      revision_number: 2,
      scope_level: "tenant",
      published_by: "admin@example.test",
      published_by_name: "admin@example.test",
      published_at: "2026-01-02T10:00:00Z",
      activated_at: null,
      deactivated_at: "2026-01-05T10:00:00Z",
      rules_count: 2,
      rules: null,
    },
    {
      revision_number: 1,
      scope_level: "tenant",
      published_by: "admin@example.test",
      published_by_name: "admin@example.test",
      published_at: "2026-01-01T10:00:00Z",
      activated_at: null,
      deactivated_at: "2026-01-02T10:00:00Z",
      rules_count: 1,
      rules: null,
    },
  ],
};

const systemDetail = {
  family: systemFamily,
  revisions: [
    {
      revision_number: 1,
      scope_level: "system",
      published_by: "ops@example.test",
      published_by_name: "ops@example.test",
      published_at: "2026-01-04T10:00:00Z",
      activated_at: "2026-01-04T10:00:00Z",
      deactivated_at: null,
      rules_count: 0,
      rules: [],
    },
  ],
};

// The per-family profile the detail endpoint publishes. These mirror
// `nullapart_mail_core::policy_profile::rule_profile` for an unwired family, an
// outbound limit family and the inline classifier, which is what the editor
// renders its threshold fields and predicate warnings from.
const CONDITION_FIELDS = ["sender", "recipient", "auth", "content", "finding"] as const;
const NO_READER_NOTE =
  "No stage reads this family's published rules, so nothing here can match or miss.";
const READER_NOTE =
  "The reader for this family uses only enabled rules and their thresholds, and never evaluates a condition.";

function unreadConditions(note: string) {
  return CONDITION_FIELDS.map((field) => ({ field, honoured: false, note }));
}

const unwiredProfile = {
  enforcement: {
    mode: "not_enforced",
    summary:
      "Nothing reads this family's published rules yet. A revision is stored, audited and versioned, but it changes no delivery decision.",
  },
  conditions: unreadConditions(NO_READER_NOTE),
  metadata: {
    read: false,
    exact_keys: false,
    metadata_optional: true,
    merge: "No reader, so metadata is stored but never applied.",
    fields: [],
  },
};

const bulkProfile = {
  enforcement: {
    mode: "outbound_thresholds",
    summary:
      "Enabled rules override the outbound intelligence operating points. Sender approval state and behaviour still decide which of them is compared.",
  },
  conditions: unreadConditions(READER_NOTE),
  metadata: {
    read: true,
    exact_keys: true,
    metadata_optional: true,
    merge:
      "Enabled rules apply in revision order and each overwrites the keys it sets, so the last enabled rule to set a key decides it.",
    fields: [
      {
        key: "max_messages_per_minute",
        label: "Messages per minute",
        kind: "count",
        min: 1,
        max: 4294967295,
        default: 25,
        hint: "Whole number above zero. Omit the key to keep the built-in default.",
      },
      {
        key: "max_messages_per_hour",
        label: "Messages per hour",
        kind: "count",
        min: 1,
        max: 4294967295,
        default: 100,
        hint: "Whole number above zero. Omit the key to keep the built-in default.",
      },
    ],
  },
};

const mlProfile = {
  enforcement: {
    mode: "ml_thresholds",
    summary:
      "Enabled rules set the inline classifier's per-class score bands. The stage reports an explicit warning when no rule carries a threshold payload.",
  },
  conditions: unreadConditions(READER_NOTE),
  metadata: {
    read: true,
    exact_keys: true,
    metadata_optional: true,
    merge:
      "Enabled rules are ordered by priority and the first rule that defines a class sets its bands; a later rule cannot change a class an earlier rule already set.",
    fields: [
      {
        key: "thresholds",
        label: "Per-class score bands",
        kind: "class_bands",
        min: 0,
        max: 1,
        default: null,
        classes: ["malware", "phishing"],
        hint: "Scores run from 0 to 1. A class needs three rising points.",
      },
    ],
  },
};

function ok(body: unknown, status = 200) {
  return {
    ok: true,
    status,
    statusText: "OK",
    json: async () => body,
  };
}

function fail(status: number, body: unknown) {
  return {
    ok: false,
    status,
    statusText: "Error",
    json: async () => body,
  };
}

interface StubOptions {
  session: unknown;
  families?: unknown[];
  detail?: unknown;
  features?: unknown[];
  published?: unknown;
  refreshed?: unknown;
  override?: unknown;
  listError?: { status: number; code: string; message: string };
  detailError?: { status: number; code: string; message: string };
  featuresError?: { status: number; code: string; message: string };
  publishError?: { status: number; code: string; message: string };
}

/**
 * The server now publishes the gating decisions (caller tier, writable override
 * scopes). These helpers stand in for that resolution so the fixtures stay the
 * builtin-role answers the pages used to derive themselves.
 */
function tierOf(session: unknown): string | null {
  const roles = (session as { roles?: string[] }).roles ?? [];
  if (roles.includes("system_admin")) return "system";
  if (roles.includes("support")) return "support";
  if (roles.includes("customer_admin")) return "customer";
  return null;
}

function scopesOf(session: unknown): string[] {
  switch (tierOf(session)) {
    case "system":
      return ["system", "deployment", "tenant"];
    case "support":
      return ["deployment", "tenant"];
    case "customer":
      return ["tenant"];
    default:
      return [];
  }
}

function stubFetch(options: StubOptions) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/auth/session")) {
      return ok({ data: options.session });
    }
    if (method === "POST" && url.endsWith("/revisions")) {
      if (options.publishError) {
        return fail(options.publishError.status, {
          code: options.publishError.code,
          message: options.publishError.message,
        });
      }
      return ok({ data: options.published }, 201);
    }
    if (method === "POST" && url.endsWith("/refresh")) {
      return ok({ data: options.refreshed });
    }
    if (method === "PUT" && url.includes("/overrides")) {
      return ok({ data: options.override });
    }
    if (options.detailError && url.includes("/policies/")) {
      return fail(options.detailError.status, {
        code: options.detailError.code,
        message: options.detailError.message,
      });
    }
    if (options.detail && url.includes("/policies/")) {
      return ok({ data: { ...options.detail, caller_tier: tierOf(options.session) } });
    }
    if (options.featuresError && url.includes("/features")) {
      return fail(options.featuresError.status, {
        code: options.featuresError.code,
        message: options.featuresError.message,
      });
    }
    if (url.includes("/features")) {
      return ok({
        data: {
          features: options.features ?? [],
          allowed_override_scopes: scopesOf(options.session),
        },
      });
    }
    if (options.listError && url.includes("/policies")) {
      return fail(options.listError.status, {
        code: options.listError.code,
        message: options.listError.message,
      });
    }
    if (url.includes("/policies")) {
      return ok({
        data: { families: options.families ?? [], caller_tier: tierOf(options.session) },
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(entry: string) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({ getParentRoute: () => rootRoute, path: "/policies", component: Policies }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/policies/features",
      component: FeatureOverrides,
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/policies/$familyKey",
      component: PolicyFamilyDetail,
    }),
  ]);
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [entry] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function rowFor(text: string): HTMLElement {
  const cell = screen.getByText(text);
  const row = cell.closest("tr");
  if (!row) throw new Error(`no table row found for ${text}`);
  return row;
}

describe("Policies", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
    };
  });

  it("lists policy families with level, floor and revision in force", async () => {
    stubFetch({
      session: adminSession,
      families: [customerFamily, systemFamily, unpublishedFamily],
    });
    renderAt("/policies");

    const link = await screen.findByRole("link", { name: "Attachment handling" });
    expect(link).toHaveProperty("href", expect.stringContaining("/policies/attachments"));
    // The raw key stays on the row because audit records name it.
    expect(within(rowFor("Attachment handling")).getByText("attachments")).toBeTruthy();
    expect(screen.getByText(/#3 · by admin@example\.test/)).toBeTruthy();
    expect(screen.getByText("Nothing published yet")).toBeTruthy();
    expect(screen.getByText("Security floor")).toBeTruthy();
    expect(within(rowFor("Attachment handling")).getByText("Customer")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Feature overrides" })).toBeTruthy();
  });

  /**
   * A service that predates the publisher-name field still stores the actor's
   * row key. The list drops the clause rather than printing the word for a
   * missing value or a key nobody can act on.
   */
  it("drops the publisher clause when the service names no publisher", async () => {
    stubFetch({
      session: customerAdminSession,
      families: [
        {
          ...customerFamily,
          active_revision: {
            revision_number: 3,
            published_by: "8f14e45f-ea41-4334-b632-f1bc9c9c9e21",
            published_at: "2026-01-05T10:00:00Z",
            scope_level: "tenant",
          },
        },
      ],
    });
    renderAt("/policies");
    await screen.findByRole("link", { name: "Attachment handling" });

    const row = rowFor("Attachment handling");
    expect(within(row).getByText(/^#3 ·/)).toBeTruthy();
    expect(row.textContent ?? "").not.toMatch(/undefined|8f14e45f|by /);
  });

  it("filters families by management level", async () => {
    stubFetch({
      session: adminSession,
      families: [customerFamily, systemFamily, unpublishedFamily],
    });
    renderAt("/policies");
    await screen.findByRole("link", { name: "Attachment handling" });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "System" }));

    expect(screen.queryByRole("link", { name: "Attachment handling" })).toBeNull();
    expect(screen.getByRole("link", { name: "Malware scanning" })).toBeTruthy();
  });

  it("shows a tenant the buckets instead of the platform level ladder", async () => {
    stubFetch({
      session: customerAdminSession,
      families: [customerFamily, systemFamily],
    });
    renderAt("/policies");
    await screen.findByRole("link", { name: "Attachment handling" });

    // Reachable at customer level, so the row says it is the tenant's to change
    // rather than printing the platform's level word.
    expect(within(rowFor("Attachment handling")).getByText("Yours to change")).toBeTruthy();
    const lock = within(rowFor("Malware scanning")).getByText("Needs your provider");
    const described = lock.getAttribute("aria-describedby");
    expect(described).toBeTruthy();
    expect(document.getElementById(described as string)?.textContent).toMatch(
      /Your provider changes this family\./,
    );
    // A customer console does not describe the ladder above it.
    expect(screen.queryByText("Needs System")).toBeNull();
    expect(screen.queryByText(/^System$/)).toBeNull();

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Show only what you can change" }));
    expect(screen.queryByRole("link", { name: "Malware scanning" })).toBeNull();
    expect(screen.getByRole("link", { name: "Attachment handling" })).toBeTruthy();
  });

  it("renders a family read-only when the role cannot publish at all", async () => {
    stubFetch({ session: viewerSession, detail: customerDetail });
    renderAt("/policies/attachments");

    expect(await screen.findByRole("heading", { name: "Attachment handling" })).toBeTruthy();
    // The catalog key stays on the page because audit records and support
    // threads name the key, not the label.
    expect(screen.getByText("attachments")).toBeTruthy();

    expect(screen.queryByRole("button", { name: "Publish revision" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reload delivery servers" })).toBeNull();
    // Drafting is hidden too: a draft nobody can publish is a dead end, so the
    // refusal says why instead of letting the save fail later.
    expect(screen.queryByRole("button", { name: "Add rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.getByText(/your role cannot publish policy changes/i)).toBeTruthy();
  });

  it("says who may change a family the tenant cannot reach", async () => {
    stubFetch({ session: customerAdminSession, detail: systemDetail });
    renderAt("/policies/malware");

    expect(await screen.findByRole("heading", { name: "Malware scanning" })).toBeTruthy();
    expect(
      screen.getByText(
        "This family is changed by your provider, not by your organisation. Ask them if it needs new rules.",
      ),
    ).toBeTruthy();
    const heading = screen
      .getByRole("heading", { name: "Malware scanning" })
      .closest(".policy-detail-heading") as HTMLElement;
    expect(within(heading).getByText("Needs your provider")).toBeTruthy();
    expect(within(heading).getByText("Security floor")).toBeTruthy();
    expect(screen.queryByText("System")).toBeNull();
    expect(screen.queryByRole("button", { name: "Publish revision" })).toBeNull();
  });

  it("names the level a locked family needs and the level the session reaches", async () => {
    stubFetch({ session: supportAdminSession, detail: systemDetail });
    renderAt("/policies/malware");

    expect(await screen.findByRole("heading", { name: "Malware scanning" })).toBeTruthy();
    expect(
      screen.getByText(
        "This family changes at System level. Your roles reach Support level, so publishing is not available here.",
      ),
    ).toBeTruthy();
    const heading = screen
      .getByRole("heading", { name: "Malware scanning" })
      .closest(".policy-detail-heading") as HTMLElement;
    expect(within(heading).getByText("Security floor")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Publish revision" })).toBeNull();
  });

  it("shows publish for a system admin on a system-level family", async () => {
    stubFetch({ session: adminSession, detail: systemDetail });
    renderAt("/policies/malware");

    expect(await screen.findByRole("button", { name: "Publish revision" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reload delivery servers" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Add rule" })).toBeTruthy();
  });

  it("publishes rules with a fresh idempotency key", async () => {
    const fetchMock = stubFetch({
      session: adminSession,
      detail: customerDetail,
      published: {
        family_key: "attachments",
        revision_number: 4,
        published_at: "2026-01-06T10:00:00Z",
        rules_count: 1,
      },
    });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Publish revision" }));
    await user.click(screen.getByRole("button", { name: "Confirm publish" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/policies/attachments/revisions") && init?.method === "POST",
      );
      expect(call).toBeTruthy();
      const headers = new Headers(call?.[1]?.headers);
      expect(headers.get("X-Idempotency-Key")).toBeTruthy();
      const body = JSON.parse(String(call?.[1]?.body)) as { rules: Record<string, unknown>[] };
      expect(Array.isArray(body.rules)).toBe(true);
      expect(body.rules[0]).toEqual(
        expect.objectContaining({
          name: expect.any(String),
          priority: expect.any(Number),
          action: expect.objectContaining({ disposition: expect.any(String) }),
        }),
      );
    });
    expect(await screen.findByText(/Published revision #4/)).toBeTruthy();
  });

  it("edits a rule through the structured dialog and updates the table", async () => {
    stubFetch({ session: adminSession, detail: customerDetail });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Add rule" }));
    await user.type(screen.getByLabelText("Rule name"), "Hold new senders");
    await user.type(screen.getByLabelText("Reason code"), "HOLD_NEW_SENDER");
    await user.selectOptions(screen.getByLabelText("Then the message is"), "hold");
    await user.click(screen.getByRole("button", { name: "Save rule" }));

    expect(await screen.findByText("Hold new senders")).toBeTruthy();
    // The table reads as an outcome, never as the machine key. The key an
    // operator typed is still in the rule editor, which is where it is edited.
    expect(screen.getByText("Hold new sender")).toBeTruthy();
    expect(screen.queryByText("HOLD_NEW_SENDER")).toBeNull();
    // The action column shows the operator wording, never the wire enum.
    expect(screen.getByText("Hold it without a review queue")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Save rule" })).toBeNull();
  });

  it("rejects an invalid reason code inline and blocks the save", async () => {
    stubFetch({ session: adminSession, detail: customerDetail });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Add rule" }));
    await user.type(screen.getByLabelText("Rule name"), "Bad code rule");
    await user.type(screen.getByLabelText("Reason code"), "not a code");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /uppercase letters, digits and underscores/i,
    );
    await user.click(screen.getByRole("button", { name: "Save rule" }));

    expect(screen.getByLabelText("Rule name")).toBeTruthy();
    expect(screen.queryByText("Bad code rule")).toBeNull();
  });

  it("states what publishing in a family with no reader changes", async () => {
    stubFetch({
      session: adminSession,
      detail: { ...customerDetail, profile: unwiredProfile },
    });
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    expect(screen.getByText("Stored, not enforced")).toBeTruthy();
    expect(screen.getByText(/it changes no delivery decision/)).toBeTruthy();
    // The rule table stops calling a stored predicate a matcher.
    expect(screen.getByText("Conditions, stored")).toBeTruthy();
  });

  it("says in the rule dialog which predicates the reader never evaluates", async () => {
    stubFetch({
      session: adminSession,
      detail: { ...customerDetail, profile: bulkProfile },
    });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Add rule" }));
    expect(screen.getByText(/recorded on the rule but never evaluated/)).toBeTruthy();
    expect(
      screen.getByText("Sender, Recipient, Authentication, Content and Scanner findings"),
    ).toBeTruthy();
  });

  it("renders the limits this family publishes and refuses a half-filled set", async () => {
    stubFetch({
      session: adminSession,
      detail: { ...customerDetail, profile: bulkProfile },
    });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Add rule" }));
    await user.type(screen.getByLabelText("Rule name"), "Cap the sender rate");
    await user.type(screen.getByLabelText("Reason code"), "DEFER_RATE");
    await user.type(screen.getByLabelText("Messages per minute"), "10");

    // An untouched sibling is not scolded before the operator tries to save.
    await user.click(screen.getByRole("button", { name: "Save rule" }));
    expect(
      await screen.findByText(/Messages per hour is required when any threshold/),
    ).toBeTruthy();
    expect(screen.queryByText("Cap the sender rate")).toBeNull();

    await user.type(screen.getByLabelText("Messages per hour"), "40");
    expect(screen.queryByText(/is required when any threshold/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "Save rule" }));
    expect(await screen.findByText("Cap the sender rate")).toBeTruthy();
  });

  it("builds the classifier score bands a banded family reads", async () => {
    const fetchMock = stubFetch({
      session: adminSession,
      detail: { ...customerDetail, profile: mlProfile },
      published: {
        family_key: "attachments",
        revision_number: 4,
        published_at: "2026-01-06T10:00:00Z",
        rules_count: 2,
      },
    });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Add rule" }));
    await user.type(screen.getByLabelText("Rule name"), "Band malware");
    await user.type(screen.getByLabelText("Reason code"), "ML_MALWARE");
    await user.selectOptions(screen.getByLabelText("Add a class band"), "malware");

    await user.type(screen.getByLabelText("Becomes a finding at"), "0.4");
    await user.type(screen.getByLabelText("Medium band above"), "0.7");
    await user.type(screen.getByLabelText("High band above"), "0.9");
    await user.click(screen.getByRole("button", { name: "Save rule" }));

    await user.click(screen.getByRole("button", { name: "Publish revision" }));
    await user.click(screen.getByRole("button", { name: "Confirm publish" }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input).endsWith("/policies/attachments/revisions") && init?.method === "POST",
      );
      const body = JSON.parse(String(call?.[1]?.body)) as {
        rules: { action: { metadata?: Record<string, unknown> } }[];
      };
      const banded = body.rules.find((rule) => rule.action.metadata !== undefined);
      expect(banded?.action.metadata).toEqual({
        thresholds: { version: 1, classes: { malware: { low: 0.4, medium: 0.7, high: 0.9 } } },
      });
    });
  });

  it("renders the revision history for the family", async () => {
    stubFetch({ session: adminSession, detail: customerDetail });
    renderAt("/policies/attachments");

    expect(await screen.findByText("#2")).toBeTruthy();
    expect(screen.getByText("#1")).toBeTruthy();
    expect(screen.getAllByText("replaced")).toHaveLength(2);
    expect(screen.getByText("in effect")).toBeTruthy();
    // The revision table states the level it applies at in words, never the
    // stored scope enum.
    expect(screen.queryByText(/^tenant$/)).toBeNull();
    expect(screen.getAllByText("This customer").length).toBeGreaterThanOrEqual(3);
  });
});

describe("policy rule builder", () => {
  it("omits empty CSV fields and unset tri-states from the condition", () => {
    const draft = newRuleDraft();
    draft.senderDomains = " example.test , , partner.test ";
    draft.senderInternal = false;
    draft.authSpf = ["fail"];
    draft.severities = ["critical"];

    const condition = toCondition(draft);

    expect(Object.keys(condition)).toEqual(["scope", "sender", "auth", "finding"]);
    expect(condition.scope).toBe("transaction");
    expect(condition.sender).toEqual({
      domain: ["example.test", "partner.test"],
      internal: false,
    });
    expect(condition.recipient).toBeUndefined();
    expect(condition.content).toBeUndefined();
    expect(condition.auth).toEqual({ spf: ["fail"] });
    expect(condition.finding).toEqual({ severity: ["critical"] });
  });
});

describe("policy error states", () => {
  it("renders the safe server message when the policy list is denied", async () => {
    stubFetch({
      session: adminSession,
      listError: { status: 403, code: "FORBIDDEN", message: "Permission is required" },
    });
    renderAt("/policies");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Permission is required");
  });

  it("offers step-up re-authentication when step-up is required", async () => {
    stubFetch({
      session: adminSession,
      listError: {
        status: 403,
        code: "STEP_UP_REQUIRED",
        message: "Step-up authentication is required",
      },
    });
    renderAt("/policies");

    expect(await screen.findByRole("button", { name: "Re-authenticate" })).toBeTruthy();
    expect(screen.getByText("Re-authentication is required for this action.")).toBeTruthy();
  });

  it("surfaces a rejected publish as a safe message with a rule-field hint", async () => {
    stubFetch({
      session: adminSession,
      detail: customerDetail,
      publishError: { status: 400, code: "INVALID_REQUEST", message: "Request is invalid" },
    });
    const user = userEvent.setup();
    renderAt("/policies/attachments");
    await screen.findByText("Quarantine external attachments");

    await user.click(screen.getByRole("button", { name: "Publish revision" }));
    await user.click(screen.getByRole("button", { name: "Confirm publish" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Request is invalid");
    expect(alert).toHaveTextContent("Review the rule fields and try again.");
  });
});

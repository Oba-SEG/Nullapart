import { describe, expect, it } from "vitest";

import {
  MAX_RECIPIENTS,
  digestWindowError,
  digestWindowOptions,
  draftFromSettings,
  recipientAddressError,
  settingsInputFrom,
  severityFloorOf,
  splitRecipients,
  validateRecipients,
  type NotificationSettingsResponse,
} from "./notifications";

function response(
  overrides: Partial<NotificationSettingsResponse> = {},
): NotificationSettingsResponse {
  return {
    deployment_id: "dep-1",
    generated_at: "2026-10-19T00:00:00Z",
    settings: null,
    effective: {
      enabled: true,
      severity_floor: "warning",
      recipient_count: 0,
      digest_window_minutes: 60,
      deliverable: false,
    },
    verified_domains: ["example.test"],
    deliveries: [],
    capabilities: { update_settings: { allowed: true, blocker: null } },
    ...overrides,
  };
}

describe("notification draft", () => {
  it("starts from the stored row when one exists", () => {
    const draft = draftFromSettings(
      response({
        settings: {
          enabled: false,
          severity_floor: "critical",
          recipient_emails: ["Postmaster@Example.TEST"],
          digest_window_minutes: 360,
          updated_by: "ob@example.test",
          updated_at: "2026-10-18T00:00:00Z",
        },
      }),
    );
    expect(draft).toEqual({
      enabled: false,
      severityFloor: "critical",
      recipients: "Postmaster@Example.TEST",
      digestWindow: "360",
    });
  });

  it("falls back to the effective values an unsaved tenant is running on", () => {
    const draft = draftFromSettings(
      response({
        effective: {
          enabled: true,
          severity_floor: "info",
          recipient_count: 0,
          digest_window_minutes: 15,
          deliverable: false,
        },
      }),
    );
    expect(draft.enabled).toBe(true);
    expect(draft.severityFloor).toBe("info");
    expect(draft.digestWindow).toBe("15");
    expect(draft.recipients).toBe("");
  });

  it("reads an unknown floor as the default rather than offering a value the API refuses", () => {
    expect(severityFloorOf("urgent")).toBe("warning");
    expect(severityFloorOf(null)).toBe("warning");
    expect(severityFloorOf("critical")).toBe("critical");
  });

  it("keeps a stored window that is not one of the presets selectable", () => {
    const options = digestWindowOptions("90").map((option) => option.value);
    expect(options).toContain("90");
    expect(options).toContain("60");
  });
});

describe("recipient validation", () => {
  it("splits on both separators and drops blanks", () => {
    expect(splitRecipients("a@x.test, b@x.test\n\n  c@x.test ")).toEqual([
      "a@x.test",
      "b@x.test",
      "c@x.test",
    ]);
  });

  it("refuses an address shape the server would reject", () => {
    expect(recipientAddressError("postmaster")).toBeDefined();
    expect(recipientAddressError("a@b@c.test")).toBeDefined();
    expect(recipientAddressError("postmaster@localhost")).toBeDefined();
    expect(recipientAddressError("postmaster@example.test")).toBeUndefined();
  });

  it("normalizes case and drops repeats the ledger would send twice", () => {
    const result = validateRecipients(
      ["Postmaster@Example.test", "postmaster@example.test"],
      ["example.test"],
    );
    expect(result.emails).toEqual(["postmaster@example.test"]);
    expect(result.errors).toEqual([]);
    expect(result.droppedDuplicates).toBe(1);
  });

  it("refuses an address outside the verified domains instead of promising a mail", () => {
    const result = validateRecipients(["help@other.test"], ["example.test"]);
    expect(result.emails).toEqual([]);
    expect(result.errors[0]).toMatch(/outside the domains your customer has verified/);
  });

  it("does not let a verified parent authorize a host below it", () => {
    const result = validateRecipients(["postmaster@mail.example.test"], ["example.test"]);
    expect(result.errors[0]).toMatch(/outside the domains/);
  });

  it("refuses the list that is over the stored cap", () => {
    const many = Array.from(
      { length: MAX_RECIPIENTS + 1 },
      (_, index) => `op${index}@example.test`,
    );
    const result = validateRecipients(many, ["example.test"]);
    expect(result.errors.join(" ")).toMatch(/limited to 10 addresses/);
  });
});

describe("digest window", () => {
  it("accepts the range the endpoint enforces", () => {
    expect(digestWindowError("0")).toBeUndefined();
    expect(digestWindowError("1440")).toBeUndefined();
  });

  it("refuses a value the endpoint would reject", () => {
    expect(digestWindowError("")).toBeDefined();
    expect(digestWindowError("1441")).toBeDefined();
    expect(digestWindowError("-1")).toBeDefined();
    expect(digestWindowError("2.5")).toBeDefined();
  });
});

describe("settings payload", () => {
  it("builds the full write the endpoint expects", () => {
    const built = settingsInputFrom(
      {
        enabled: false,
        severityFloor: "info",
        recipients: "Postmaster@Example.test",
        digestWindow: "15",
      },
      ["example.test"],
    );
    expect(built.errors).toEqual({});
    expect(built.input).toEqual({
      enabled: false,
      severity_floor: "info",
      recipient_emails: ["postmaster@example.test"],
      digest_window_minutes: 15,
    });
  });

  it("sends nothing when a field the server would refuse is set", () => {
    const built = settingsInputFrom(
      {
        enabled: true,
        severityFloor: "warning",
        recipients: "help@other.test",
        digestWindow: "9999",
      },
      ["example.test"],
    );
    expect(built.input).toBeNull();
    expect(built.errors.recipients).toBeDefined();
    expect(built.errors.digestWindow).toBeDefined();
  });
});

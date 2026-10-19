import { describe, expect, it } from "vitest";
import type { Session } from "../auth/session";
import { getSessionPresentation } from "./session-presentation";

const authenticatedSession: Session = {
  authenticated: true,
  userId: "operator-1",
  email: "operator@example.test",
  roles: ["system_admin"],
  tier: "system",
  customerId: null,
  expiresAt: "2099-01-01T00:00:00Z",
};

describe("getSessionPresentation", () => {
  it("does not show an authenticated state while the session is pending", () => {
    expect(getSessionPresentation(null, false)).toMatchObject({
      stateLabel: "Verifying",
      asset: "/brand/status/status-processing.svg",
    });
  });

  it("uses a non-success state when the session query fails", () => {
    expect(getSessionPresentation(null, true)).toMatchObject({
      stateLabel: "Attention required",
      asset: "/brand/status/status-review-256.png",
    });
  });

  it("makes verified system authority distinct from a customer workspace", () => {
    expect(getSessionPresentation(authenticatedSession, false)).toMatchObject({
      stateLabel: "System control",
      scopeLabel: "System-wide authority",
      mode: "system",
    });
    expect(
      getSessionPresentation(
        {
          ...authenticatedSession,
          tier: "customer",
          roles: ["customer_admin"],
          customerId: "customer-a",
        },
        false,
      ),
    ).toMatchObject({
      stateLabel: "Customer control",
      boundaryLabel: "Customer administrator",
      scopeLabel: "Your customer · customer-a",
      mode: "customer",
    });
  });

  it("shows a tenant claim only for the tier the server published", () => {
    // The role name says customer_admin and the session even carries a customer,
    // but with no published tier the shell stays on the desk wording: the tier
    // is the server's answer, not something the UI re-derives from roles.
    expect(
      getSessionPresentation(
        {
          ...authenticatedSession,
          tier: undefined,
          roles: ["customer_admin"],
          customerId: "customer-a",
        },
        false,
      ),
    ).toMatchObject({
      stateLabel: "Operator session",
      scopeLabel: "Customer workspace",
      mode: "customer",
    });
  });

  it("makes an audited customer entry unambiguously different from system control", () => {
    expect(
      getSessionPresentation(
        {
          ...authenticatedSession,
          customerId: "customer-a",
          impersonation: {
            id: "entry-1",
            customerId: "customer-a",
            customerDisplayName: "Acme Mail",
            reason: "Investigating a reported delivery failure.",
            startedAt: "2099-01-01T00:00:00Z",
          },
        },
        false,
      ),
    ).toMatchObject({
      stateLabel: "Customer entry active",
      scopeLabel: "Customer entry · Acme Mail",
      mode: "customer-entry",
    });
  });
});

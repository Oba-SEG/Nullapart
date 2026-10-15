import { describe, expect, it } from "vitest";
import type { Session } from "../auth/session";
import { getSessionPresentation } from "./session-presentation";

const authenticatedSession: Session = {
  authenticated: true,
  userId: "operator-1",
  email: "operator@example.test",
  roles: ["system_admin"],
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

  it("derives the scope label only from a verified server session", () => {
    expect(getSessionPresentation(authenticatedSession, false)).toMatchObject({
      stateLabel: "Authenticated",
      scopeLabel: "Platform scope",
    });
    expect(
      getSessionPresentation({ ...authenticatedSession, customerId: "customer-a" }, false),
    ).toMatchObject({ scopeLabel: "Customer scope" });
  });
});

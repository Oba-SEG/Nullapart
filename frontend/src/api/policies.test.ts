import { describe, expect, it } from "vitest";

import {
  draftFromRule,
  ruleFromDraft,
  tierAllows,
  writableScopes,
  type ManagementLevel,
  type OverrideScope,
  type Rule,
} from "./policies";

describe("policy rule conversion", () => {
  it("preserves action metadata so inline ML thresholds are not silently cleared", () => {
    const stored: Rule = {
      id: "rule-1",
      name: "Inline ML malware threshold",
      priority: 10,
      enabled: true,
      condition: {
        scope: "transaction",
        finding: {
          scanner: ["inlineml"],
          category: ["malware"],
        },
      },
      action: {
        disposition: "quarantine",
        reason_code: "QUARANTINE_MALWARE",
        metadata: {
          thresholds: {
            version: 1,
            classes: {
              malware: {
                low: 0.4,
                medium: 0.7,
                high: 0.9,
              },
            },
          },
        },
      },
    };

    const draft = draftFromRule(stored);
    const roundTripped = ruleFromDraft(draft);

    expect(roundTripped.action.metadata).toEqual(stored.action.metadata);
  });
});

describe("tier ladder reads the server-published tier", () => {
  const LEVELS: ManagementLevel[] = ["customer", "support", "system"];

  it("grants a family at or below the published tier", () => {
    expect(tierAllows("system", "system")).toBe(true);
    expect(tierAllows("system", "support")).toBe(true);
    expect(tierAllows("support", "support")).toBe(true);
    expect(tierAllows("support", "customer")).toBe(true);
    expect(tierAllows("customer", "customer")).toBe(true);
  });

  it("refuses anything above the published tier and any tier at all", () => {
    expect(tierAllows("customer", "support")).toBe(false);
    expect(tierAllows("customer", "system")).toBe(false);
    expect(tierAllows(null, "customer")).toBe(false);
  });

  it("keeps the ladder monotonic so no level outranks the one above it", () => {
    LEVELS.forEach((caller, callerRank) => {
      LEVELS.forEach((required, requiredRank) => {
        expect(tierAllows(caller, required)).toBe(requiredRank <= callerRank);
      });
    });
  });
});

describe("writableScopes intersects the feature with the session", () => {
  it("keeps only the levels the server also placed in the session", () => {
    expect(writableScopes(["system", "deployment", "tenant"], ["tenant"])).toEqual(["tenant"]);
    expect(writableScopes(["deployment", "tenant"], ["system", "deployment", "tenant"])).toEqual([
      "deployment",
      "tenant",
    ]);
  });

  it("returns an empty list when the feature is above the session", () => {
    const scopes: OverrideScope[] = ["system", "deployment", "tenant"];
    expect(
      writableScopes(
        ["system"],
        scopes.filter((s) => s === "tenant"),
      ),
    ).toEqual([]);
    expect(writableScopes(["system", "tenant"], [])).toEqual([]);
  });

  it("preserves the order the feature publishes", () => {
    expect(writableScopes(["tenant", "system"], ["system", "deployment", "tenant"])).toEqual([
      "tenant",
      "system",
    ]);
  });
});

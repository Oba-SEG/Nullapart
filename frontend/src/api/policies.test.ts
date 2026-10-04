import { describe, expect, it } from "vitest";

import { draftFromRule, ruleFromDraft, type Rule } from "./policies";

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

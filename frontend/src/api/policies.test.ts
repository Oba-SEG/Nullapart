import { describe, expect, it } from "vitest";

import {
  classBandsFromMetadata,
  draftFromRule,
  isDraftValid,
  metadataFromDraft,
  newRuleDraft,
  ruleFromDraft,
  tierAllows,
  writableScopes,
  type ConditionFieldProfile,
  type FindingCategory,
  type ManagementLevel,
  type MetadataFieldProfile,
  type OverrideScope,
  type Rule,
  type RuleProfile,
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

// ---------------------------------------------------------------------------
// Profile-driven metadata: the fixtures mirror what
// `nullapart_mail_core::policy_profile::rule_profile` publishes, so a drift
// between the two is a failing test rather than a form that cannot publish.
// ---------------------------------------------------------------------------

const NO_READER_NOTE =
  "No stage reads this family's published rules, so nothing here can match or miss.";
const OUTBOUND_NOTE =
  "The reader for this family uses only enabled rules and their thresholds, and never evaluates a condition.";
const COUNT_HINT = "Whole number above zero. Omit the key to keep the built-in default.";

function unreadConditions(note: string): ConditionFieldProfile[] {
  return (["sender", "recipient", "auth", "content", "finding"] as const).map((field) => ({
    field,
    honoured: false,
    note,
  }));
}

function countField(key: string, label: string, builtIn: number): MetadataFieldProfile {
  return {
    key,
    label,
    kind: "count",
    min: 1,
    max: 4294967295,
    default: builtIn,
    hint: COUNT_HINT,
  };
}

const unwiredProfile: RuleProfile = {
  enforcement: {
    mode: "not_enforced",
    summary: "Nothing reads this family's published rules yet.",
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

const bulkProfile: RuleProfile = {
  enforcement: {
    mode: "outbound_thresholds",
    summary: "Enabled rules override the outbound intelligence operating points.",
  },
  conditions: unreadConditions(OUTBOUND_NOTE),
  metadata: {
    read: true,
    exact_keys: true,
    metadata_optional: true,
    merge: "Enabled rules apply in revision order and each overwrites the keys it sets.",
    fields: [
      countField("max_messages_per_minute", "Messages per minute", 25),
      countField("max_messages_per_hour", "Messages per hour", 100),
      countField("max_recipients_per_message", "Recipients per message", 50),
    ],
  },
};

const mlClasses: FindingCategory[] = ["malware", "phishing", "spam"];
const mlProfile: RuleProfile = {
  enforcement: {
    mode: "ml_thresholds",
    summary: "Enabled rules set the inline classifier's per-class score bands.",
  },
  conditions: unreadConditions(OUTBOUND_NOTE),
  metadata: {
    read: true,
    exact_keys: true,
    metadata_optional: true,
    merge:
      "Enabled rules are ordered by priority and the first rule that defines a class sets its bands.",
    fields: [
      {
        key: "thresholds",
        label: "Per-class score bands",
        kind: "class_bands",
        min: 0,
        max: 1,
        default: null,
        classes: mlClasses,
        hint: "Scores run from 0 to 1. A class needs three rising points.",
      },
    ],
  },
};

describe("profile-driven action metadata", () => {
  function drafted(overrides: Partial<ReturnType<typeof newRuleDraft>> = {}) {
    return { ...newRuleDraft(), name: "Rule", reasonCode: "HOLD_RULE", ...overrides };
  }

  it("keeps a stored payload for a family nothing reads", () => {
    const draft = drafted({ actionMetadata: { thresholds: { version: 1, classes: {} } } });
    const result = metadataFromDraft(unwiredProfile, draft);

    expect(result.errors).toEqual({});
    expect(result.metadata).toEqual({ thresholds: { version: 1, classes: {} } });
  });

  it("publishes no metadata when every threshold is left empty", () => {
    expect(metadataFromDraft(bulkProfile, drafted()).metadata).toBeUndefined();
  });

  it("refuses a half-filled limit set because the server accepts exact keys only", () => {
    const draft = drafted({ metadataValues: { max_messages_per_minute: "10" } });
    const result = metadataFromDraft(bulkProfile, draft);

    expect(result.metadata).toBeUndefined();
    expect(Object.keys(result.errors).sort()).toEqual([
      "max_messages_per_hour",
      "max_recipients_per_message",
    ]);
    expect(isDraftValid(draft, bulkProfile)).toBe(false);
  });

  it("publishes every declared key once they are all filled", () => {
    const draft = drafted({
      metadataValues: {
        max_messages_per_minute: "10",
        max_messages_per_hour: "40",
        max_recipients_per_message: " 5 ",
      },
    });

    expect(metadataFromDraft(bulkProfile, draft)).toEqual({
      metadata: {
        max_messages_per_minute: 10,
        max_messages_per_hour: 40,
        max_recipients_per_message: 5,
      },
      errors: {},
    });
    expect(isDraftValid(draft, bulkProfile)).toBe(true);
  });

  it("rejects a zero limit at the field the operator typed into", () => {
    const draft = drafted({
      metadataValues: {
        max_messages_per_minute: "0",
        max_messages_per_hour: "40",
        max_recipients_per_message: "5",
      },
    });

    expect(metadataFromDraft(bulkProfile, draft).errors.max_messages_per_minute).toMatch(
      /at least 1/,
    );
  });

  it("builds the classifier payload the threshold parser accepts", () => {
    const draft = drafted({
      classBands: { malware: { low: "0.4", medium: "0.7", high: "0.9" } },
    });

    expect(metadataFromDraft(mlProfile, draft)).toEqual({
      metadata: {
        thresholds: { version: 1, classes: { malware: { low: 0.4, medium: 0.7, high: 0.9 } } },
      },
      errors: {},
    });
  });

  it("names the band row that is half filled or out of order", () => {
    const half = metadataFromDraft(
      mlProfile,
      drafted({ classBands: { malware: { low: "0.4", medium: "", high: "0.9" } } }),
    );
    expect(half.metadata).toBeUndefined();
    expect(half.errors["thresholds:malware"]).toBeTruthy();

    const unsorted = metadataFromDraft(
      mlProfile,
      drafted({ classBands: { malware: { low: "0.8", medium: "0.3", high: "0.9" } } }),
    );
    expect(unsorted.errors["thresholds:malware"]).toMatch(/rise/);

    const aboveOne = metadataFromDraft(
      mlProfile,
      drafted({ classBands: { malware: { low: "0.4", medium: "0.7", high: "1.4" } } }),
    );
    expect(aboveOne.errors["thresholds:malware"]).toMatch(/exceed 1/);
  });

  it("drops a stored band the server would reject instead of showing it as set", () => {
    const stored = {
      thresholds: {
        version: 1,
        classes: {
          malware: { low: 0.4, medium: 0.7, high: 0.9 },
          spam: { low: 0.9, medium: 0.5, high: 0.6 },
          phishing: { low: 0.4, medium: 0.7 },
        },
      },
    };

    expect(Object.keys(classBandsFromMetadata(mlProfile, stored))).toEqual(["malware"]);
  });

  it("round-trips a banded rule through the profile without losing the payload", () => {
    const stored: Rule = {
      id: "rule-1",
      name: "Inline ML bands",
      priority: 10,
      enabled: true,
      condition: { scope: "transaction" },
      action: {
        disposition: "quarantine",
        reason_code: "ML_BANDS",
        metadata: {
          thresholds: {
            version: 1,
            classes: {
              malware: { low: 0.4, medium: 0.7, high: 0.9 },
              phishing: { low: 0.5, medium: 0.75, high: 0.95 },
            },
          },
        },
      },
    };

    const draft = draftFromRule(stored, mlProfile);

    expect(Object.keys(draft.classBands).sort()).toEqual(["malware", "phishing"]);
    expect(draft.classBands.malware).toEqual({ low: "0.4", medium: "0.7", high: "0.9" });
    expect(ruleFromDraft(draft, mlProfile).action.metadata).toEqual(stored.action.metadata);
  });

  it("lets clearing every band publish no metadata, which is how the defaults come back", () => {
    const stored: Rule = {
      id: "rule-1",
      name: "Inline ML bands",
      priority: 10,
      enabled: true,
      condition: { scope: "transaction" },
      action: {
        disposition: "quarantine",
        reason_code: "ML_BANDS",
        metadata: {
          thresholds: { version: 1, classes: { malware: { low: 0.4, medium: 0.7, high: 0.9 } } },
        },
      },
    };
    const draft = { ...draftFromRule(stored, mlProfile), classBands: {} };

    expect(ruleFromDraft(draft, mlProfile).action.metadata).toBeUndefined();
  });
});
